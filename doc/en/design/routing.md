# Routing engine

This document explains how the kernel and userspace choose an outbound for each flow; routing syntax and fields live in the [routing reference](../reference/routing.md).

## Decision path

A new flow is first classified by the eBPF routing engine. A complete kernel decision can remain on the native path when direct offload is safe; other decisions produce a handoff to the control plane. Userspace accepts the original destination, optionally learns a domain, re-runs the `Router` when required, applies the Clash mode, and resolves the resulting group to a leaf outbound.

The routing result is therefore a property of the flow, not of each packet. Established packets use the decision stored in conntrack state and do not repeat rule evaluation or read the current Clash-mode flags.

## Kernel routing

### `MatchSet` evaluation

`RoutingMatcherBuilder` sorts compiled routes by ascending priority and lowers each rule to the dae `match_set` ABI shared by `honk-core` and `honk-ebpf`. Each type-specific `MatchSet` carries a matcher value, negation bit, intermediate or final outbound, `must` bit, and mark.

Multiple values inside one condition form an OR chain. Distinct conditions form an AND chain. The intermediate `LogicalOr` and `LogicalAnd` outcomes preserve this structure without allocating a rule object in the kernel. A final fallback entry gives unmatched flows a real outbound.

At route entry, `route()` prepares full-prefix source, destination, and MAC keys and calls `bpf_loop` over the selected bank. `RouteCtx` maintains `GoodSubrule`, `BadRule`, `Must`, DNS-query, and domain-known state across loop iterations. A final result encodes the outbound in bits 0–7, the mark in bits 8–39, and `must` in bit 40.

| Index | Meaning in the route state machine |
| --- | --- |
| `0` | `Direct` |
| `1` | `Block` |
| `2+` | User group, in configuration order |
| `0xFC` | `MustRules`: record `Must` and continue evaluating |
| `0xFD` | `ControlPlaneRouting`: defer the decision to userspace |
| `0xFE` | `LogicalOr`: continue the current OR subrule |
| `0xFF` | `LogicalAnd`: finish one condition and continue the rule |

`ControlPlaneRouting` is an intermediate handoff outcome, not a valid fallback. The fallback must resolve to `direct`, `block`, or a user group.

### Flow-group prefilter

Every physical rule bank has four groups: TCP/IPv4, TCP/IPv6, UDP/IPv4, and UDP/IPv6. The compiler gives every `MatchSet` in one rule chain the same group membership. `ROUTING_GROUP_META_MAP` stores one packed `RoutingGroupMeta { rule_count, bitmap }` for each group and generation.

The datapath reads the generation selector once, selects the flow group, and loads that packed entry once. A clear bitmap bit skips the corresponding `ROUTING_MAP` lookup and state-machine step. Because a chain is never split across groups, skipping cannot strand `LogicalOr` or `LogicalAnd` state. Negated protocol or IP-version conditions stay in all groups because their complement may match any skipped group.

### LPM and learned-domain maps

Destination CIDRs, source CIDRs, and MAC prefixes live in separate LPM tries. Each LPM value is a bitmap of physical `MatchSet` slots, so prefixes shared by several rules merge their bits rather than overwriting one another. An LPM lookup is a match only when the current slot's bit is set.

The kernel cannot see a hostname at TCP SYN time. Domain and geosite conditions compile to `DomainSet` placeholders. `DOMAIN_ROUTING_MAP` maps a DNS-learned destination IP to the corresponding per-generation rule bitmap; a present entry also sets `DomainKnown`, proving that all domain-set checks in this pass used a complete learned bitmap.

In `domain++` mode, a generic proxy rule with a destination-port condition is changed to `ControlPlaneRouting` when it has no domain/geosite, process, MAC, or DSCP constraint and is not `direct` or `block`. `domain` and `domain+` keep the initial port/IP decision in the kernel. A learned `DOMAIN_ROUTING_MAP` entry can still make later flows kernel-decidable.

## Atomic routing publication

A routing push is a selector-last, two-phase commit. It never calls `clear_routes`; clearing the active maps would expose an empty generation and drop new traffic while reload is in progress.

1. Compile an immutable `RoutingPushPlan`—`MatchSet`s, LPM bitmaps, flow-group bitmaps, and domain projection metadata—without writing any BPF map.
2. Read the active generation and fill the other `ROUTING_MAP` bank.
3. Stage destination, source, and MAC LPM values containing both the active and replacement generations. Prune only keys used by neither plan.
4. Write the replacement generation's exploded introspection metadata and all four packed `RoutingGroupMeta` entries.
5. Flip `ROUTING_META_ACTIVE_GENERATION_SLOT` last.

A route pass reads the selector only once, so it observes the complete old bank or the complete replacement. Stale physical tail slots are harmless because `rule_count` bounds `bpf_loop`. An LPM key retired by the replacement remains while the old bank can still be observed and disappears on the following transition.

DNS-learned domain bitmaps use the same generation boundary. Reload stages their inactive-generation half before switching the rule bank.

### Group ordinals and health during reload

Configuration order defines both the routing outbound ordinal and the connectivity slot: group `i` uses `2 + i`. All leaf members of that group share the slot. For each TCP, DNS-UDP, or data-UDP network and each IP family, userspace publishes the OR of member health rather than one node's state.

A reload may reorder groups and therefore change the meaning of an ordinal. Before switching routing generations, userspace marks every old-or-new transition slot alive. This temporary fail-open health snapshot prevents an old health bit from killing a newly assigned group. It then stages learned domains, switches the routing generation, and publishes the exact new per-group, per-network, per-family alive snapshot. Slots left after a publication error remain fail-open rather than inheriting stale failure state.

## Userspace `Router`

`Router::new` compiles all rules once and sorts them by ascending priority. Positive matcher groups are ANDed and alternatives within a group are ORed; any matching negated condition vetoes the rule. `route_full` scans in priority order and returns the first match, while `route_with_must` returns that outbound plus its `must` flag or the default outbound with `must = false`.

The kernel's reserved `MustRules` outcome has Go dae's non-final behavior: it records `Must` and continues the scan. The current userspace implementation does not mirror that behavior: a rule carrying `must` is still the first-match terminal result of `route_full`. Thus a flow that falls back entirely to the userspace `Router` does not continue past a matching `must` rule; the returned flag only prevents later sniffing and Clash override. This is a current implementation limitation.

IP and source-IP conditions use `BinaryLpmTrie`, a compact binary trie with 32 levels for IPv4 and 128 for IPv6. Lookup stops as soon as it encounters a matched prefix or a missing child.

`GeoAssets` parses `geoip.dat` and `geosite.dat` at most once per `Router` build and decodes only categories referenced by the configuration. `category@attr` splits at the first `@`, indexes the base category, and keeps entries carrying that attribute key; key presence is case-insensitive. `GeositeMatcher` uses hash sets for exact names and dot-boundary suffixes, one Aho-Corasick automaton for keywords, and compiled regular expressions for regex entries.

## Domain routing and sniffing

Domain routing has two views:

- DNS answers project domain-rule bitmaps into `DOMAIN_ROUTING_MAP`, allowing later connections to the returned IP to use the kernel view.
- A connection without a learned IP mapping reaches userspace, where a sniffed name is added to `ConnectionInfo` and the full `Router` can evaluate the domain view.

The DNS projection owns a generation-pinned `Router` and bitmap snapshot. Its worker acquires the backend and then a publication fence, rechecks the generation, and skips a stale batch before writing. A replacement snapshot therefore cannot be followed by an old DNS batch mutating the map. If the generation changes during reconciliation, desired state is rebuilt for the current snapshot.

TCP sniffing extracts TLS SNI or HTTP `Host` and returns the buffered prefix for forwarding. It reads at most 4096 bytes. A negative cache suppresses repeated work for destinations that repeatedly produce no usable domain.

UDP sniffing handles QUIC v1 and v2 Initial packets. It derives Initial keys, removes header protection, decrypts the payload, collects CRYPTO frames, reassembles them across fragments or packets, and runs the shared TLS ClientHello parser. Per-flow sessions and negative caches bound repeated attempts. An incomplete ClientHello is not treated as a final no-domain result because later Initial fragments may change routing.

The initial IP-based decision and the optional domain target are separate. A sniffed name can affect routing only for an accepted `domain` reality check or in `domain++`; `domain+` never changes the route. `must`, `block`, and reserved direct decisions remain final. A negative-cache hit skips name extraction and keeps the existing path.

### Dial modes

| Mode | Sniff | Verify name against destination IP | Re-run routing | Dial behavior |
| --- | --- | --- | --- | --- |
| `ip` | No | Not applicable | No | Use the original destination IP. |
| `domain` | Yes, unless a final/negative-cache path skips it | Yes; discard a mismatch | Only after verification succeeds | Use the verified name for proxy dialing; an unmatched domain rule falls through to later IP/port rules. |
| `domain+` | Yes, with the same skips | No | No | Use the sniffed name for proxy dialing while preserving the initial route. |
| `domain++` | Yes, with the same skips | No | Yes for non-reserved decisions | Re-run routing from SNI/HTTP Host and use the resulting proxy target. |

## Clash modes and direct offload

`ModeState` applies Clash mode only after the routing result. It never overrides `block` or a result carrying `must`.

| Mode | Userspace override | Route-time kernel policy |
| --- | --- | --- |
| `Rule` | Keep the routed outbound | Offload a plain `direct` result only when SNI cannot change it: `dial_mode: ip` or `domain+`, no domain-class rule exists, or this flow set `DomainKnown` through `DOMAIN_ROUTING_MAP`; otherwise hand off to userspace |
| `Global` | Use the current GLOBAL selection when it resolves | Normally hand off to userspace. The exact lowercase GLOBAL selection `direct` is a special case that publishes `OFFLOAD_ALL` because every non-final result converges to direct |
| `Direct` | Force `direct` | Offload every non-`must`, non-`block` result and normalize its cached outbound to `Direct` |

`lan_ingress` reads `DATAPATH_FLAGS_MAP` once for a new flow. When the mode policy offloads a non-`must` flow, it records the decision in bit 57 of `RoutingMeta`; established packets then check only cached `outbound == Direct && (must || offload)`. A `direct(must)` flow uses the `must` bit and does not need bit 57.

Offloaded flows never create a userspace relay or `/connections` entry and cannot be re-routed by later SNI. Their transmit packets and bytes are still counted at `lan_ingress`.

## Health interaction

Before redirect or native forwarding, the datapath checks `OUTBOUND_CONNECTIVITY_MAP`. A dead selected outbound returns `TC_ACT_SHOT`: honk fails closed rather than leaking the flow through `direct`. Destination port 53 is exempt for both TCP and UDP so DNS can reach the control plane and apply its own fallback policy.

The group-shared slot normally contains the OR of all leaf health. A TCP group with exactly one unique leaf and no `final` keeps that slot open as a userspace last resort; the control plane still dials the same proxy, and successful traffic can revive it. UDP and all-dead multi-leaf groups remain fail-closed. Clash `Global` and `Direct` overrides still cannot bypass a `must` or `block` result. See the [datapath design](./datapath.md) for the exact redirect and drop paths.

## Related docs

- [Datapath design](./datapath.md)
- [Control-plane design](./control-plane.md)
- [Routing configuration reference](../reference/routing.md)
