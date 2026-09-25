# Compiled routing decision plane

## Scope

Routing has one authored semantic model and two derived execution paths. The
userspace `Router` evaluates a canonical policy IR; a restricted compiler lowers
that same IR to native eBPF comparisons. The kernel does not interpret a second
policy representation. Linux 6.12 is the real-backend baseline.

The static TC programs retain packet parsing, special/local exclusions, DNS ownership,
conntrack, mode and health enforcement, NFQUEUE ownership, redirection, and reply
accounting. Generated code implements only `RoutingInput -> RoutingDecision`.
No flow is sent to userspace merely because its policy is compiled. Existing
native-direct and cached-flow paths remain native.

## Rule semantics

The canonical IR retains ordered rule IDs, display metadata, conditions, and an
outbound/mark/must action. Lower numeric priority wins; equal priorities retain
stable source order. The dae parser assigns source-order priorities `0, 1, ...`.
Startup, SIGHUP/reload, and network events synthesize no local-interface rules
or hidden kernel replacement allowlist. Conditions are ANDed, alternatives in a condition are ORed, and
negation applies once to the entire condition. Fallback is a separate terminal
action. Empty expanded sets remain conditions: positive empty sets are false,
negative empty sets are true; they must not disappear and widen a compound rule.


The configuration model and parser live in
[`crates/honk-config/src/routing.rs`](../../../crates/honk-config/src/routing.rs)
and its routing parser. `RoutingRule` carries one outbound tag, priority, mark,
and an explicit terminal `must` flag; `RoutingCondition` carries the positive
and negated matcher lists. `RoutingOutbound` is a single string target (a group
or built-in `direct`/`block`). `ClashRuleDisplay` retains simple matcher types
and uses `complex` for compound, negated, or parser-recorded `must` statements.
`Config::validate` rejects a rule or fallback that names a configured node
directly; use a group (including a one-node filter group).

## Kernel routing

The cutover preserves the current userspace matching contract:

- Ordinary domain pattern/suffix/keyword alternatives form one condition;
  geosite is a separate condition when both fields are present. Existing suffix,
  regex, keyword, case, and geosite attribute behavior is retained.
- Destination/source IP predicates preserve IPv4/IPv6 identity, including `/0`,
  host addresses and overlapping prefixes.
- Port ranges are inclusive. TCP/UDP and IPv4/IPv6 masks retain both alternatives.
- Process patterns retain the 15-byte configuration normalization and substring
  matching contract. Kernel process bytes are converted with the same lossy UTF-8
  and trimming behavior as a routing handoff, without allocation.
- Missing process/MAC/DSCP facts are not ordinary zero values. A missing domain
  does not satisfy a positive domain condition and does not veto a negative one.
- A configured `(must)` result is terminal: it sets the explicit `must` decision
  field and skips sniffing. Neither it nor `block` can be overridden by Clash
  mode.

LAN/WAN TCP/UDP destination port `53` evaluates this same ordered policy once
after existing ingress and control-plane exclusions, not a separate must-only scan. Local listeners do not exempt ordinary LAN DNS. The
[routing reference](../reference/routing.md#outbound-targets-and-must) defines
DNS ownership and [explicit local-rule migration](../reference/routing.md#explicit-local-rules).

The old compiler's dropped full/regex conditions, narrowed protocol unions,
truncated rule chains, first-rule DNS projection, and overlapping-prefix bitmap
loss are not compatibility requirements. The shared IR and independent semantic
fixtures must prevent these errors rather than encode them into the new backend.

## Canonical policy and domain facts

`CompiledRoute` contains metadata and a vector of `CompiledCondition` values,
rather than parallel positive/negative matcher field lists. A condition contains
one `CompiledPredicate` and its negation flag. Domain predicates reference an
immutable, policy-local registry of compiled domain matchers. Rule names are
labels, never bitmap identities. Identical domain predicates may share a stable
predicate ID within one policy.

### Source organization

- [`crates/honk-core/src/routing/`](../../../crates/honk-core/src/routing/) —
  userspace `Router`, priority-ordered compiled routes, `route_action`,
  `GeositeMatcher`, and the `BinaryLpmTrie`/geo-asset helpers. `geo.rs` parses
  `geoip.dat`/`geosite.dat` once per `Router` build and decodes only referenced
  codes; `category@attr` splits at the first `@` and filters attribute keys
  case-insensitively.
  Startup uses one captured Geo source set for both traffic and DNS compilation
  and drops it after both routers are built; compiled matchers and fingerprints
  remain owned by the routers.
- [`crates/honk-core/src/control/routing_matcher.rs`](../../../crates/honk-core/src/control/routing_matcher.rs) —
  compiles the IR into `RoutingPushPlan` and has no map side effects.
  [`crates/honk-core/src/ebpf/real/routing.rs`](../../../crates/honk-core/src/ebpf/real/routing.rs)
  owns generation maps, extension loading, target attachment, and publication.
- [`crates/honk-ebpf/src/route.rs`](../../../crates/honk-ebpf/src/route.rs) —
  static root/slot facade and fixed-ABI dispatch; it contains no interpreter or
  fallback rule engine. Static TC callers retain packet parsing and enforcement
  around this synchronous call.
- Older sockops/sk_msg redirection experiments are not part of the current
  datapath. They were removed after kernel-panic reports on some kernels; TC
  redirect is the supported path, and the loader resolves only current program
  names.

The userspace reference and kernel compiler consume this representation. DNS and
sniffing produce the truth bits of **all domain predicates**, not the first
matching complete traffic rule. This includes predicates used by negated rules;
the evaluator applies negation, not the projection writer. A known domain with
no matching predicate produces a present zero bitmap. Removing its final live
owner removes the IP entry.

DNS association remains IP-based and source-independent, with multiple live
owners ORed as before. It does not prove the exact SNI of every connection to a
shared address. Dial-mode reality checks and permitted sniff rerouting remain
userspace responsibilities. The migration does not introduce blanket
unknown-to-punt behavior or silently change the four dial modes.

## Generated function ABI

The fixed-layout ABI lives in `honk-ebpf-common`. All fields use fixed-width
integers; neither Rust enum layout, references, strings, nor allocator-owned
objects cross the boundary.

`RoutingInput` contains network-order source/destination addresses, a canonical
16-byte MAC key, normalized process bytes and length, host-order ports, protocol
and family masks, DSCP, and provenance/presence information. `RoutingDecision`
contains outbound, mark, must, domain-finality, and rule ID. A scalar return code
separates a successful decision from an unavailable or failed evaluator.

`domain_final` means that a later domain routing observation cannot change this
phase's route under its dial mode: the policy has no domain predicates, domain
rerouting is disabled, or a complete learned-domain bitmap was available. It is
policy-generation data, not a separately published global routing flag.

For non-DNS traffic, a non-`must` direct result with unresolved domain finality is
encoded as `ControlPlaneRouting` when handed to userspace. Passing it as final
`direct` would make TCP and UDP initialization skip sniffing. Known direct,
`must`, block, and mode-owned direct offload retain their terminal behavior
within that non-DNS path; port-53 ownership follows the rules above.

Miss-only inputs reuse the existing per-CPU packet scratch; cached packets do
not clear that storage. Volatile slot accesses keep the complete input/output
ABI live under LLVM optimization. Process normalization uses separately
verified, bounded global subprograms so Unicode decoding does not multiply
the WAN parser's verifier states.

The static callers convert the decision into their existing datapath actions.
In particular, `ControlPlaneRouting` is not a `TC_ACT_*` value. An evaluator error
runs the caller's existing fail-closed cleanup, including an outstanding UDP
Preparing claim; it is not disguised as a userspace routing request.

## Restricted native backend

The backend emits typed eight-byte BPF instructions, checked labels/fixups,
constant comparisons, masks, map lookups and terminal result writes. It owns no
TLS/QUIC parser, proxy dialer, mode controller, health checker, or generic VM.
Large IP/MAC/domain sets are data indexes, not thousands of inline literals.

The emitter folds empty inline predicates before writing instructions: a positive
empty predicate makes its whole rule impossible; a negated one adds no condition.
If a rule becomes unconditional, emission ends at its action. Later rules and the
fallback must not leave unreachable instructions that the kernel rejects before
semantic verification. Retained actions keep their original rule IDs and metadata.

Each generation owns separate destination IPv4/IPv6 and source IPv4/IPv6 LPM
maps, a MAC index and a domain hash map. Family-separated IP maps prevent an IPv6
prefix from matching a mapped IPv4 flow. A more-specific LPM entry inherits all
matching ancestor predicate bits, so longest-prefix lookup preserves ordered
rule semantics. Facts use the complete `DomainRouting` bitmap within their own
generation; a staged prefix cannot shadow facts from another generation.

Facts are values, not pointers. Each category (domain, destination IP, source
IP, MAC) is resolved at most once per invocation: the lookup copies the 32-byte
`DomainRouting` bitmap out of the map value into a fixed stack area for that
category, or fills the area with zeros when the input has no such fact or the
map has no entry. Every fact use is dominated by that resolution and no map
pointer is read after it; each condition tests its bit directly in the area (a
zero bitmap fails every positive bit, which is what a missing entry meant),
then applies negation. The domain is resolved in the prologue because a hit
also sets `domain_final`. Within each rule, complete positive and negative
destination/source-port conditions run before the remaining conditions.
Non-domain facts are resolved at their first reached use, not at rule entry:
each use checks its category bit in the invocation-local `R8` readiness mask.
Only a completed bitmap copy or zero fill sets that bit; map misses, absent MACs,
invalid families and present-zero bitmaps therefore also count as resolved.
An earlier skipped use leaves the bit clear so a later use still resolves it.
Every call starts with an empty readiness mask; no fact state crosses invocations
or generations. Lazy guards add code at each use site, while avoiding fact work
on paths rejected earlier; this is not a measured net throughput improvement.

The verifier must not see the mask's initial value as a constant. Set with
`mov 0` it is one precise value per resolution history; states with different
values cannot subsume one another, and the verifier walks every later
process-name chain once per value (the #280 policy: 160,415 processed
instructions on Linux 6.12.107; a policy with four fact rules ahead of
twenty-nine process-name rules: 368,874). The prologue therefore loads the mask
back from the decision's just-zeroed `mark`: the verifier does not fold a memory
load into the stored constant, so the low word is unknown, while the runtime
value is zero. The three lazily resolved areas are pre-filled from fresh loads of
the same field, so a use verified before its resolution reads initialized stack
and the stored words share no scalar id with the mask; spilling the mask register
itself links them and the walk splits again (133,354). Each guard is a `jset` on
the mask register, which refines the tested bit on both edges, so the skip edge
and the resolve edge agree at the bit test; testing a copy in `R0` leaves the
register unrefined on the skip edge (82,234). With all three the two policies
cost 53,741 and 100,645 processed instructions, close to unconditional
rule-entry resolution; `jset` alone on a constant mask changes nothing. At
runtime every fact use follows a completed resolution. These are measurements
of Linux 6.12.107; a verifier that tracked memory contents through the store
would make the mask a constant again.
Because the mask is loaded from `mark`, the prologue never writes a configured
value there. A marked or `must` fallback stores its mark, `must` and direct-mark
index only on the fallback exit reached after every rule; a plain fallback adds
no stores.

The verifier is why. A pointer's type depends on the lookup outcome, and the
verifier never merges a NULL with a map pointer, so a fact pointer kept live
across later rules multiplied the states walked through everything emitted
after it; two `sip && dip && dport` rules ahead of fifteen process-name rules
pushed a policy over the 1,000,000-instruction budget (#280: 159,837
instructions processed without them, over 1,000,000 with, on Linux 6.12).
Copied bitmaps are scalars, and a recorded imprecise scalar state can subsume
the others when the rest of the state is compatible. Branch layout is part of
that: the verifier explores the fall-through of an unresolved conditional
first, so the copy from a map value sits on the fall-through at every split
(including the IPv4/IPv6 dispatch) and the zero fill on the jump target; a
zero fill recorded first becomes precise once a bit test on it is predictable
and cannot subsume the later unknown values. Measured on the same kernel, the
issue's policy verifies in 53,383 processed instructions without the two rules
and 53,741 with them. Successful verifier-budget tests establish loadability,
not that numeric cost. IPv4/IPv6 key construction and map selection still join at one lookup call;
only IPv4 key padding is zeroed, without clearing bytes immediately overwritten.

Fact preparation keeps hash-first duplicate coalescing, sorts only unique keys,
and applies ancestor inheritance in the original vector before compacting its
retained capacity. Assembler-owned ordinal labels identify internal branches;
only rule source records retain diagnostic text. Input/output offsets come from
the shared ABI declarations rather than an independently maintained offset table.

Policy identity hashes length-framed normalized rule fields, ordered domain
registry keys and selected geo digests, never derived trie nodes or `Debug`
renderings. It preserves effective no-op reloads: changing an ignored process-name
suffix must not republish an equal native plan and discard sniff-only facts.

Each fact LPM retains the 2,048,000-entry limit without preallocation; the learned
domain hash retains 65,536 entries. Prefix count is independent of predicate count:
one GeoIP predicate can contain hundreds of thousands of prefixes. The emitter
checks its 1,000,000-instruction budget before each instruction insertion and stops
immediately on exhaustion, before further instruction or fixup expansion.

Capacity and verifier limits are explicit errors. No rule chain is truncated and
no missing outbound silently becomes direct. Generated source attribution records
rule IDs and normalized rule descriptions. A raw loader uses the existing syscall
and BTF infrastructure, not a new runtime clang/LLVM dependency or an ELF writer.
It preserves the real function prototype and uses instruction-slot offsets for
`func_info`/`line_info`; `.BTF.ext` byte offsets are not the raw syscall format.

## Synchronous slots and atomic publication

Every relevant, loaded TC program exposes two non-inlined, distinct BTF-global
functions, `honk_route_slot0` and `honk_route_slot1`. Uninstalled functions return
an error and contain no fallback rule engine. The backend loads the LAN/WAN L2/L3
routing targets before admitting traffic, including variants that may be attached
to an interface later.

`ROUTING_POLICY_ROOT` is a one-entry map-in-map pointing at an immutable
`RoutingPolicyDescriptor`. The descriptor identifies the slot, policy generation,
feature bits and the active domain-map ID for inspection. A route pass obtains
one descriptor and calls exactly one synchronous slot. Cached packets do not
perform this lookup.

The controller supplies the immutable plan and the complete learned-domain slice
in one backend publication call. The backend chooses its inactive slot and owns
the candidate locally; no caller-selected slot or pending-domain handshake is
needed. Static plan reuse and DNS projection ownership remain separate.

Publication is serialized with the existing reload and DNS publication fences:

 1. Compile and validate the complete candidate and retain the active policy.
 2. Build and fill candidate-owned fact maps, including its learned-domain state.
 3. Load the generated extension with those exact map FDs and valid BTF metadata.
 4. Attach it to the inactive slot of every relevant TC target.
 5. Replace the single generation root last.
 6. Only after that successful update returns may old TC slots/maps be retired.
    Userspace IR/reference leases retain their own lifetime independently.

Linux 6.12 waits for old non-sleepable BPF invocations before a successful
map-in-map update returns: its
[`maybe_wait_bpf_programs`](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c)
uses `synchronize_rcu()`. A plain root store, elapsed delay, or merely retaining
two slots is not an equivalent grace period. The design does not rely on
`BPF_LINK_UPDATE` for freplace (unsupported), nor detach/attach the active slot.

The native backend's publish operation is all-or-nothing before root commit.
Failure during map construction, verification or any inactive attachment leaves
the active code and facts intact. Failure is not handled by closing datapath
admission, which would pass traffic through, or by punting all flows. Rule-derived
flags and domain writers must use the same policy generation. Mode/NFQUEUE
coordination and existing-flow ownership remain with their current controllers.

The committed routing generation is nonwrapping. `ROUTING_GENERATION_SEQUENCE`
persists reservations across process restarts; its 20-bit space permits 1,048,575
reservations, including failed publications and descriptor-only NFQUEUE fences.
At exhaustion the active policy remains, further publication is rejected and
NFQUEUE fences remain closed. Do not delete the pin while host fragment queues
can survive. Unchanged policy can skip recompilation, but a queue fence still
publishes a fresh descriptor generation. See [datapath ABI](./datapath.md#map-inventory)
for physical carriers and [control-plane admission](./control-plane.md#transparent-ingress)
for queued metadata and generation lifetimes.

Only the generation root is a stable policy pin. Tools resolve the active domain
map through its descriptor instead of assuming that a same-named pinned map
changes the references held by an already loaded BPF program.

## Verification and acceptance

Implementation is accepted only with all existing matchers supported and with:

- Independent golden fixtures for precedence, OR/AND/negation, missing facts,
  `(must)`/block/marks, IPv4/IPv6, overlap, process normalization, domain projection
  and capacity failures.
- Reference-versus-real-generated-BPF comparisons of the complete decision, not
  only outbound or emitted structure, including source metadata and finality.
- Real TC/cgroup/netns traffic for native direct, proxy, block, DNS, LAN/WAN,
  TCP/UDP, and cached flows; queue/token tests retain the real NFQUEUE contract.
- Failed staging/verification/attachment and repeated-generation tests proving
  that no partial generation is visible and old flows remain owned.
- Paired tests of full routing and traffic costs, hot/cold facts, reload latency,
  JIT size, and peak memory. The strengthened packed-data/AOT bounded-loop path
  is a baseline; isolated port microbenchmarks are not whole-engine proof.

### Recorded branch validation

The current CI real-kernel baseline is the pinned Ubuntu Linux
`6.12.0-061200-generic` VM. CI builds the test executables on the hosted runner
and runs those exact artifacts in the VM; it does not compile again in the guest.
The VM runs the root-only routing and integration gates, while `just test-routing`
also exercises the generated policy through the root/slot path, including
precedence, complete decision metadata, capacity failures, and failed-publication
preservation. `just test-netns` includes that routing gate.

Performance measurements and historical prototype/lab records are intentionally
not kept on this design page. The reload benchmark definition lives in
[`crates/honk-core/benches/reload.rs`](../../../crates/honk-core/benches/reload.rs);
the [CI workflow](../../../.github/workflows/ci.yml) selects the VM gate,
[`run-vm-gate.sh`](../../../.github/ci/run-vm-gate.sh) owns the host preparation and VM command,
and [`pins.env`](../../../.github/ci/pins.env) owns the pinned image.

## Related docs

- [Routing configuration reference](../reference/routing.md)
- [Datapath](./datapath.md)
- [DNS](./dns.md)
- [NFQUEUE](./nfqueue.md)
- [Control plane](./control-plane.md)
