# Compiled routing decision plane

## Scope

Routing has one authored semantic model and two derived execution paths. The
userspace `Router` evaluates a canonical policy IR; a restricted compiler lowers
that same IR to native eBPF comparisons. The kernel does not interpret a second
`MatchSet` program. Linux 7.2 is the real-backend baseline.

The static TC programs retain packet parsing, special/local/DNS exclusions,
conntrack, mode and health enforcement, NFQUEUE ownership, redirection, and reply
accounting. Generated code implements only `RoutingInput -> RoutingDecision`.
No flow is sent to userspace merely because its policy is compiled. Existing
native-direct and cached-flow paths remain native.

## Rule semantics

The canonical IR retains ordered rule IDs, display metadata, conditions, and an
outbound/mark/must action. Lower numeric priority wins; equal priorities retain
source order. Conditions are ANDed, alternatives in a condition are ORed, and
negation applies once to the entire condition. Fallback is a separate terminal
action. Empty expanded sets remain conditions: positive empty sets are false,
negative empty sets are true; they must not disappear and widen a compound rule.

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
- A configured `(must)` result is terminal. It is not the internal historical
  `MustRules` opcode. Neither it nor `block` can be overridden by Clash mode.

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

A non-`must` direct result with unresolved domain finality is encoded as
`ControlPlaneRouting` when handed to userspace. Passing it as final `direct`
would make TCP and UDP initialization skip sniffing. Known direct, `must`,
block, and mode-owned direct offload retain their terminal behavior.

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

Each generation owns separate destination IPv4/IPv6 and source IPv4/IPv6 LPM
maps, a MAC index and a domain hash map. Family-separated IP maps prevent an IPv6
prefix from matching a mapped IPv4 flow. A more-specific LPM entry inherits all
matching ancestor predicate bits, so longest-prefix lookup preserves ordered
rule semantics. Facts use the full `DomainRouting` bitmap in their own generation;
there is no shared two-bank LPM value that a staged prefix can shadow.

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

Linux 7.2 waits for old non-sleepable BPF invocations before a successful
map-in-map update returns. A plain root store, elapsed delay, or merely retaining
two slots is not an equivalent grace period. The design does not rely on
`BPF_LINK_UPDATE` for freplace (unsupported), nor detach/attach the active slot.

The native backend's publish operation is all-or-nothing before root commit.
Failure during map construction, verification or any inactive attachment leaves
the active code and facts intact. Failure is not handled by closing datapath
admission, which would pass traffic through, or by punting all flows. Rule-derived
flags and domain writers must use the same policy generation. Mode/NFQUEUE
coordination and existing-flow ownership remain with their current controllers.

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

The earlier isolated Linux 7.2.3 prototype covered a protocol/port fragment only.
The branch validation below exercises the production callers and full policy.

### Recorded branch validation

`just test-routing` builds a separate test object and runs 117 hand-authored cases
in four dial modes (468 complete-decision comparisons) through the real root/slot
path. It also exercises predicate bit 255 for domain, destination/source IP and
MAC, rejects predicate capacity 257, and publishes a single rule with 65,537
distinct prefixes, checking its first/last hits and adjacent miss. Publication
failure checks preserve fact-dependent hits and misses, successfully republish
after an occupied attachment, identify the frozen-root syscall error, and reattach
every inactive target to verify link cleanup. `just test-netns` includes this gate.

These checks are separate native test scenarios with fresh backend fixtures;
the publication scenario explicitly installs its own baseline and retains the
same-backend failure-to-repair sequence. Both local and VM gates select the
routing-test module, not one monolithic test name. Golden cases carry explicit
labels and must/punt metadata rather than deriving their meaning from array positions.

The structural cleanup preserved byte-for-byte instructions and source records
for 32 generated programs plus 256 policy-equality relations, and passed all
15 checks in the expanded gate on Linux `7.2.0-cachyos`. The earlier capacity
repair also checked 10,000 process-name alternatives through the production parser
and emitter under a 256 MiB address-space limit, returning a capacity error rather
than aborting. The VM and lab records below predate these added checks.

The pinned Ubuntu `7.2.0-070200-generic` VM passed all 12 root-only checks:
TC/cgroup lifecycle and allocator compatibility, generated-policy publication,
TC/TUN packet contracts, the production NFQUEUE contract, and real netns flows.
CI builds the executables on its hosted runner and runs those exact artifacts
inside this kernel rather than compiling again in the guest.

On the isolated Linux 7.2.3 lab host, IPv4/IPv6 LAN checks covered 21 scenarios
and WAN checks covered 12: direct/proxy/block TCP and UDP, MAC/source/destination
conjunctions, DSCP, process matching, transparent DNS, hot and cold TLS domains,
and native held-first-packet direct UDP. A 16 MiB TCP stream ran for 12.802 s
across a reload that blocked new flows; policy publication took 9.43 ms and
restoration 9.24 ms. Direct/global mode checks preserved block and must rules.

Paired measurements used baseline `8b2ad586` (packed group metadata plus the
existing bounded-loop matcher), the same host/config, five trials, 512 short
connections at concurrency 16, and 8 × 8 MiB transfers at concurrency 4.
Kernel timings below are whole-TC averages, including cached packets, not
isolated generated-function timings.

| Equivalent workload | Baseline | Compiled | LAN TC mean, baseline → compiled |
| --- | ---: | ---: | ---: |
| must-direct connections/s | 9,719 | 9,738 | 382 → 342 ns |
| compound-proxy connections/s | 4,149 | 4,084 | 684 → 694 ns |
| cold-facts fallback connections/s | 6,241 | 6,709 | 598 → 563 ns |
| must-direct bulk, MiB/s | 2,145 | 2,158 | 292 → 281 ns |
| compound-proxy bulk, MiB/s | 1,944 | 2,011 | 422 → 423 ns |

Final-artifact equivalent-path throughput ranged from -1.6% to +7.5%; the
whole-TC averages are workload-dependent, not a blanket no-regression guarantee.
Observed peak process RSS was 84,628 → 78,636 KiB. The candidate retained
135,560 JIT bytes across its loaded
programs, including the preloaded L3 variants and a 10,014-byte generated
function. The allocation benchmark measured an unchanged reload at 15.33 →
15.29 ms, with 20 allocations / 68,097 bytes and no flag writes in either case.

The positive-domain comparison is deliberately excluded: baseline traffic
incorrectly used direct, while the candidate used the configured proxy.
Baseline known-zero traffic timed out after DNS; the candidate completed at
9,780 connections/s on the native path. These are correctness differences,
not like-for-like speedups.

## Related docs

- [Routing configuration reference](../reference/routing.md)
- [Datapath](./datapath.md)
- [DNS](./dns.md)
- [NFQUEUE](./nfqueue.md)
- [Control plane](./control-plane.md)
