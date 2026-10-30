# Native API, Clash API and `/stats` reference

honk provides a native HTTP API, a Clash-compatible HTTP API and a userspace statistics snapshot. The native and Clash APIs have independent features, listeners, credentials, and HTTP boundaries. Both reuse the same engine handles and userspace statistics.

## Native API

Enable the opt-in `native-api` Cargo feature with `--features native-api` (or `native-ui`). `--no-default-features --features native-api` works without Clash. Choose the release artifact by the interfaces you need:

| Release | Native API | Embedded UI | Clash API |
| --- | --- | --- | --- |
| Full | Yes | Yes (`native-ui`) | Yes |
| `-native-api` | Yes | No | No |
| `-clash-api` | No | No | Yes |

The listener remains disabled until you enable [`experimental.native_api`](./experimental.md#native_api). `.dae` remains the configuration format. Source administration edits the `-c` files, or with `--store db` records revisions in a SQLite configuration db ([Configuration db](#configuration-db---store-db)).

The native contract, including authentication, node/provider management, geodata and automatic-policy overrides, is [api-standardize e6b0dbab5599689d965bc18a71be67c809d99d0f](https://github.com/daeuniverse/api-standardize/tree/e6b0dbab5599689d965bc18a71be67c809d99d0f). `crates/honk-core/tests/fixtures/native_api_openapi.yaml` tracks this bundle. Native runtime mode remains gated, and `full_transparency` is not advertised.

Source administration requires a captured `.dae` startup. Writes additionally require `config_write` and either a nonempty secret or `password_auth`. Discover current capabilities and source permissions rather than inferring availability from route names.

| Method | Path | Meaning |
| --- | --- | --- |
| GET | `/api` | Public discovery: authentication state and sign-in links for every caller; the fixed `/api/v1` base and all contract links for an admitted caller. |
| POST | `/api/v1/auth/setup` | Create the first password-mode administrator and issue a session. |
| POST | `/api/v1/auth/login` | Verify the password-mode administrator and issue a session. |
| POST | `/api/v1/auth/logout` | Revoke the authenticated password-mode session. |
| GET | `/api/v1/version` | Native contract identity, the engine's build version, and the build's commit and target; no invented build timestamp. |
| GET | `/api/v1/capabilities` | Implemented resources and request limits. |
| GET | `/api/v1/runtime?detail=summary\|full` | Engine phase, accepted generation and independently timestamped visible userspace traffic. |
| GET | `/api/v1/runtime/outbounds` | Full-width per-kind outbound counters from the shared statistics lifetime. |
| GET | `/api/v1/runtime/memory` | Actual process RSS and available cgroup-v2 readings; unknown values are null. |
| GET | `/api/v1/runtime/traffic/history`, `/api/v1/runtime/memory/history` | Bounded samples; optional `window_seconds` and `max_points`, each 1–600 and default 600. |
| GET | `/api/v1/connections?type=all\|tcp\|udp&src=192.0.2.1&limit=100&detail=summary\|full` | Visible active userspace connections; `src` is an optional IP literal without port. |
| GET | `/api/v1/flows`, `/api/v1/flows/{flow_id}` | Active and retained terminal userspace decisions; detail includes the source-recorded trace. |
| GET | `/api/v1/nodes` | Stable node IDs, current direct group membership/provenance and qualified measurements. |
| POST | `/api/v1/nodes` | Create a main-source node from `{name,link}`; 201 only after activation. |
| GET | `/api/v1/nodes/{id}` | One node in the list projection; unknown IDs return 404. |
| DELETE | `/api/v1/nodes/{id}` | Remove a main-source inline node; return `{deleted:0\|1}` after activation. |
| GET | `/api/v1/groups`, `/api/v1/groups/{groupId}` | Read-only group observations, direct members, config revision and captured health; the list follows configuration order. |
| GET | `/api/v1/groups/{groupId}/config` | The group's `policy` and `config` with the config revision as `ETag`. |
| PUT | `/api/v1/groups/{groupId}/selection` | Select one direct member for `tcp`, `udp` or `both`. |
| DELETE | `/api/v1/groups/{groupId}/selection` | Clear an automatic group's pin for `tcp`, `udp` or `both`. |
| PATCH | `/api/v1/groups/{groupId}/config` | Restricted source-owned JSON Patch with the group's accepted revision. |
| POST | `/api/v1/probes` | Queue bounded typed measurements of configured nodes/groups. |
| GET | `/api/v1/providers`, `/api/v1/providers/{id}` | Accepted node counts and real subscription-owner status. |
| POST | `/api/v1/providers/{id}/refresh` | Fetch, admit and publish a configured provider through an operation. |
| POST | `/api/v1/providers` | Create an unfetched main-source subscription from `{name,kind:"subscription",url}` plus optional `update_interval`, `user_agent` and `cache`. |
| DELETE | `/api/v1/providers/{id}` | Remove a main-source HTTP(S) subscription and its loaded nodes. |
| GET | `/api/v1/geodata` | Read retained metadata of the assets actually loaded by traffic/DNS routing. |
| POST | `/api/v1/geodata/update` | Download configured assets, validate all candidates and activate verified bytes through an operation. |
| DELETE | `/api/v1/connections/{connection_id}`, `/api/v1/connections` | Close exact userspace owners; bulk requires a filter or `all=true`. |
| POST | `/api/v1/dns/query` | Live diagnostic query. |
| GET | `/api/v1/dns/cache`, `/api/v1/dns/log` | Exact cache inspection and retained client outcomes. |
| DELETE | `/api/v1/dns/cache/{entry_id}`, `/api/v1/dns/cache` | Invalidate one exact incarnation, or a name and optional types. |
| POST | `/api/v1/dns/cache/flush` | Invalidate the DNS cache with acknowledged persistence fencing. |
| POST | `/api/v1/routing/trace` | Generation-pinned simulation with `resolve: "none"`. |
| GET | `/api/v1/rules` | Complete generation-scoped rule dictionary including fallback. |
| GET | `/api/v1/dns/rules` | Running generation's DNS request and response rules, each list ending with its fallback. |
| GET | `/api/v1/logs` | Sanitized structured-log SSE, separate from Clash logs and native events. |
| GET, PATCH | `/api/v1/runtime/settings` | Read or atomically merge supported transient recorder settings. |
| GET, PUT | `/api/v1/x-honk/runtime/mode` | Gated with `404 capability_not_supported` pending a complete failure contract. |
| GET | `/api/v1/datapath` | Bounded backend-owned observations, not full flow transparency. |
| GET | `/api/v1/events` | Bounded authenticated SSE invalidations with filter-bound resumable cursors. |
| GET | `/api/v1/config`, `/api/v1/config/sources/{source_id}` | Authenticated accepted source metadata and content, with listener-secret values masked. |
| POST | `/api/v1/config/validate` | Offline `syntax` or `full` candidate validation, without writing or activation. |
| PUT | `/api/v1/config/sources/{source_id}` | Authorized whole-source replacement with RFC 9110 `If-Match`, then a real reload operation. |
| POST | `/api/v1/config/sources` | Create one new `.dae` file that an include pattern loads, then a real reload operation. |
| POST | `/api/v1/operations/reload` | Queue a reload from disk; accepts an empty body or JSON `{}`. |
| GET | `/api/v1/operations/{id}` | Actual queued/running/succeeded/failed state and safe result/error for admitted operations. |

### Connection observations

Admitted anonymous loopback requests read the same connection data as bearer-authenticated requests. Display fields mask listener-secret values.

| Parameter | Default | Values |
| --- | --- | --- |
| `detail` | `summary` | `summary` omits `src`, `dst` and `domain`; `full` includes them. Unknown domains are null. |
| `type` | `all` | `all`, `tcp`, `udp` |
| `limit` | 100 | 1–1000, shared by TCP and UDP |

Full detail does not grant elevated permissions. The API rejects unknown parameters and repeated single-value parameters.

Filters apply before totals and the combined limit. Totals include all matching visible rows. Rows appear newest registered first, with lexical ID tie-breaking.

IPv4-mapped IPv6 sources compare as IPv4.

Connection `outbound` is the routing-time group/action, not a current leaf or a reconstructed selection. With recording enabled, `flow_id`, captured root-first group/leaf IDs, first-observation UTC and domain provenance link to retained evidence. Missing/evicted evidence remains unknown.

Captured userspace rule IDs share the generation identity used by `/rules` and trace. Kernel-final provenance is not reconstructed. Per-connection rates remain null.

Empty lists have `visibility: partial`, not proof that the device has no connections. HTTP readiness is not datapath readiness.

TCP accounting advances during successful copy reads or splice destination writes, including successfully written sniff prefixes once. UDP retains its per-packet accounting. A single one-second sampler uses the actual elapsed interval.

First samples, resets and overflow produce null rates rather than synthetic zeros. `counter_since` belongs to the shared counter lifetime, `sampled_at` to the traffic sample, and `observed_at` to the HTTP observation. UInt64 fields are decimal strings.

Bounded counts remain JSON numbers. `process.cpu_percent` is null until two usable CPU samples exist. See [telemetry](#outbound-counters-and-telemetry).

`generation.activated_at` is when the active generation was published, or when the engine first ran for the startup generation. While a configuration activation is in progress, `generation.state` is `reloading`, and a running, healthy engine reports `lifecycle.state: reloading`. Configuration revision is available with accepted sources.

`last_reload` reports completed API reload outcomes as described below.

### Runtime degradations

`degradations` lists reduced functionality after recovered failures and configured interfaces that are not yet bound. Each component has at most one entry.

| Field | Meaning |
| --- | --- |
| `code`, `message`, `details.reason` | Safe error information |
| `component` | Affected component |
| `since` | First degradation time; repeated failures preserve it |

An empty list means no known degradations. Entries do not change `lifecycle.state`: it remains `running` while configured interfaces are unbound. Monitoring must inspect `interface_binding`.

Adding, changing or clearing an entry publishes `runtime.updated`.

| Component | Condition | Re-evaluation or recovery |
| --- | --- | --- |
| `persistence` | The state database could not be opened or reset at startup. | Restart |
| `state_cache` | The state database's cache tables could not be opened. | Restart |
| `quic_probe` | A Score group needs QUIC probes, but the startup target or client is unavailable; see below. | Clears when an applied configuration has no Score group, or on restart once the target resolves. |
| `pname_routing` | A rule uses `pname()`, but cgroup v2 hooks are absent or only thread names are available. | Every configuration application |
| `iface_watch` | The real backend could not subscribe to rtnetlink or register polling. | Restart |
| `interface_binding` | A configured `lan_interface` or `wan_interface` entry is not fully bound. | Clears automatically when every entry is bound. |
| `udp_trace` | Kernel UDP receive tracing is unavailable during flow recording. | Every UDP listener start |

For `quic_probe`, target/client failure means one of:

- The first `tcp_check_url` is not an HTTPS URL.
- Its host does not resolve.
- The QUIC client cannot be built.

The probe target is chosen at startup. Reason `restart_required` means a reload added a Score group to a process that started without one.

For `pname_routing`, absent hooks leave `pname()` conditions without a process name: positive conditions never match, and negated conditions always match. Reason `comm_fallback` means conditions use the thread name instead of argv.

With `iface_watch`, reconciliation runs every 60 seconds without event notifications. Its code is `interface_watcher_disabled`; its reason is `subscribe_failed` or `poll_setup_failed`.

`interface_binding` uses code `interface_binding_incomplete` and message "A configured network interface is not fully bound; traffic interception may be incomplete."

| `details.reason` | Meaning, in descending precedence |
| --- | --- |
| `attach_failed` | A TCX link could not be created, updated or verified. Working hooks may still intercept some traffic. |
| `unsupported_type` | The entry is [refused](./global.md#interface-semantics), including unsupported nesting or self-master. |
| `pending` | The interface is absent, or an `auto` entry has no IPv4 default route. |

The first applicable reason wins. The message never names an interface; names appear only in logs. A failed topology read leaves the entry unchanged.

`udp_trace` keeps code `udp_trace_unavailable`. `details.reason` is `ipv4_unavailable` or `ipv6_unavailable` when failures affect only that listener family, and `unavailable` when both are affected. A family whose tracing remains available keeps recording kernel route evidence.

Attach warnings name the missing `family`. The listener warning carries `ipv4_unavailable` and `ipv6_unavailable` fields. Re-evaluation at listener start does not retry fallback hook attachment: that attempt is once per real backend, so restart after changing kernel/BTF support.

`GET /api` is public in every authentication mode. Password setup and login POSTs are also public. Without explicit anonymous loopback access, all other API resources require the configured static bearer or a live password session. This includes version and capabilities.

The exceptions cover only requests without credentials. Any request carrying credentials is authenticated, public or not. Invalid or duplicate credentials are rejected, not treated as anonymous. A token in the query string is always rejected. The existing secretless development mode requires explicit anonymous loopback authorization and rejects `Sec-Fetch-Site: cross-site`.

Host and Origin checks apply before these authentication exceptions and also cover public static files. OPTIONS preflight requires a permitted Host, Origin, method and header set but no bearer. No cookie credentials or wildcard CORS is returned.

### HTTP errors and limits

Errors use `{error:{code,message,details},request_id}`.

| Condition | JSON response |
| --- | --- |
| Known unavailable action | `404 capability_not_supported` |
| Unknown path | `404 resource_not_found` |
| Unsupported method on a known resource | `405 method_not_allowed`, with `Allow` including HEAD for GET resources |

HEAD follows GET status and headers without a body. API responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

| Application budget | Bytes |
| --- | --- |
| Normalized request target | 4096 |
| Normalized header names and values, combined | 16384 |
| Body, including chunked requests | 65536 |

Authenticated GET/HEAD requests with a nonempty body are invalid. Observation reads never trigger probes or selection changes; `/dns/query` is explicitly a live diagnostic.

Error `details` name what was rejected, never a submitted or configured value. Request-boundary errors carry the `header` or request part (`field`: `query`, `body` or `target`) and a `kind`. A JSON body that fails to parse or match its schema gets the endpoint's `400 invalid_request` with `{field,kind}`: `field` identifies one of:

- The dotted member path, such as `sources[0].content`.
- The object holding an unknown key.
- `body`.

`kind` is `invalid_json`, `missing`, `wrong_type`, `unknown_field`, `duplicate`, `invalid_value` or `too_large`. A 422 `unsupported_value` names the rejected `field` or `fields`, plus where relevant the managed `resource` path, the `allowed` values or paths, the failed `check`, or the `settings` that can permit it.

The native server owns at most 64 HTTP/1.1 connections in total and 16 per canonical socket peer IP. It pauses acceptance at the global capacity. Immediately after accept, it closes any connection exceeding its peer's limit without an HTTP response and logs it at DEBUG.

Forwarded headers do not change the peer, so clients behind one reverse proxy share its allowance.

Header reading is bounded to five seconds. Shutdown drains connections for at most five seconds before aborting and joining them. The 30-second read-idle deadline applies only while no request is in flight on a connection (from the end of a request body until its response resolves).

Stalled writes have a separate 30-second deadline. Successful SSE heartbeat writes keep healthy streams alive, while reads cannot extend a blocked writer's deadline.

TLS/HTTP2 can terminate at a trusted reverse proxy. Forwarded headers neither rewrite fixed discovery paths nor authorize a Host/Origin.

Password mode closes credential admission before this HTTP grace, then joins its actual blocking credential job. The five-second HTTP budget does not bound that final KDF/database join.

HTTP transport boundary: Hyper can reject malformed or hard-limit HTTP with 400/414/431 or a disconnect before application code; those transport rejections need not carry the JSON envelope or application headers.

Application target/header budgets apply to Hyper's parsed, normalized representation, not the original wire bytes. Hyper may remove a request-target fragment or coalesce equal `Content-Length` fields before application counting. Oversized original text in those forms can therefore reach a normal response instead of 413.

Raw input remains subject to Hyper's transport handling. This is an accepted boundary difference, not a second HTTP parser or a raw-wire size guarantee. Body limits still cover all delivered body bytes.

With `ui` configured, `/` and `/ui` redirect to `/ui/`. Directory hosting retains extensionless SPA fallback. Missing static assets, fonts/icons, manifest or service worker return 404, never HTML.

Build with `--features native-ui` (the full release builds do) and set `ui: embedded` to serve the pinned real doona distribution without filesystem extraction or network access. `ui: embedded-lite` selects the lighter doona lite edition (preview), also requiring `native-ui`. Both editions connect to the native API on the page origin.

The hash router uses `/ui/#/...`. Other safe embedded navigation paths redirect to `/ui/` so relative assets and the service worker resolve correctly. The embedded UI is stored precompressed and served as brotli or gzip when the browser accepts it.

Directory hosting serves the administrator's `.br`/`.gz` siblings the same way. Content-hashed files under `assets/` are cached as immutable for a year. Other static responses use `no-cache`.

Static responses use `nosniff` and carry no framing header, so dashboards such as LuCI can embed the UI. A deployment that needs clickjacking protection adds `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` at its reverse proxy. Assets remain public behind Host/Origin admission.

Discovery and password setup/login use the public exceptions above. Other API requests require a static or session bearer unless explicit anonymous loopback access is enabled. No credentials are injected into the UI.

### Authentication discovery and password sessions

Discovery returns `auth: {mode, setup_required, anonymous_loopback}`. `mode` is `token` for a nonempty configured `secret` and for anonymous loopback development, or `password` when `secret` is empty and `password_auth` is enabled. `setup_required` is true only in password mode before the administrator record exists.

`anonymous_loopback` is true only for the explicit development mode on an actual loopback bind. `links.auth_setup`, `links.auth_login` and `links.auth_logout` contain their endpoint paths in password mode and are null otherwise.

A request without a credential that the listener does not admit gets only `name`, `api_major`, `links.auth_setup`, `links.auth_login`, `auth.mode` and `auth.setup_required`. Every other field is omitted. A request admitted by bearer, session or explicit anonymous loopback gets the full response.

In token mode, the three password endpoints are unavailable with `404 capability_not_supported`. Password-mode requests use the following contract:

| Endpoint | Request and success | Mode-specific failures |
| --- | --- | --- |
| `POST /api/v1/auth/setup` | `{"username":"admin","password":"..."}` → `201 {"token":"hnk1_…","expires_at":"..."}` | `403 permission_denied` for an ineligible peer; `409 setup_already_completed` after the first administrator is published. |
| `POST /api/v1/auth/login` | Same body → `200 {"token":"hnk1_…","expires_at":"..."}` | `409 setup_required` before setup; `401 invalid_credentials` for either a wrong username or wrong password. |
| `POST /api/v1/auth/logout` | `Authorization: Bearer <session>` → `204` | Invalid or expired sessions fail normal bearer authentication. |

`expires_at` is an RFC 3339 UTC timestamp. Setup and login use these limits:

| Input | Requirement |
| --- | --- |
| `Content-Type` | `application/json` |
| Query string | Not allowed |
| Unknown JSON fields | Not allowed |
| Body | At most 4096 bytes |
| Username | Case-sensitive ASCII matching `[A-Za-z0-9_.-]{1,64}` |
| Password | 8–128 Unicode scalar values, at most 512 UTF-8 bytes |

Invalid JSON or fields return `400 invalid_request`. A missing or different media type returns `415 unsupported_media_type`.

Media types are case-insensitive. Duplicate or non-text `Content-Type` values return `400 invalid_request`; configuration, authentication, probes and routing diagnostics share this JSON/header parser.

Setup trusts only the peer address from the accepted socket, never `Forwarded`, `X-Forwarded-For` or another header. It permits `127.0.0.0/8`, `::1`, RFC 1918, `fc00::/7`, `169.254.0.0/16` and `fe80::/10`. IPv4-mapped IPv6 is classified as IPv4.

Other peers receive `403 permission_denied` before account-state or credential processing.

Setup and login admit at most five attempts per canonical peer IP and ten attempts across all peers in each one-minute window. Five consecutive credential failures from one peer impose a 60-second lock on only that peer, measured from its last failure. Another peer's failures or successful login cannot extend or clear that lock.

Successful setup/login clears only that peer's failure state but still counts in the attempt windows. A rejected attempt returns `429 rate_limited` with `Retry-After`. These counters and locks are process-local.

Peer state is bounded and discarded once both its attempt window and lock have expired, so an inactive peer's partial failure streak also expires. The global attempt window remains in force across all peers.

Only one credential job runs at a time, off Tokio workers. Overlapping attempts return 429 with `Retry-After: 1`. HTTP cancellation neither frees that slot nor discards its credential outcome.

Discovery reads short-lived credential state, not a lock held across KDF or database I/O.

Session tokens are opaque `hnk1_…` values used as `Authorization: Bearer <session>`. Each has a fixed 12-hour lifetime. The process retains only SHA-256 token digests, keeps at most 32 live sessions and evicts the oldest when issuing another.

Restart ends every session. A session that ends by logout, expiry or eviction also closes the `/events` and `/logs` streams it opened. The client then reconnects and must authenticate again.

Operations started through a configured secret or password login belong to the administrator rather than to one token, so logout does not delete them.

Password mode stores one credential record in the `admin` row of the state db, `<data_dir>/state/honk.db` (a 0600 file in a 0700 directory; see [Configuration db](#configuration-db---store-db)). A malformed record prevents startup, and so does a corrupt state db: password mode never moves it aside.

The record uses PBKDF2-HMAC-SHA256 with 100,000 iterations and a fresh 16-byte random salt. Password mode uses the configured `global.data_dir` itself: if that directory is unusable, startup fails instead of falling back to another directory, where setup would reopen. First setup inserts the row without replacing an existing one, so of two processes racing setup on one state db exactly one wins.

Setup fails and can be retried in either case:

- The db is busy before anything is written.
- The insert fails and is rolled back.

If the commit or rollback fails, the row’s durability is uncertain. The process refuses login and a second setup until it restarts.

Once setup claims the credential state, discovery reports `setup_required:false`, including while durability is indeterminate. An indeterminate write returns 503 with `durability_confirmed:false` and no `Retry-After`, without claiming `written:true`. Restart is required to establish the stored account state.

There is no HTTP password reset. To recover access, stop honk, run `honk-core admin reset`, restart, and run setup again. Moving `<data_dir>/state` aside also works but discards every other persisted state.

Reset takes the exclusive state-directory lock before checking whether the database exists, so it cannot race a first startup that is creating it.

### Recorded userspace flows

Admitted anonymous loopback requests read the same flow data as bearer-authenticated requests.

General attachment is active while an admitted GET SSE on `/events` or `/logs` is open, or for 60 seconds after the last stream closes or a successful GET `/flows`, `/flows/{id}` or `/dns/log`. It enables ordinary event capture only. It does not enable any Auto diagnostic recorder.

Diagnostic demand is separate:

| Admitted request | Auto diagnostic demand |
| --- | --- |
| `/events` with explicit flow kinds or an effective flow-event `flow_id` filter | Flows only |
| Successful GET `/flows` or `/flows/{id}` | Flows only |
| GET `/logs` SSE | Logs only |
| Successful GET `/dns/log` | DNS log only |
| Unfiltered/non-flow `/events`, ordinary API, validation, failed GET or HEAD | None |

Flow-event demand means explicit `kinds` containing `flow.updated` or `flow.gap`, or a nonblank `flow_id` whose effective kinds include flow events. Omitted `kinds` without such a filter does not request flows. Each admitted stream owns an independent lease for exactly its requested demand.

Failed admission acquires none, and closing/dropping the stream releases it even if never polled. Flows, logs and DNS logs each retain demand for an independent 60 seconds after their last stream closes or their corresponding successful GET. General activity and other demand kinds cannot extend that grace.

There is no DNS-log SSE kind. Recording starts on demand, so initially empty history is expected.

`record_flows` defaults true and permits recording while flow diagnostic demand is active. An explicit runtime `record_flows: "on"` keeps recording enabled without clients. Runtime `"off"` forces it off, and configuration `record_flows: false` prohibits recording until changed and restarted.

When effective recording stops, flow records and snapshots are released. One process-local store retains at most 1024 flows, 64 steps per flow and 8 MiB including snapshots and the kernel-dictionary reservation. Terminal records expire after at most 300 seconds, earlier under pressure.

Restart clears all records. The existing sampler performs expiry without a second timer.

Kernel witness production follows effective flow recording through the existing composed datapath flags. The existing sampler reconciles changes on a subsequent tick. Scheduling, telemetry and publication contention can delay convergence, so this is not a fixed one-second deadline.

Traffic routed before enablement can have explicit missing kernel evidence. Disabling demand does not discard retained witnesses or dictionaries, change routing/NFQUEUE authority, or revoke an operation's already-admitted capture eligibility. Unrecorded operations skip witness decoding.

Flow IDs represent incarnations, never tuples. TCP and UDP capture actual route predicates and short circuits, sniff/verification, group selection, DNS children, physical attempts, session reuse/retries and terminal boundaries. Failed or blocked setup is retained even without a live connection.

Names, IDs and generations come from the operation that used them, not today's configuration or a routing simulation. DNS lookup/parent IDs and outbound attempt/parent IDs preserve causality. A reused carrier is an attachment, not a new physical dial.

Protocol request/confirmation milestones require actual protocol evidence, and DNS-child readiness never becomes business-target confirmation. Terminal TCP/UDP evidence follows the owning cleanup boundary. Kernel offload ends observation as unknown, not a fabricated closed connection.

`trace_status` and `trace.status` are `complete` only when all executed decisions through the current frontier in that flow's scope were captured. Active, failed and closed flows can each be complete. This is not a success or global-coverage claim.

Missing/ambiguous source evidence, listener-secret withholding and exhausted capture budgets remain sticky `partial` with explicit `missing` reasons. Reaching a trace limit never stops forwarding. Userspace TCP/UDP and intercepted DNS population coverage remains `partial`.

Kernel-only direct, block and bypass populations remain `none`, and `full_transparency` stays absent.

Per-flow condition expressions use configured source spelling cached with the compiled generation, including GeoIP references rather than expanded network lists. This avoids expansion-only truncation, not real capture limits: oversized authored text, redaction, missing source evidence and exhausted step/byte budgets still report partial traces.

For handed-off traffic, kernel rule outcomes come from the compiled program's own branch witness, not userspace re-evaluation. UDP additionally requires the received packet's capture ID. Tuple, decision token, routing generation and action must agree with the retained witness.

A later tuple incarnation cannot supply an older packet's evidence. Capture IDs do not wrap. Frozen dictionaries retain at most 16 policies, 64 KiB each and 1 MiB total within the recorder reservation.

Dictionary rejection/eviction, missing witnesses, ambiguous TCP association and executed overflow beyond 256 rule/condition values produce partial evidence. Unexecuted rules beyond that value ceiling alone do not imply lost execution.

If a policy’s kernel trace dictionary would exceed 64 KiB, honk publishes it with kernel route tracing off and logs a warning. This applies at startup and on reload. Its flows report `kernel_trace_not_captured` rather than undecodable witnesses. The check sizes rule identifiers for the longest generation number, so a policy right at the bound may already be published untraced.

Native extension fields retain source detail without inventing identities: route input may include `ingress`, `domain_fact_bitmap` and `domain_fact_state` rather than fabricated domain rule IDs. DNS-related outbound/connection steps carry `lookup_id`, and known physical peers carry `server_addr`. Selection facts include the health family and whether a decision was applied or only peeked.

Score's `previous_leaf_node_id` is distinct from `previous_member_id`: leaf history cannot reconstruct a historical subgroup path.

Flow list filters are `network`, `state`, `connection_id`, `detail`, `limit` and `cursor`. Eight bounded immutable snapshots live for at most 30 seconds. Cursors bind instance and original filters/detail.

A recognised cursor sent with different filters, detail or limit returns `400 invalid_request`. A full snapshot table evicts the oldest snapshot. Exhausted retained-byte capacity returns `503 snapshot_unavailable` with Retry-After.

Expired or evicted list snapshots return `410 snapshot_expired`, known retained tombstones `410 flow_expired`, unknown IDs `404 resource_not_found`. Detail has no query parameters and always includes full retained input/trace. Counters are decimal strings.

Revisions, sequence and elapsed microseconds are safe JSON integers. Display fields preserve paths, `@` and URLs within the 512-byte `MAX_TEXT` bound. Identifiers retain their separate validation.

Unrepresentable or oversized text and step/byte overflow remain explicit partial evidence, without discarding causal IDs or outcomes. Retained rule displays belong to the captured generation and are never rebuilt from current configuration.

### Nodes and groups

`Node.stream_transport` is an optional nullable string projected from accepted Trojan/VMess/VLESS configuration: `tcp`, `ws`, `grpc` or `xhttp` (including the `splithttp` alias). Honk returns null when unrecognized or inapplicable. It describes configured transport, not negotiation or health.

`protocol` and TCP/UDP health transport keep their existing meanings. It exposes no credentials, host, path, extra options or link. The fixture copies the doona contract bundle with its `read_only_reason` extension (SHA-256 `9f780ba92f13218ed7bc52e9a9af79a960d241ce6552a45522b41c30fc04faa0`).

This pin does not identify a published frontend release.

Node reads accept `group_id`, `limit` (1–1000) and `cursor`. Filtering is direct membership, not recursive leaves. Node pages freeze observations across up to eight snapshots, 30 seconds and 4 MiB.

A page that cannot fit returns `503 snapshot_unavailable` with `Retry-After`. An unrecognised node cursor returns `410 snapshot_expired`. A recognised cursor sent with different filters or a different `limit` returns `400 invalid_request`.

Groups return a summary array. Detail carries `config_revision` but no `ETag`, and `GET /groups/{groupId}/config` returns `{policy, config}` with that revision as a quoted `ETag`. Group IDs are random process-lifetime identities: same-name reload/reorder retains them, removal/readdition creates new IDs, and restart requires rediscovery.

They are not positional config UUIDs or name hashes.

These display values use the same listener-secret mask as source/flow displays:

- Node names and subscription tags.
- Group names, member names and icons.
- Check URLs and final-outbound labels.
- Outbound-counter names.

Node snapshots are masked before bounded serialization. Resumed pages retain those masked bytes.

Opaque IDs, revision hashes, membership and cursor bindings are unchanged.
The existing masking threshold still applies: listener-secret values shorter than eight bytes are not masked; startup warns about them.

Health rows are completed, qualified producer observations rather than optimistic alive flags, copied IPv4/IPv6 ranking signals, synthetic failures or restored delays. Raw TCP, HTTP response headers, DNS exchanges and QUIC handshakes retain actual destination family and completion time.

Node rows carry two averages per measurement key. Only successful native probes update them; restart clears them.

| Field | Calculation |
| --- | --- |
| `moving_avg_ms` | Halving average `(previous + sample) / 2`, used by URLTest ranking |
| `avg10_ms` | Mean of the newest ten successes, or all available successes during warm-up |

Both are null while the row is unavailable, and always null on group-specific samples. Unknown ranking/warmth remain null/unknown.

Group-specific samples preserve the measured member and leaf rather than rebinding to a later selection. GET never advances URLTest, round-robin or Score state. Group `icon` is the configured validated HTTP(S) URL or data URI, subject to listener-secret masking.

Absent icons are null, never guessed.

A health completion older than the retained sample for the same key is discarded, unless the retained sample lies in the future because the system clock stepped back. A replay at the same timestamp updates the row without counting twice in the averages. Group-specific samples keep at most 4096 measurement keys.

When full, replacement is second-chance rather than strict least-recently-updated: a key refreshed since the scan last passed it is skipped, so a continuously refreshed key outlives stale ones.

`PUT /groups/{groupId}/selection` takes `{"member_id":"<direct-member-id>","network":"tcp"}`. `network` is required and also accepts `udp` or `both`. On a Selector the write replaces its choice (`source: runtime`).

On an automatic group (`can_override: true`) it pins the member (`source: override`). A pin acts like a Selector choice, so an unavailable pinned member is not replaced by a sibling. Pins are runtime-only: they are never persisted, every configuration activation (including a subscription refresh that changes nodes) clears them.

An unchanged or empty refresh activates nothing and keeps them, and health checks keep running. One owner validates both networks before publishing `both`. A TCP-only write leaves UDP unchanged.

Writes serialize with manager replacement, update existing persistence/warm consumers, and return the committed `selection_revision` and actual `connections_interrupted`. Clash writes both networks and displays the TCP projection. With `interrupt_connections: true`, affected pre-transition transports are closed by their captured group path and network, not by deleting tracker rows or matching today's leaf names.

`DELETE /groups/{groupId}/selection?network=` clears the pin for `tcp`, `udp` or `both` (the default) and returns `GroupOverrideCleared` with the selection per network. A network without a pin keeps its selection, and a Selector returns `409 state_conflict`.

#### Group configuration patch

`PATCH /groups/{groupId}/config` requires:

- `Content-Type: application/json-patch+json`.
- A nonempty RFC 6902 array with at most 32 operations.
- RFC 9110 `If-Match` against the accepted revision from the `GET /groups/{groupId}/config` ETag.

Lists and multiple header field lines are combined. Weak tags never match. `*` matches the existing group.

A nonmatching condition returns 412. A detected concurrent source/dependency change returns 409 if the condition still matches.

Operation members other than `op`, `path`, `from` and `value` are ignored. Body errors (400, 413) precede a stale `If-Match` (412). The operations `add`, `replace`, `remove`, `test`, `copy` and `move` must stay within these paths:

| Path | Accepted value |
| --- | --- |
| `/policy` | A matching pair, such as `{"kind":"selector","native":"selector"}` |
| `/config/default_member_id` | Direct-member ID |
| `/config/final_outbound` | Configured outbound name |
| `/config/tolerance` | Nonnegative safe integer or null; only URLTest accepts non-null values |
| `/config/idle_timeout` | Nonnegative safe integer or null |
| `/config/interrupt_connections` | Boolean or null |
| `/config/check_url` | Null or a URL meeting the requirements below |

`check_url` must:

- Start with lowercase `http://` or `https://` and contain a host.
- Contain no userinfo, whitespace, control characters or commas.
- Not contain both single and double quote characters.
- Fit within 2048 bytes in normalized form.

PATCH stores the normalized URL that GET displays and the probe sends: no fragment, `/` for an empty path, lowercase host and no default port. `test` compares that form. Selector groups store `check_url` but do not probe it.

Only URLTest groups report or accept `tolerance`. Other policies report null and omit it from `mutable_config`. Setting it to a non-null value returns `422 unsupported_value`.

`remove` is accepted. A patch switching the policy to URLTest may set it.

Removing a field or setting it to null restores its dae default. If the source omits `tolerance` or `interrupt_connections`, GET reports null. The engine still applies `global.check_tolerance` or the default `interrupt_connections: false`.

| Failure | HTTP status |
| --- | --- |
| Unsupported path or value | 422 |
| Malformed patch | 400 |
| Failed `test` | 409 |
| Missing precondition | 428 |
| Stale revision | 412 |

Patch availability and `mutable_config` depend on the source's write permission. Without it, `mutable_config` is empty and PATCH returns `404 capability_not_supported`. PATCH edits parser spans in the authorized source, then performs full offline admission, durable replacement and a 202 reload operation.

It does not edit the Group in memory. The accepted group/config revision is checked before writing and again under the reload lock before activation. Source disk hashes and dependency topology are independently fenced.

A provider publication racing after the write can leave `written:true,committed:false`. No rollback is promised. A group ETag is not a source-file SHA-256.

Icons, names, filters and membership are not PATCH fields. Edit their authorized source instead.

### Native events

When bearer authentication is required, use streaming fetch with Bearer and `Accept: text/event-stream`. Browser EventSource cannot supply an Authorization header. Optional `kinds` and `flow_id` filters bind the resume cursor.

The store retains 512 events for at most 60 seconds, with 16 clients and 64 queued live events per client. A full client queue disconnects rather than silently skipping. A new stream while all 16 client slots are taken returns `503 temporarily_unavailable` with `Retry-After`.

Heartbeat comments arrive every 15 seconds. Every stream sends ready first. On a valid resume, ready keeps the supplied cursor, retained replay then advances it, and live events follow without an attachment gap.

Expired, unknown, previous-instance or changed-filter cursors return `409 event_cursor_expired` before HTTP 200.

Each event/log record caches at most one complete frame for its first exact filter binding. Other bindings remain independently signed. The unchanged 2 MiB retained-ring budget reserves payload storage, one possible cached frame and its cache cell before publication.

Near-maximum payloads can therefore expire earlier than the count limit. This ring budget is not a process-wide memory ceiling for queued or HTTP-held references.

A fresh stream's ready cursor is an opaque checkpoint, not a retained event record. A newly issued checkpoint remains resumable when older history has already expired. It does not revive an evicted record cursor or survive loss of a newer event.

Age, filter, instance and recording-reset checks still apply. Compare delivery/replay positions, not cursor bytes.

Published events are `stream.ready`, `runtime.updated`, `flow.updated`, `flow.gap`, `generation.changed` and `operation.updated`. Operation events reflect actual admitted work, not only reloads. Generation events originate at accepted publication, not request receipt.

Events contain bounded safe IDs/state, not packet bodies or raw configuration. Flow/event retention is memory-only, not a durable log.

`flow.updated` is an invalidation hint: fetch its `href` for the latest retained revision. Each live client queue keeps only the newest pending hint for a given flow, appended at its new sequence position. Revisions may jump, but delivered cursors remain ordered.

Publication is immediate, including terminal updates, with no batching timer. While event capture is active, the replay ring records every published notification, and replay is not coalesced. Other event kinds and logs are never coalesced.

Distinct-flow or other nonreplaceable events still disconnect a full live queue. Flow data, revisions and captured trace steps are unchanged.

Event capture is active while a client is attached or a permitted recorder is explicitly pinned on. An idle hub still admits new streams. Stopping capture invalidates earlier event cursors.

`flow.gap` with `reason=recording_changed` marks lost continuity across manual or automatic recording transitions when events are active. It does not count packet loss or uncaptured flows. A sleeping hub does not replay its shutdown gap.

Reattachment starts a fresh boundary.

### Outbound counters and telemetry

`runtime/outbounds` retains `kind` (`builtin`, `node` or `group`) alongside `name`: names can collide across kinds, so do not key rows by name alone. Cumulative connections, bytes and errors are full 64-bit decimal strings. Active connections are safe JSON integers.

Counters share the engine's existing statistics lifetime and survive reload, rather than resetting with a dashboard or listener request.

Traffic and memory histories use the existing one-second sampler with missed ticks skipped, not a task per client. Each enabled ring retains at most 600 points for 600 seconds, even with no clients. Restart clears it.

`record_traffic: false` or `record_memory: false` disables the corresponding history capability and releases its buffer on restart, without disabling current observations. History selects actual samples in the requested window. If thinning is needed, it uses the smallest stride that fits `max_points`, anchored at the newest sample, and returns oldest first.

`sampled_every_seconds` describes that nominal stride, not a promise of evenly spaced timestamps: gaps and nulls remain, with no interpolation or zero filling.

`process.cpu_percent` in `/runtime` is the process CPU-time delta (`CLOCK_PROCESS_CPUTIME_ID`) divided by the actual elapsed sampler interval, as a percentage of one CPU. A value of 100 is one fully busy core. Multi-threaded work can exceed 100. Sampling is nominally every second. It is null until two usable samples exist, or when readings are unavailable, time/counters move backward or the wall interval is zero.

RSS comes from `/proc/self/status`. Cgroup-v2 membership and mount discovery select the actual `memory.current`, `memory.max` and `memory.events` files. Unreadable/unknown values are null, not zero or substituted RSS.

An unlimited `memory.max` also has a null limit. Cgroup scope is `unknown`. Process and cgroup usage overlap and must not be added together.

Capabilities list observed metrics, read once at startup before the first sample. `kernel` is null and kernel-memory accounting is not advertised.

### Accepted configuration and reload operations

The source manager requires a genuine `.dae` startup captured by the file loader. Programmatic configs and compatibility serde loaders do not provide lossless sources. Their configuration/validation/reload capabilities remain unavailable.

GET describes the accepted snapshot, not a fresh disk scan: opaque source IDs, exact-byte SHA-256 hashes, main/include kinds, write permissions and safe diagnostics. Source `path` and rule `file` retain canonical entry-directory-relative names, such as `config.d/routing.dae`. Source `absolute_path` additionally exposes the canonical absolute path.

Source hashes, configuration revision and runtime generation are distinct: accepting comments-only changes advances revision without requiring a new runtime generation. Effective group membership changes revision, but health observations do not.
Reloads refresh any previously captured dependency fingerprints; unchanged sources and fingerprints retain their configuration revision.

Admitted anonymous loopback requests read the same configuration data as bearer-authenticated requests. Accepted content includes ordinary credentials, share links and paths. Only declared native/Clash listener-secret values are masked, including duplicate and overridden declarations and occurrences elsewhere in the source.

Parser spans identify the secret values while preserving nonsecret text and line structure. Credential-bearing sources remain read-only with hashes of their original bytes. A write whose content contains a masked value, in either its raw or JSON-escaped spelling, returns `403 permission_denied`.

A value shorter than eight bytes is neither masked nor refused: it can be written into an ordinary source and is read back unmasked. The required `secrets_redacted` boolean reports whether listener-secret values were withheld. Masked content is never an editable round-trip payload.

Native settings and listener credentials cannot be changed or moved through this API. Edit them locally and restart. To make a main file editable, first place listener credentials in a dedicated read-only include locally.

With `config_write: true` and either a nonempty secret or `password_auth`, the accepted main source and all accepted includes are writable unless credential-bearing. Only accepted source IDs authorize replacement, and creation accepts only a new `.dae` path that an include pattern loads. Caller-supplied paths do not authorize arbitrary file writes.

Subscription/generated sources are not writable. Ordinary include glob ordering, entry-root confinement, duplicate/cycle rejection and no-match semantics remain unchanged. Saving does not flatten or reformat other files.

A refused configuration write names its cause in `details.reason`, merged with any other details such as `stage`. Non-object details are preserved under `value`. The `code`, `message` and HTTP status do not change.

Each response names the first failed check:

| Reason | First failed check |
| --- | --- |
| `writes_disabled` | `config_write` is off, or neither a secret nor `password_auth` is configured |
| `configuration_unavailable` | the configuration coordinator is not running |
| `listener_secret_source` | the source declares a native or Clash listener secret, or the write would make it declare one |
| `listener_secret_in_content` | the source or the written content contains a listener secret value, or in db mode a source path does |
| `listener_settings_changed` | the candidate changes `experimental.native_api`, `clash_api.secret` or, in db mode, `global.data_dir` from the running configuration |
| `credential_sources_changed` | the write, or an edit on disk since the last reload, changes the sources that declare a listener secret; reload honk and retry |
| `import_entry_changed` | the `-c` entry is not the entry of the db's active revision |
| `unsafe_path` | the store refused the target path |

Write-refusal reasons appear on these responses:

| Request or condition | Response |
| --- | --- |
| Source PUT/creation, import or revision activation | `403 permission_denied` |
| Group PATCH or node/provider write | `404 capability_not_supported` |
| Refused source write during a node/provider write | 503 |
| Store refuses a created source | `400 invalid_request` |
| Database import leaves a secret outside its field after stripping | `422 unsupported_value`, reason `listener_secret_in_content` |

Source and management admission check `writes_disabled` before `configuration_unavailable`.

Candidate guards check secret declarations, secret content, credential-source changes, then listener-setting changes. Other refusals carry no `reason`. The request log line of a refusal with a reason is written at INFO with `reason` and never with the path or content.

Native `/logs` shows that line with `reason` and `status`, while other request lines stay withheld.

A source listed by `GET /config` with `writable: false` names its first failed check in `read_only_reason`. Writable sources omit the field. The reason describes the accepted snapshot:

| Reason | Meaning |
| --- | --- |
| `writes_disabled` | Configuration writes are disabled, as above. |
| `store_blocked` | In database mode, a failed record blocks writes until the head revision is activated again. |
| `listener_secret_source` | The source declares a listener secret. |
| `listener_secret_in_content` | The source contains a listener-secret value. |

`GET /config/sources/{source_id}` omits `read_only_reason`, `writable` and `loaded_at`.

A source containing a listener-secret value remains read-only; honk keeps running. At startup and each accepted reload, including no-op reloads, honk logs one WARN per such source. This includes secret-declaring sources and applies even when configuration writes are disabled.

The warning includes the source ID and the path masked as in the listing. A secret that no source contains makes the source writable again.

Validation takes JSON `{"mode":"syntax","sources":[{"id":"candidate","content":"..."}]}`. Each source may also carry `path`. Syntax mode parses only submitted documents: IDs/paths are diagnostic labels, not filesystem authority.

Full mode overlays the first document on the configured entry file, resolves additional `.dae` paths within its authorized entry root, and checks real local dependencies. These are cached subscriptions, geodata, hosts and ECH material. A never-fetched subscription is admitted with a warning and no cached nodes. Existing same-fetch active nodes can still be rebased.

Other missing or invalid dependencies are errors. A full-mode first `path` other than the entry file, a non-`.dae` path, or a path outside the entry root returns `400 invalid_request`. Validation never fetches dependencies, creates/chmods cache directories, starts workers or publishes a generation.

A completed invalid candidate returns HTTP 200 with `valid:false` and safe diagnostics. This offline admission is not a promise that later runtime activation will succeed.

Source/dependency admission is bounded to 32 sources and 8 MiB in total, counting each dependency materialization, including repeated references. Geodata files are runtime assets the engine loads whole anyway: they are hashed for conflict detection but never count toward this budget. The independent HTTP JSON body limit remains **64 KiB**, so it is not possible to upload an 8 MiB body.

| Capability | Limit | Basis |
| --- | --- | --- |
| `config.max_bytes` | 61440 bytes | The 65536-byte request body reserves 4096 bytes for the creation envelope. This is the maximum replacement or created content per request. |
| `config_validate.max_bytes` | 8 MiB | Full validation also counts dependencies read from disk. |

`resources.config` has no `content` member. Replacement or created content exceeding `config.max_bytes` returns `413 request_too_large`. Full validation and PUT use these bounds.

Limits are errors, not silent truncation.

Full validation applies include ordering before semantic admission. Submitted documents outside the effective include tree are checked only for structure, including recovered lexer errors. Their settings and warnings do not change the effective candidate.

Their bytes and source count still share the same budget as every materialized dependency reference.

Unknown fields in PUT and validation bodies, `secrets_redacted` included, return `400 invalid_request`. PUT takes JSON `{"content":"..."}` and RFC 9110 `If-Match` over the current **disk bytes**, not the config revision or runtime generation. The resource's strong ETag is its lowercase SHA-256 hash, quoted: `If-Match: "<64 lowercase hex digits>"`.

Lists and multiple header field lines are combined. Any matching strong tag satisfies the condition, weak tags are valid syntax but never match, and `*` matches an existing resource. Well-formed nonmatching opaque tags (including hashes with different case) yield `412 stale_revision`, not a schema error.

Missing `If-Match` is 428, checked before `Content-Type` and the body. Malformed syntax or non-text values are 400. The condition is reevaluated on detected target/dependency changes. Failure returns 412. A change while the condition still holds, including `*` or a matching list, returns `409 state_conflict`.

Invalid candidates return 422 without a write or reload. Denied writes return 403.

A candidate changing a restart-required setting also returns 422 without a write or reload. Otherwise, reload would reject the change and leave the disk file ahead of the accepted hash. Each setting receives an `error` diagnostic with code `restart-required` and a message naming the setting.

This applies to source PUT, Group PATCH, node/provider edits, database import and revision activation.

`full` validation reports these rows as warnings. Change such settings in the file and restart honk. JSON-bearing requests require `Content-Type: application/json`.

The whole candidate is validated before a mode-preserving, exclusive temporary write, file sync, atomic rename and parent-directory sync. Target identity/hash and the complete dependency set are rechecked before rename.

These checks do **not** lock out arbitrary external editors: an uncoordinated change can still race between the final check and rename. Do not manually edit the same configuration while an API save is in progress. Detected conflicts are rejected rather than overwriting them.

If rename succeeds but directory sync fails, the 503 reports `written:true,durability_confirmed:false` without `Retry-After`: bytes have changed and durability is unconfirmed, not rolled back. A later reload-queue failure can likewise report `written:true`, also without `Retry-After`. An HTTP error alone does not imply that nothing was written.

`POST /api/v1/config/sources` creates one new source file. Capabilities advertise `config.create` only when `config.writable` is true. An unavailable or read-only configuration answers as for PUT, and a writable configuration whose `config.create` is false returns `404 capability_not_supported`.

The body is `{"path":"config.d/proxies.dae","content":"..."}`. `path` must meet these requirements:

- Relative to the entry directory, using only normal segments.
- Ends in `.dae`.
- At most 1024 bytes, with no control characters.
- Its parent stays inside the entry root, including through symlinks.

Otherwise the request returns `400 invalid_request`.

A path that exists on disk or names an accepted source returns `409 state_conflict` and is never overwritten. The candidate gets the same full validation, credential checks and restart-required checks as PUT, and an include pattern must load the new file. Otherwise the 422 carries a `source-not-included` error diagnostic on the main source with a null location.

The file is written through a temporary file and a no-replace rename with the entry file's mode. In database mode the new source is recorded in a new revision instead. A failed reload leaves the created file in place, because honk cannot remove it without racing other editors of that path.

Every failed creation reports `written` (`true` once the file is created) and `committed` (`false`, `true` or `null`). Size limits, `Idempotency-Key`, and the 413, 415, 429 and 503 responses match PUT.

For PUT, HTTP 202 is sent only after durable replacement and real reload queue admission. `Location` matches the returned operation `href`, with `Retry-After: 1`.  202 is not activation success. The daemon owns the admitted work across HTTP disconnects.

An optional `Idempotency-Key` binds principal, method, path and daemon instance plus the exact body bytes. Concurrent or later same-key/same-body requests share the original admission/operation, without another write, hash check or reload—even when retrying with the old hash after losing the first 202. A different body under that key is 409.

At most 32 reservations/operations are retained. Terminal operations remain for up to 300 seconds. When the store is full, a new admission evicts the oldest terminal operation, whose ID then returns 404.

Its `Idempotency-Key` still replays the original 202, or returns 409 for a different body, until 300 seconds after the operation finished. At most 1024 evicted keys are kept (`resources.operations.max_replay_keys`), and past that the oldest is forgotten. Only when every slot holds a preparing or running operation does admission return `503 temporarily_unavailable` with `Retry-After: 1`.

Restart clears this process-local replay state.

The same coordinator serializes API writes/reloads and SIGHUP **before reading/parsing files**, then uses the real runtime reload and subscription reconciliation. Rejected activation retains the previous accepted snapshot/generation, but already-written bytes remain on disk. A committed-but-degraded result retains the new snapshot/generation and reports the operation as failed, with commit information.

There is no automatic file rollback. Repair the disk configuration and explicitly reload when needed. When files on disk fail to load, the failed operation and `last_reload` carry the same details:

- An `unsupported_value` error.
- The `details.diagnostics` that a write of that content returns, naming accepted source IDs and lines.
- `committed:false`.

When all rows would exceed the 4 KiB operation error details, only the error rows are kept. Every failed reload, source write and node/provider write reports `error.details.committed` (`false`, `true` or `null`). A plain reload's details omit `written`, which writes carry instead.

GET operation, `runtime.last_reload` and `operation.updated` expose actual API reload outcomes. SIGHUP itself does not create a synthetic operation or populate `last_reload`. A no-op may accept changed source text without a new runtime generation.

Operations also serve probes, provider refresh and group updates. Probes and provider refresh do not require source-management capability. Native suspend and resume remain unavailable with `404 capability_not_supported`.

When a configured secret or password login protects the listener, all sessions use the same administrator operation principal and logout does not remove retained operations.

### Configuration db (`--store db`)

`honk-core --store db` keeps the administered `.dae` sources as revisions in the state db, `<data_dir>/state/honk.db`. `data_dir` is `--data-dir` (default `/var/lib/honk`) and must equal `global.data_dir`. There is no working-directory fallback.

The `state` directory is 0700 and the file 0600, both owned by the daemon user and neither a symlink. At startup or `honk-core admin reset`, if either is owned by the daemon user and has only extra group or other read or execute bits, honk removes those bits with a warning. Anything else, including group- or other-writable modes, is refused.

`config export` and other offline reads refuse any mode other than 0700 and 0600 and never change permissions. The db uses WAL, so `honk.db-wal` and `honk.db-shm` sit beside it with the same mode. On a filesystem that cannot hold WAL, for example one without shared memory, it falls back to a rollback journal (`honk.db-journal`) with a warning.

Of the configuration, only `.dae` sources move into the db. Subscription bodies are there in both modes. Hosts, ECH and geodata stay on disk and resolve against `data_dir`.

The directory of the imported tree authorizes nothing.

With an empty db, startup imports `-c`. It needs `native_api.enabled`, `config_write` and a credential. It strips every `native_api` and `clash_api` `secret:`, checks that the stripped tree with the secrets re-applied parses to the same configuration, and records revision 1 with principal `startup`.

A secret value that survives stripping, for example in a comment or a file name, refuses the import. With a revision present, startup runs the active revision and does not read `-c`. It refuses to continue if another instance moved `head` during startup, which only a mock-mode instance, holding no instance lock, can do.

Db mode runs without the Clash API: a non-empty `experimental.clash_api.external_controller` refuses startup, both in an imported tree and in the active revision. A corrupt db, a foreign `application_id` or a newer schema refuses startup. The db is never renamed or recreated.
Startup and API re-import compare configured values after restoring stripped credentials and reconciling parser-generated group/provider IDs and parse timestamps. Derived node identities, endpoints, group definitions and subscription fetch settings still participate in the strict comparison.

Listener secrets are stored apart from the revisions and never returned. Writes cannot change them, `native_api` settings or `global.data_dir` (403), and a source that contains a stored secret value is refused. Responses and the `--without-secrets` export mask both stored values.

In db mode source `absolute_path` is omitted, source paths are labels rather than files, and `If-Match` covers the stored source bytes.

A write is activated first and recorded after. The revision row and `head` move only once activation commits, including degraded and reconciliation-failed commits. A rejected activation adds no row and reports `written:false`.

If recording fails, the operation fails with code `store_unavailable` and `details {committed:true,written:false,active_generation_id}`. If the engine stops before confirming activation, the operation code is `activation_unconfirmed` with `details {committed:null}`. After either, `store.recorded` is false, capabilities report the config as not writable, the export filename carries no revision, and writes return `503 temporarily_unavailable` with `details.stage:"store"`.

Activating the `head` revision re-activates it without a new row and clears the state. So does a restart, which runs `head`. Retention keeps at most 50 revisions and 16 MiB of stored JSON, pruning the oldest first and never the active one.

JSON escaping can make a revision larger than its sources, and a revision whose JSON alone exceeds 16 MiB is refused.

Between publishing new accepted sources and completing their durable record, `store.recorded` is false and export uses `honk.dae`. `revision` and `parent` still describe the durable head. Reads of unchanged old accepted sources can remain recorded.

The coordinator awaits blocking SQLite promotion before finishing the operation, processing its next mutation or acknowledging shutdown.

These routes and fields are honk extensions, so they live under `x-honk` (contract: Engine extensions). `GET /config` carries `x-honk.store {kind, revision, parent, recorded}`, where `kind` is `file` or `db`. Capabilities add `config.x-honk.store` and `resources.x-honk` entries `config_export {available}`, `config_import {available, replace_required}` and `config_revisions {available, can_activate, max_revisions}`.

Admitted discovery links them in `links.x-honk`. The paths below are under `/api/v1/x-honk`.

- `GET /config/export` returns the accepted sources as one inlined document: `text/plain; charset=utf-8`, `Content-Disposition: attachment; filename="honk-r<n>.dae"` (`honk.dae` in file mode), a strong `ETag` over the body and `Cache-Control: no-store`. Listener secrets are left out, and when any were the body starts with `# listener secrets omitted`. Add them back before running it. Available in both modes.
- `POST /config/import` (db mode, writable) takes strict JSON `{"replace":bool}` and a required `Idempotency-Key`. It re-reads the `-c` tree and records it through a reload operation as a new revision with origin `import`. Startup always records revision 1, so `replace:true` is required and anything else returns `409 state_conflict`. A secret copy that survives stripping returns `422 unsupported_value`. The tree must keep the entry path, listener secrets, `native_api` settings and `data_dir`. Otherwise 403.
- `GET /config/revisions` (db mode) returns `{active, max_revisions, revisions:[{revision, parent, created_at, principal, origin, content_sha256, bytes, sources:[{path, sha256}]}]}`, newest first and without content. `active` and rows share one database snapshot.  `parent` becomes null if retention removes that parent revision.
- `POST /config/revisions/{n}/activate` (db mode, writable) takes an empty body or `{}` and an optional `Idempotency-Key`. It validates revision `n`, activates it and records it as a new revision with origin `activate`. Activating the active revision is a no-op unless `store.recorded` is false. An unknown `n` returns `404 resource_not_found`.

In file mode, import and the revision routes return `404 capability_not_supported`.

To return to file mode:

1. Run `honk-core config export --out /etc/honk/config.dae`.
2. Restart without `--store db`.

A later database-mode start resumes from `head`. File edits reach the database only through import with `replace:true`.

To recover from a damaged database:

1. Run `honk-core config export --out exported.dae`. Export checks only the application ID and schema version, so it may still read a damaged file.
2. Stop honk.
3. Move the whole directory aside with `mv <data_dir>/state <data_dir>/state.bad`, keeping `honk.db-wal` with the main file.
4. Start with `--store db -c exported.dae`.

### Bounded probes

`POST /probes` requires JSON, for example `{"target":{"type":"node","node_id":"<id>"},"kind":"http","transport":["tcp"],"ip_version":"ipv4","warmth":"cold"}`.

| Field | Values |
| --- | --- |
| Node target | `{"type":"node","node_id":"<id>"}`; rejects `members` |
| Group target | `{"type":"group","group_id":"<id>"}` |
| Group `members` | `"direct"` (default), `"leaves"`, or a nonempty list of direct-member IDs |
| `kind` | `tcp_connect` and `http`: data probes over TCP only. `dns`: DNS probes over TCP, UDP or both. |
| `ip_version` | `ipv4`, `ipv6`, `any` |
| `warmth` | `cold`, `warm` |

The purpose follows from `kind`; it is not sent in the request.

Targets come only from accepted configuration:

| Probe | Target |
| --- | --- |
| Raw TCP | Node’s configured server endpoint |
| HTTP | Configured check URL |
| DNS | Configured check target, with real UDP or framed TCP exchanges |

There is no caller URL or redirect following. Probes apply no address or port policy checks to configured targets or node servers.

IPv4-mapped IPv6 is normalized, and the selected IP is pinned while HTTP Host/TLS SNI retains the configured name. Private/loopback addresses and nondefault configured ports need no allowlist entries. Probes, geodata and shared downloads use configured targets without an address or port allowlist.

Whoever can write the configuration or control subscription content decides those targets. Provider content is trusted configuration. Raw TCP permits only the actual configured node port, not an arbitrary caller port.

| Probe budget | Limit |
| --- | --- |
| Member associations per job | 64 |
| Projected rows per job | 256 |
| Active jobs | 4 |
| Queued jobs | 16 |
| Jobs per target | 1 |
| Preparation, queueing and measurement | One 30-second deadline |
| Requests per minute, per resource | 30 for the sole principal and globally |

Final transport-owner cleanup remains joined after the deadline, so total operation time can exceed 30 seconds. Rate rejection returns `429 rate_limited`; capacity rejection returns 503. Both include `Retry-After`.

Admission returns 202 with a `queued` operation at once, even while four jobs are active. A job that ends before measurement fails with `probe_cancelled`, `probe_deadline`, `unsupported_value` (local resolution is refused, or the node cannot carry UDP to the probe port) or `engine_unavailable`. Optional `Idempotency-Key` replays retained admission.

Results preserve member-to-leaf associations even when execution is deduplicated, actual measurement/family/warmth, and whether current-generation health accepted the result. Raw TCP latency is not HTTP ranking evidence. Cancelled, unavailable and obsolete work does not become a fake unhealthy sample.

Selection observations do not advance policy state. If final cleanup fails, the operation fails with `probe_cleanup_failed`: `result` stays null and the completed measurements are in `error.details`.

A child group among the direct members is probed through one selected leaf. Selection can expand descendants; the planner rejects graphs above 256 entries. A Selector without subgroups or `final` is exempt from that planner limit.

The target group still has the 64-member and 256-row limits. To probe larger groups in batches, send `members` as a list of at most 64 IDs. `members: "leaves"` additionally rejects a whole-group graph above 256 entries.

### DNS query, cache and outcome history

`POST /dns/query` requires a strict JSON body with `Content-Type: application/json`; other media types return 415.

| Field | Location | Requirement or default |
| --- | --- | --- |
| `domain` | Body | Required |
| `type` | Body | Optional array of up to eight distinct record types; default `["A"]`. More types return `413 request_too_large`. |
| `cache_mode` | Body | `normal` or `bypass` |
| `upstream` | Body | Configured upstream name, including an otherwise unreferenced upstream |
| `detail` | Query string | `summary` or `full` |

Supported types are A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, SVCB, HTTPS and CAA.

All types share one generation and a ten-second deadline. The rate ceiling is 30 requests/minute for the sole principal and globally.

A forced upstream replaces request-stage routing, not hosts/strategy precedence or response policy. A local-host answer still reports the default route and no upstream.

`bypass` does none of the following:

- Read or write positive, negative or stale cache entries.
- Join a writing singleflight.
- Supersede entries or start refresh work.

Full detail projects validated answer records. Per-type timeouts, refusals and errors remain actual outcomes.
DNS query/cache responses and DNS log pages mask listener-secret display values without changing opaque IDs or cursor bindings.

Literal `.` names the DNS root and works for live queries, exact cache listing and name-based deletion. Ordinary input names are case-insensitive with an optional trailing dot. Presented names retain their canonical trailing dot.

Valid root wire questions also use the ordinary strict DNS path. Non-UTF-8 labels remain outside that consumer contract.

`GET /dns/cache` accepts `name`, `domain`, repeated `type`, `include_expired=false|true`, `detail`, `limit` (1–1000, default 100) and `cursor`. Reads neither promote LRU nor count hits. Up to eight immutable filter/instance-bound snapshots live for 30 seconds within an aggregate 8 MiB wire/metadata budget.

Exhausted capacity returns `503 snapshot_unavailable` rather than clipping. An unrecognised cache cursor returns `410 snapshot_expired`. A recognised cursor sent with different filters or a different `limit` returns `400 invalid_request`.

Coverage is the runtime cache (`persistent:false`), not a SQLite inventory. Opaque `entry_id` identifies an exact cache incarnation, not merely a name/type.

Name/type/expiry selection happens before snapshot byte admission and cloning. Unselected cache entries do not consume the requested snapshot's budget. Negative-answer precedence and expiry selection use one observation instant.

Every page also carries `usage {entries, entry_capacity}` for the whole runtime cache at snapshot time, ignoring the filters. `entry_capacity` is `max_cache_size` after clamping to 1–100,000. Both values are decimal strings, taken while every shard is locked, and later pages of one snapshot repeat them.

Eviction is per shard, so one hot shard can evict while the totals still show headroom. `usage.entries` also counts expired and non-exact slots that `total` excludes.

`DELETE /dns/cache/{entry_id}` takes no body/query and returns `{deleted}`. `DELETE /dns/cache?name=...&type=A` takes no body and returns `{matched,deleted}` (omit types to select all types for that name). `POST /dns/cache/flush` accepts an empty body or JSON `{}` and returns `{matched,deleted}`.

The common cache owner fences old foreground/refresh publications and queued persistent puts, then waits for persistence deletion acknowledgement. Old work cannot resurrect invalidated entries after success. Persistence errors propagate instead of reporting a successful flush.

Routing/domain maps are not cleared.

`GET /dns/log` records completed ordinary client DNS outcomes once, including known client socket/ingress and parseable refusals/errors. Native/Clash diagnostics and background refresh duplicates are excluded. `record_dns_log` defaults true and permits recording while its independent DNS-log demand is active, retaining at most 512 records and 8 MiB.

An explicit runtime `record_dns_log: "on"` keeps recording enabled without clients. Configuration false prohibits it until changed and restarted. When effective recording stops, history is released and its cursors become invalid.

Eviction removes whole oldest records. Pages are newest first with `name`, `type`, `src`, `limit` (1–500, default 100) and filter-bound `cursor`. Eviction or shrink invalidates affected cursors.

An unrecognised log cursor returns `410 snapshot_expired`. A recognised cursor sent with different filters or a different `limit` returns `400 invalid_request`. Query/cache/log JSON responses are capped at 262144 bytes.

A cache or log page ends before the first entry that would exceed the cap and returns `next_cursor`. Thus `limit` is a maximum, not a promised count.

An entry exceeding the cap by itself occupies one complete page, without clipping. Its 65535-byte wire limit bounds the expansion; refusing the entry would make every following entry inaccessible.

A query response over the cap returns 503 with `Retry-After`, never a silently clipped RRset.

### Routing simulation and rule locations

Admitted anonymous loopback requests have the same rule reads and routing simulation as bearer-authenticated requests. `POST /routing/trace` takes `{"input":{"network":"tcp","domain":"example.com","dst_port":443},"resolve":"none"}`. Input requires TCP/UDP, a nonzero destination port and at least one of `domain`/`dst_ip`.

Optional source IP/port, `pname`, DSCP (0–63) and `mark` are accepted. It evaluates immutable current policy with three-valued conditions. Missing evidence remains unknown.

It does not resolve DNS, dial, probe or mutate group selection. `resolve` defaults to `none`. `live` requires a domain and no `dst_ip`.

Violating that shape returns 400, while a well-shaped live request returns 422 because live resolution is unsupported. Content-Type, JSON/schema, input and resolve checks precede rate admission. Rejected validation consumes no trace-rate slot.

Limits are one address, 256 rule/condition steps, five seconds and 30 requests/minute for the sole principal and globally.

The response is a `simulation` pinned to one `instance_id` and `generation_id`, not historical flow evidence. `/rules` returns the complete dictionary including fallback, never truncated. `max_rules` is 4096 or the running dictionary size if larger, and `dns_rules.max_rules` likewise covers the larger DNS list.

The fallback entry's `expression` is its source statement, such as `fallback: proxy`, or `fallback: <outbound>` when none is retained. Trace evaluations use `fallback: <outbound>`. If either read cannot pin the router within its deadline, it returns `503 snapshot_unavailable` with `Retry-After`.

Its rule IDs use the same generation-scoped identity as trace and captured userspace flow evidence. Where accepted parser spans exist, source locations contain opaque `source_id`, one-based `line`/`column` and `file` matching that source's entry-relative `path`. Otherwise source is null.

An editor must use that source ID and its content permission, never derive a filesystem path from the display label. Edit rules through source PUT, not PATCH `/rules`.

For accepted `.dae` rules, `/rules` and `/routing/trace` rule `expression` retain the authored condition values, including geosite/geoip names, negation and quoted arguments. This includes rules in credential-bearing sources. Comments and the outbound clause are removed.

Trace condition expressions show configured values as unquoted dae text, in actual compiled predicate order. Ordinary domain alternatives and geosite in one `domain(...)` call form one union condition. Negation applies to the whole union.

Destination IP and geoip alternatives likewise share one condition. Listener-secret values remain masked. Ordinary condition text is visible without write permission.

Rules without accepted source metadata expose compiled condition values with null source provenance. Compiled displays reflect normalized predicates, not exact authored syntax or expanded geodata. Trace pins display metadata and decisions to the same accepted generation.

Disk edits do not change either response until a reload is accepted. Rejected reloads retain the previous expressions. Historical flows retain the bounded compiled values captured with their own generation, including programmatic-router values.

### DNS routing rules

`GET /dns/rules` returns the `dns { routing { … } }` rules of the running generation as `{generation_id, request, response}`. It is read-only. Edit DNS rules through source PUT, as with `/rules`.

Each list is in evaluation order and ends with exactly one `kind: "fallback"` entry. Entries carry `rule_id`, zero-based `index`, `expression`, `action`, `upstream`, `source` and `kind`. Request actions are `upstream`, `asis` and `reject`.

Response actions are `accept`, `reject` and `requery`. `upstream` is the name the engine uses for `upstream` and `requery`, lowercased, and null for the other actions. `expression` is the whole statement as written, action included and trailing comment removed, such as `qname(suffix: example.com) -> AliDNS` or `fallback: googledns`.

A fallback the configuration does not write still appears with the engine default (`upstream` `default` for requests, `accept` for responses), expression `fallback: <action>` and null `source`. Rules the parser omits with a warning are not listed.

`rule_id` is `{instance}:{generation}:dns_request:rule:{index}`, `{instance}:{generation}:dns_request:fallback`, or the same forms with `dns_response`. It is unique across both lists and changes with the generation, so address a rule by `generation_id` and `rule_id` together.

`source` has the same shape as in `/rules`:

| Field | Meaning |
| --- | --- |
| `source_id` | Opaque source identifier |
| `file` | Display value matching that source’s entry-relative `path` |
| `line` | One-based line where the statement starts in that source |
| `column` | One-based byte column where the statement starts in that source |

Rules without accepted source metadata have null `source` and an expression rendered from the parsed conditions. Both lists are returned whole, including fallback. `resources.dns_rules.max_rules` is at least 4096 and at least the larger running list size.

A read that cannot pin the running configuration within five seconds returns `503 snapshot_unavailable` with `Retry-After`. Disk edits change the response only after a reload is accepted.

### Provider observations and refresh

Admitted anonymous loopback requests read the same provider data as bearer-authenticated requests. Provider GETs do no networking. List accepts `limit` (1–1000, default 100) and `cursor`, with eight 30-second snapshots and 4 MiB aggregate retention.

A list that cannot fit returns `503 snapshot_unavailable` with `Retry-After`. An unrecognised provider cursor returns `410 snapshot_expired`. A recognised cursor sent with different filters or a different `limit` returns `400 invalid_request`.

IDs join accepted `Node.provider_id`. Subscriptions return their configured names and full URLs in `url_redacted`. The field name remains for compatibility.

GET and successful operation results use the same representation. `traffic` and `expires_at` come from the provider's `subscription-userinfo` header and are null without it. A configured name matching the former `provider-<id>` label is an ordinary name, never an ID alias.

Their status comes from the subscription owner: `ok` requires a successful usable publication. Cached, pending, never-loaded, disabled or failed-with-retained-nodes providers are `stale`. `error` requires a real failure with no nodes.

Never-loaded or disabled-without-cache rows have zero nodes and null update/error, not synthetic failures.

Subscription rows carry `download`, derived from `download_detour` and shaped like the geodata route:

| Field | Meaning |
| --- | --- |
| `route` | `routing`, `direct` or `group` |
| `group_id` | The group's `GET /groups` ID; null for other routes or a group that no longer exists |

File and inline rows report null for `download`.

A failed fetch reports `last_error.code` `fetch_failed`, or `route_unavailable` when the subscription's download route has no usable node yet. See the [subscription reference](./subscription.md#fetch-persistence-and-recovery). A publication that configuration validation rejects, such as a node that duplicates a static node, reports `publication_rejected` with the diagnostic in `details.diagnostic_code` (for example `duplicate-node-id`).

A failed refresh operation carries the same details.

`POST /providers/{id}/refresh` takes an empty body and optional `Idempotency-Key`, returning a 202 operation. Success requires actual revision-authorized runtime publication, not just fetch or cache write. Disconnecting HTTP does not cancel admitted work.

A distinct concurrent refresh for the same provider conflicts (409), while retained same-key replay returns the original operation first. Disabled providers, or a runtime without a subscription owner (`can_refresh: false`), return `404 capability_not_supported`. Stopped/capacity-limited owners return 503.

The virtual `inline` provider is not refreshable or deletable. It groups static non-builtin nodes, whose `provider_id` is `inline`. Builtins retain null provider ownership.

Subscription IDs remain UUIDs.

### Managed entries and geodata

`POST /api/v1/nodes` accepts a link of 1–8192 characters. A longer declaration (for example XHTTP `extra` near its 16 KiB header bound) belongs in a configuration source edit. A link the engine rejects returns `422 unsupported_value` with the parser's static reason as `error.message`, such as `XHTTP xPaddingBytes must stay within 1-8192`, and `details.fields: ["name","link"]`.

Submitted names, links and option values are never echoed, and nothing is written. `POST /api/v1/providers` reports a rejected subscription entry the same way. Other refusals keep the generic message.

`resources.nodes.can_manage` and `resources.providers.can_manage` require a running source coordinator and a writable, non-credential-bearing accepted **main** source. Node creation accepts `{"name":"edge","link":"socks5://192.0.2.2:1080"}`. Provider creation accepts `{"name":"feed","kind":"subscription","url":"https://example.net/sub"}`.

`resources.providers.create_options` lists the effective defaults for omitted provider fields:

| Field | Constraint | Built-in default |
| --- | --- | --- |
| `update_interval` | Seconds, at most one year; `0` means refresh only on request | `86400` |
| `user_agent` | 1–256 printable ASCII characters | `honk/<version>` |
| `cache` | Available only when `global.store_subscribe` opened a subscription store | `true` |

Where `assets.subscription` sets a default, `create_options` returns that value instead of the built-in fallback.

`resources.providers` also advertises `create_unfetched: true` for this creation path. A provider with any explicit option is written as `tag: 'url' { ... }`, with `ua`, `interval` and `cache` on separate lines. A schema length, pattern, kind, interval or user-agent bound violation returns `400 invalid_request`.

An unadvertised option (such as `cache` without its store) returns `422 unsupported_value`. Strict JSON and the 64 KiB body limit remain. The engine parser and full offline admission precede the existing FD-relative durable replacement and real reload.

`201` with the live Node/Provider and its `Location` is returned only after activation and subscription reconciliation. HTTP disconnect does not cancel queued work. With `--store db`, these actions record a new revision instead of rewriting the main file.

Node names are 1–64 characters and links at most 8192 characters. Provider names are 1–64 ASCII letters/digits/`_.-`, with an HTTP(S) URL of at most 4096 characters. Schema length/pattern/enum/bound violations return `400 invalid_request`.

Duplicate names return 409. Structurally valid but unsupported links, identities, provider URL schemes or options return 422. New providers start with zero nodes, stale status and no update time, even if an old cached body exists.

Their exact source specification remains deferred through unrelated edits and reload until explicit refresh. Changing that specification or restarting restores ordinary subscription startup behavior. Same-fetch provider aliases cannot be created through this API, and ambiguous alias deletion is refused rather than transferring IDs or nodes.

DELETE takes no body or query. Sending one returns `400 invalid_request`, and a body over the limit returns `413 request_too_large`, both without `Retry-After`. Unknown IDs return `{"deleted":0}` without a write.

Successful removal returns `{"deleted":1}` only after activation. Builtins, subscription-derived nodes, declarations outside the main source and unsupported/ambiguous ownership return `404 capability_not_supported`. Static includes remain visible under `inline`.

The fixed client contract has no per-node writable flag, so a displayed removal action may still be refused. Deleting a node that a group names as its `final` returns `409 state_conflict` with those group IDs in `details.groups`. Other still-referenced entries fail validation before writing.

A main source changed on disk after it was read returns `409 state_conflict`. Editing existing entries remains a source PUT. There is no node/provider PATCH endpoint.

These synchronous actions serialize with source PUT, Group PATCH and SIGHUP. They fence accepted revision, disk bytes and dependencies, but do not lock out arbitrary external editors. Safe failure details include `stage` (these synchronous writes always carry it), `written`, `durability_confirmed` (present only when `written` is true) and `committed`.

Unknown completion is null, not false. Lifecycle and operational failures use 503 with Retry-After. POST name conflicts use 409, and a source changed on disk during the write returns `409 state_conflict`, since the request carries no precondition.

DELETE still maps other validation failures to 503. A durable write followed by rejected activation reports written true/committed false. With `--store db` nothing is written before activation, so rejection reports written false.

Committed degradation reports committed true with `active_generation_id` set, null when unknown. No rollback is promised. Source PUT retains its independent disk-hash If-Match contract, so a stale editor conflicts after a managed mutation.

Admitted anonymous loopback requests read the same geodata as bearer-authenticated requests. Geodata GET joins retained traffic/DNS metadata under the existing router-before-config publication order. It never scans disk or downloads.

Hash and size describe loaded bytes, not later disk edits. Unrecorded or differing modification times are null.

`source_redacted` keeps its compatibility field name. GET and successful operation results show the first download URL with these protections:

- Remove userinfo, query and fragment.
- Replace each potentially credential-bearing path segment with `[redacted]`.
- Mask listener-secret values.

It is null for an asset without URLs or a URL that cannot be shown safely. Unused assets are absent. Incompatible loaded snapshots are unavailable rather than arbitrarily selected.

Updates require `config_write`, source authority and download URLs for every loaded asset. URLs come from the configuration file’s `assets.geodata.geosite`/`assets.geodata.geoip`. When sources are configurable, they come from the stored or built-in URLs described below. URLs are never request parameters. Only direct final HTTP(S) URLs are accepted: no userinfo, fragments, redirects or content encoding.

HTTPS verifies certificates. A direct request resolves a non-literal host only with the configured numeric `global.bootstrap_resolver`, without system-DNS fallback. To match routing rules, `routing` first looks up the host with that resolver. If it is unset or fails, lookup uses `/etc/hosts` and the system nameserver.

Requests take the download route described below, `routing` by default. One update owns at most two 256 MiB assets. Each URL's file must return headers within 30 seconds of the request.

No pause in its body may last 30 seconds, and the whole download is capped at 10 minutes. Its checksum request has a separate 10-second deadline, starting once the file arrives. This covers the whole request, including route decision, resolution, tunnel and TLS setup. Validation, filesystem work and mandatory joins are not a hard total-time guarantee.

All downloads are parsed and the full candidate compiled before any replacement. A file that lacks a category the active configuration uses fails with `asset_validation_failed` and leaves the loaded file in place. A loaded file in `global.data_dir` or `$DAE_LOCATION_ASSET` is replaced where it is.

Updates never overwrite files loaded from lower-priority locations, such as a package's `/usr/share/honk`. Instead, they create `global.data_dir/<file>`, which takes precedence in later lookups. If another file appears there meanwhile, replacement is refused.

Files are opened through no-symlink parent/file descriptors. Aliases, changed bytes, source/dependency conflicts and unsafe paths reject the work.

Parent-component spellings are normalized only after the safe open for identity comparison. Replacements are individually atomic and durable, **not a multi-file transaction**. An error after the first rename retains per-asset written/durability facts and does not undo the replacement. The normal reload receives the immutable verified geo snapshot in both no-op and rebuild paths, so later disk changes cannot substitute different activation bytes.

Results are actual published GeoData. Rejected/degraded activation remains failure with commit information. Repair conflicting disk state before retrying.
Cached subscriptions remain dependencies of this admission, but their fingerprints name database rows rather than filesystem paths. Geodata updates fence those row bytes with the final pre-rename recapture. Only real file dependencies acquire inode guards.

`POST /geodata/update` has no body. Same-key replay returns the retained operation before checking exclusivity. A distinct in-flight update conflicts, and operation capacity returns 503.

`202` means daemon ownership, not that files or routing changed. An asset whose downloaded bytes equal the loaded file is not written. When every asset is identical the update succeeds without activation, a generation event or a change to `runtime.last_reload`.

An update that reaches activation sets `runtime.last_reload`. A failure before activation leaves it unchanged.

### Geodata sources and automatic updates

With a state db and an initialized geodata owner, `resources.geodata.configurable_sources` is true and `runtime_settings.fields` lists `geodata`. The capability then also reports `max_urls: 4`, `interval_hours: {min: 6, max: 168, default: 24}` and `lifecycle: {file_values: start, overrides_persist: true}`: file values are taken at startup only, and a patch lasts across restarts. `checksum` is `sha256sum` with or without a state db.

The native API tries to open `<data_dir>/state/honk.db` whenever it is enabled. A failed open aborts startup in db mode, with `password_auth`, for a foreign application ID or newer schema, or when another honk instance holds the database. Other failures may continue without persistence.

When it opens, the settings live in its strict `geodata_settings` row and survive restarts and activations. If that row cannot be opened the listener still starts, logs a warning and advertises no geodata capability. Without a state db or geodata owner, only the configuration file's URLs apply and none of the fields below appear.

`GET /runtime/settings` then carries `geodata`: `source`, `geosite.urls`, `geoip.urls`, `auto_update` (`enabled`, `interval_hours`), `download` (`route`, `group_id`) and `verify_checksum`. The stored settings are the only ones in force. At startup, when `assets.geodata` names a download URL, honk writes it into the stored settings over a patched one.

If the file names no URL for an asset, a URL list from an earlier file is deleted and built-in URLs apply. A patched list is kept. Configuration download URLs and routes are startup-owned. A reload that changes their effective values is rejected as restart-required, so other activations never touch the stored settings and a patch lasts until the next startup.

| `source` | Meaning |
| --- | --- |
| `config` | Every stored list came from the configuration file. |
| `override` | At least one stored list came from a URL patch. |
| `default` | No list is stored. Built-in MetaCubeX `meta-rules-dat` release files apply, from raw.githubusercontent.com first and fastly.jsdelivr.net second. |

Automatic updates are on by default, with a 24-hour interval.

`download.route` selects the route for every geodata request, including checksums: `routing`, the default, follows the routing rules like user traffic. `group` forces the group in `group_id`, the ID `GET /groups` reports. `direct` dials the host over the bypass mark with the bootstrap resolver.

Routed and group requests use the external UI download's route decision and tunnel. An unusable route fails that URL like a connection error:

| `last_error.code` | Condition |
| --- | --- |
| `group_unavailable` | Group absent or without a selectable member |
| `route_blocked` | Routing rules select `block` |
| `connection_failed` | Tunnel cannot be opened |

honk tries the next URL and never falls back to direct.

This also applies just after startup when the group selected by the route or rules has no reachable node. Through a node, a hostname is resolved at the node's egress. At startup, `assets.geodata.route` overrides `assets.route` and writes its effective route into the stored settings over an API patch.

Without a file route, a patched route is retained. Otherwise the route follows routing and a previous file route is removed. The route does not affect `source`.

See the [assets reference](./assets.md).

`PATCH /runtime/settings` merges `geodata` and stores it without downloading. A `urls` list has 1–4 distinct HTTP(S) URLs of at most 4096 bytes, without userinfo or fragment, and replaces the whole list in fallback order. Patching one asset stores only that list, so `source` becomes `override`, whatever it was, and the other asset keeps following the file or the built-in URLs.

`auto_update` is stored on its own, with `interval_hours` from 6 to 168, and the file never sets it. `download` is stored on its own. `group_id` is required for `group` and refused otherwise, and an id that is not a current group returns `409 state_conflict`.

A stored group that a later activation removes reads `group_id: null`, and its downloads fail with `group_unavailable` until the route changes. `verify_checksum` is stored on its own, and the file never sets it. `"geodata": null` deletes the stored row.

The file's URLs are written again at the next startup. The top-level `source` is unaffected. A geodata patch with other fields is validated as one request, and validation failures leave everything unchanged.

The anonymous loopback principal cannot patch `geodata` (`403 permission_denied`). Every admitted caller reads the URLs as written, with listener secrets masked.
If shutdown prevents recorder settings from landing after geodata was stored, PATCH returns `503 temporarily_unavailable` with `details.geodata_stored: true`; the stored geodata is not rolled back.

An update tries each asset's URLs in order. It advances to the next URL after a connection error, non-200 file response, deadline expiry or checksum failure.

The checksum URL appends `.sha256sum` to the file URL's path and preserves its query:

| Checksum response | Result |
| --- | --- |
| 200 | The first token must equal the file's SHA-256. |
| 404 | No published checksum; use the file unverified. |
| Other status or failure | Reject that URL. |

If every URL fails, the details describe the last attempted URL:

| Field | Meaning |
| --- | --- |
| `stage` | Failed stage |
| `asset` | `geosite` or `geoip` |
| `http_status` | Present for a rejected reply: a file status other than 200, or a checksum status other than 200/404 |

`asset: geoip, stage: checksum_unavailable, http_status: 403` means the server refused the `.sha256sum`, not the file.

Configured, stored and built-in geodata URLs, including their checksum requests, have no address or port allowlist.

`verify_checksum` is `true` by default. Set to `false`, manual and automatic updates request no `.sha256sum` and use every downloaded file unverified: `verified` is `false` and `sha256` is still reported. It is for mirrors that answer a missing checksum with a status other than 404 or with a page that is not a checksum.

A failure with `checksum_unavailable` or `checksum_mismatch` logs a warning that names this setting. Nothing turns the check off automatically.

`GET /geodata` also reports these fields:

| Scope | Field | Meaning |
| --- | --- | --- |
| Per asset | `fetched_url_redacted` | URL of the loaded file's download, displayed like `source_redacted` |
| Per asset | `verified` | Whether the download was verified |
| Per asset | `download_route.route` | Route setting used for that download |
| Per asset | `download_route.group_id` | Group traversed by the request, including one chosen by rules; otherwise null |
| Top level | `last_checked_at`, `last_updated_at`, `next_check_at`, `last_error` | Update status and schedule |
| Top level | `required_codes` | Sorted categories referenced by the active configuration for each loaded asset |

`last_error.code` identifies the failed stage, such as `http_status_rejected`, `checksum_mismatch` or `asset_validation_failed`.

`last_checked_at`, `last_updated_at`, `last_error` and the consecutive failure count persist in the state database's strict `geodata_status` row. Each startup recomputes `next_check_at` from that state and draws a new random delay. It is not stored.

Per-asset fields remain in memory only. After restart they are null, and `verified` is false, until the next attempt.

Automatic updates are on by default, every 24 hours. `auto_update.enabled: false` stops them. After startup the schedule continues from the last recorded check.

The first check runs five minutes plus the random delay after startup if the previous check:

- Is older than the wait.
- Lies in the future because the clock ran ahead.
- Does not exist.

Restart therefore never downloads immediately. A host that restarts more often than the interval still updates. `POST /geodata/update` fetches immediately.

Automatic updates queue the same `geodata_update` operation. A manual update while one runs returns `409 state_conflict`. If an update is running when an automatic update becomes due, its outcome determines the schedule. Each wait is the interval plus up to 60 minutes of random delay. After consecutive failures the wait is one hour, doubling per failure, never longer than the interval, and the count survives restarts.

A success restores the interval.

### Embedded doona provenance

Default-off `native-ui` implies `native-api`. The build embeds both editions:

| Edition | Absolute asset directory |
| --- | --- |
| Standard doona | `HONK_DOONA_DIR` |
| doona lite | `${HONK_DOONA_DIR}-lite`, ignoring trailing slashes on `HONK_DOONA_DIR` |

Both directories must contain `index.html`. `HONK_DOONA_DIR` is the only required environment variable.

| Pin in `.github/ci/pins.env` | Value |
| --- | --- |
| doona release | `0.1.0-rc.4` |
| Commit | `58dfe2e2d1bccb1c0363895adb27eb4bfa1e932d` |
| Archive checksums | `DOONA_SHA256`, `DOONA_LITE_SHA256` |

From the repository root, run `export HONK_DOONA_DIR=$(ci/fetch-doona.sh)`. The script:

1. Downloads both program archives from the pinned release.
2. Checks each archive against its checksum.
3. Checks for `THIRD-PARTY-NOTICES.txt` and every `LICENSES/` file named by that edition's `NOTICE`.
4. Removes fonts and extracts standard into the requested directory, and lite into its `-lite` sibling.
5. Prints only the standard directory.

`just lint` and `just test-ci` run the script when the variable is unset.

Full release builds include the embedded UI. The lean `-clash-api` and `-native-api` artifacts do not. The binary embeds each edition's own notices, and every full release tarball carries them under `doona/` and `doona-lite/`, respectively.

Lite uses system fonts. The Noto Sans TC and SC fonts are not embedded. Doona's CSS declares those fonts with `font-display: optional`, so the browser falls back to system fonts when the font requests return 404.

To use Noto Sans, extract `doona-<version>.tar.gz` and `doona-fonts-<version>.tar.gz` from the [doona release](https://github.com/Zakkaus/doona/releases) into one directory and point `ui` at it, or install the `doona` and `doona-fonts` packages and set `ui: /usr/share/doona`. Both editions share the corresponding GPL-3.0-only source at the doona tag [`v0.1.0-rc.4`](https://github.com/Zakkaus/doona/tree/v0.1.0-rc.4).

The release workflow attaches `doona-source-0.1.0-rc.4.tar.gz` to the tag release and to the rolling Debug release. `ci/fetch-doona.sh --source` checks that the tag still points at the pinned commit and generates it with `git archive --format=tar --prefix=doona/ v0.1.0-rc.4 | gzip -n` (GNU gzip). Redistributors of a `native-ui` binary must preserve the notices and provide corresponding source through a method permitted by GPL-3.0 section 6.

To reproduce the assets, extract the source archive into its own directory, use Node matching `^22.13.0 || ^24.0.0 || >=26.0.0` and `pnpm@11.15.1`. From the extracted source directory:

1. `pnpm install --frozen-lockfile`.
2. `pnpm build`.
3. `pnpm -C apps/lite build`.
4. `SOURCE_DATE_EPOCH=1793194168 pnpm package`.

The epoch is the pinned upstream commit's timestamp. The source archive has no Git history. Install brotli and use GNU tar and GNU gzip on `PATH` (verified with tar 1.35 and gzip 1.15).

Another gzip implementation can produce different archive hashes from identical tar bytes. Cargo builds embed only the files in `HONK_DOONA_DIR` and its `-lite` sibling and never build or download the frontend. That source's checker is `tools/conformance.mjs`.

Its live walk is read-only and skips controls, diagnostics and missing observed IDs. Check base and management contracts, and exercise browser actions separately: schema passes alone are not full UI, kernel or platform acceptance.

### Native logs and runtime settings

`GET /logs` serves SSE to authenticated callers and admitted anonymous loopback callers, with optional minimum `level` and `target` prefix filter. Capture is a separate structured tracing layer, not formatted console/Clash text. Records contain actual `ts`, `level` and `target`.

Only audited static messages and bounded typed fields are disclosed. Unaudited messages are explicitly withheld and arbitrary Debug/error/config fields are not formatted into the native buffer. `record_logs` defaults true and permits capture while its independent `/logs` SSE demand is active, retaining up to 512 records for 60 seconds.

The logs capability advertises these limits as `max_buffered_records` and `retention_seconds`, and lists `filters: [level, target]`. An explicit runtime `record_logs: "on"` keeps capture enabled without clients. Configuration false prohibits it until changed and restarted.

When effective recording stops, retained logs are released and resume cursors expire.
Like Clash `/logs`, capture always omits the `quinn::endpoint` target: its endpoint-driver ERROR duplicates carrier failures that honk reports with their own context.

Use `Last-Event-ID` for resume. Logs have independent stream/filter-bound cursors and, like `/events`, send ready → replay → live, retaining the supplied cursor on ready until replay advances it. Both reject expired/foreign/filter-changed cursors with `409 event_cursor_expired` before 200, allow 16 clients with 64 queued events each, disconnect full queues and send 15-second heartbeat comments.

A new stream while all 16 slots are taken returns `503 temporarily_unavailable` with `Retry-After`. Retention shrink invalidates evicted cursors.

`PATCH /runtime/settings` uses ordinary JSON merge semantics, for example `{"log":{"level":"debug","buffered_records":128},"flows":{"retention_seconds":60}}`. GET and successful PATCH return a coherent snapshot of recorder settings with `source: "config"|"runtime"`. Geodata is read separately and may reflect a concurrent update.

Supported fields are:

| Field | Allowed value | Configured value |
| --- | --- | --- |
| `record_flows`, `record_logs`, `record_dns_log` | `"on"`, `"off"`, `"auto"` | `"auto"` |
| `log.level` | `trace`, `debug`, `info`, `warn`, `error` | Configured native capture level |
| `log.buffered_records` | 64–512 | 512 |
| `dns_log.max_records` | 64–512 | 512 |
| `flows.max_flows` | 64–1024 | 1024 |
| `flows.retention_seconds` | 1–300 | 300 |
| `geodata` | See [geodata sources](#geodata-sources-and-automatic-updates) | Stored separately; not reset by activation |

Configuration permission determines which level and retention controls are available, independently of temporary recording activity. Schema and bound violations, such as empty, null (except `geodata: null`, which clears stored geodata settings), unknown or out-of-range values, return `400 invalid_request`. Geodata credential admission precedes schema validation, so an anonymous request containing `geodata` returns `403 permission_denied` first.

A field not listed in `resources.runtime_settings.fields` (a recorder's `log.*`, `dns_log.*` or `flows.*` fields when configuration prohibits that recorder, or `geodata` without a state db or geodata owner) instead returns `422 unsupported_value`. The full merge is validated before any store changes, and shrinking discards old records.

The capabilities advertise the bounds, not the current values: `logs.min_buffered_records`, `dns_log.min_records` and `flows.min_flows` are 64, and the `flows` capability reports the largest `max_flows` (1024) and `retention_seconds` (300). A patched `log.level` also replaces the console and log file filters, including one from `RUST_LOG` or `--debug`. Clash `/logs` keeps its per-request level.

Overrides are memory-only. Every accepted explicit activation, including a no-op or committed-degraded activation, restores configured settings and the startup console and file filters. Recorder modes reset to `"auto"`. Rejected activation and provider/network refresh do not reset them.

The top-level recorder fields accept `"on"` to keep a permitted recorder on, `"off"` to force it off, or `"auto"` to follow the corresponding independent flow, log or DNS-log demand. Omitted fields remain unchanged. Null is rejected.

Configuration false prohibits recording, and a runtime request to pin that recorder on rejects the entire patch with `422 unsupported_value`.

GET and successful PATCH include readonly `recording`: `flows`, `logs` and `dns_log` each contain `{allowed, mode, active}`, where `mode` is `"auto"`, `"on"` or `"off"`. `events.active` reports event capture, and `grace_remaining_seconds` reports the remaining general attachment grace, not any of the independent flow/log/DNS-log diagnostic countdowns. It is zero while a general stream is open.

Settings reads renew none of these deadlines.

### Connection closing, mode and datapath lifecycle

`DELETE /connections/{connection_id}` accepts no body or query. It returns 204 only after the exact TCP owner has closed or the UDP view has retired with token/generation/backend and in-flight reply-delivery acknowledgement. Concurrent/repeated closes of the same still-tracked owner wait for the same real completion (`Pending`) and inherit its success or `Failed` result.

Closing/Failed is not fabricated Gone/404. Absent IDs or captured owners replaced by another incarnation remain Gone/404. Visible but non-closable owners return 409.

Unconfirmed retirement returns 503. Closing one shared XUDP view does not kill its carrier or siblings.

Bulk DELETE accepts `type=all|tcp|udp`, optional source IP `src`, and `all=true|false`. Without a narrowing type/source filter, `all=true` is required. It snapshots the live set once and rejects more than 1000 matches with 413 before closing anything.

Success returns `{closed,skipped}`. Vanished rows do not count as closed, and non-closable rows are skipped. A retirement failure returns 503 after every selected close has finished, with the `{closed,skipped}` counts in `error.details`.

Those owners stay closed. Repeating an optional `Idempotency-Key` re-evaluates current owners. Synchronous close has no operation replay ledger.

The native `x-honk` `runtime_mode` resource is unavailable: its pinned PUT contract omits lifecycle-conflict and owner/backend-unavailable responses, and its capability does not distinguish reads from writes. GET/HEAD/PUT return `404 capability_not_supported`. No accepted modes are advertised.

The shared mode/target/origin owner remains active for Clash when native is enabled, without cache restore or mode persistence. Startup and accepted explicit activation (including no-op) reset to rule. Provider/network refresh preserves mode.

If the backend rejects the reset before commit, activation is rejected. After routing commit, it reports committed-degraded, retains the previous mode/source and fences admission rather than claiming a reset. Global retains stable target identity: if refresh removes it, new traffic fails closed rather than selecting a same-named replacement.

`must`/`block` remain final. With native disabled, existing Clash default/cached mode behavior is unchanged.

`GET /datapath` and runtime's datapath summary use backend-owned program/hook/routing/admission observations, not configured-interface guesses. Mock reports disabled/none. Real observations are partial, with unknown/null for unverified facts and separate datapath routing-generation identity.

Map capacity may be known while occupancy remains null. Attached hooks alone do not establish active admission, and `full_transparency` is never advertised.

The optional [business-connection grace](./global.md#shutdown) does not permit detaching unfinished cleanup to claim success. Already-started blocking work is not cancelled by aborting an async wrapper: the StateTick maintenance owner warns after its nominal stop deadline and continues to join the actual SQLite work. Blocking credential KDF/database work and an already-started NSS lookup also retain their real join.

These exceptions can extend total shutdown beyond nominal per-stage or HTTP grace deadlines. See [control-plane ownership](../design/control-plane.md#native-observation-api).

## Enablement and authentication

The API server starts only when `experimental.clash_api.external_controller` is non-empty and the binary includes the default-on `clash-api` feature. The controller requires a numeric socket address such as `127.0.0.1:9090` or `[::1]:9090`, not a DNS hostname. A leading `:port` binds `0.0.0.0:port`.

An invalid address is logged and does not stop the engine.

When `experimental.clash_api.secret` is non-empty, API requests require:

```http
Authorization: Bearer <secret>
```

A WebSocket upgrade may instead pass `?token=<percent-encoded-secret>`. Honk percent-decodes the token before exact comparison. Query-token authentication is limited to WebSocket upgrades.

Ordinary HTTP requests use the Bearer header. An empty `secret` disables authentication. The `/ui` static tree is outside the API authentication layer.

**The API has no TLS.** Bind it to localhost or place a TLS reverse proxy in front of it, and set a strong `secret` when untrusted clients can reach the listener.

The shipped `config.dae` binds to `127.0.0.1:9090`. A non-loopback controller with an empty `secret` emits a startup warning but is still allowed. This applies to wildcard and assigned addresses, regardless of firewall configuration.

## Endpoint map

The table follows the router in `crates/honk-core/src/clash_api.rs`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Return the Clash hello document, or redirect a non-JSON client to `/ui/` when external UI hosting is enabled. |
| GET | `/version` | Return `honk <build-version>` (including the release tag, using the same build identity as the CLI) and Clash premium/meta capability flags. |
| GET | `/configs` | Return the current mode, the implemented Clash-compatible configuration snapshot, and safe active-generation diagnostics under `honk-diagnostics`. |
| PUT | `/configs` | Compatibility no-op; accepts the request and returns `204 No Content`. |
| PATCH | `/configs` | Set `mode` to `Rule`, `Global`, or `Direct`; matching is case-insensitive. |
| GET | `/proxies` | Return every node and group plus the synthetic `GLOBAL` selector. |
| GET | `/proxies/{name}` | Return one node, group, or `GLOBAL` selector. |
| PUT | `/proxies/{name}` | Select a direct member of a Selector group with `{"name":"member"}`; also mutates the synthetic `GLOBAL` selector. Automatic groups, including Score, reject writes. |
| GET | `/proxies/{name}/delay` | Run an on-demand proxied delay test against the caller's `?url=` for a node or group. Already-warm transports are reused; every cold reusable session or QUIC client is warmed in a throwaway runtime before timing. |
| GET | `/group/{name}/delay` | Test all group members against the caller's `?url=` with up to `URLTEST_MAX_CONCURRENT` (10) proxied dials, returning successful member delays with the same timing semantics. |
| GET | `/rules` | Return one row per route. Simple matchers use native Clash rule types; compound, negated, and `must` rules use `complex` with the full dae statement. |
| GET | `/connections` | Return a connection snapshot, or stream snapshots after a WebSocket upgrade. |
| DELETE | `/connections` | Close all tracked connections. |
| DELETE | `/connections/{id}` | Close one tracked connection. |
| GET | `/traffic` | Stream per-second traffic JSON over WebSocket or chunked JSON lines. |
| GET | `/memory` | Stream process RSS JSON over WebSocket or chunked JSON lines. |
| GET | `/stats` | Return the userspace outbound, ready-pool, warm-resource, Score selection-reason, and UDP snapshot documented below. |
| GET | `/logs` | Stream tracing events over WebSocket or chunked JSON lines from one shared 256-slot broadcast queue; `?level=` defaults to `info`. |
| GET | `/dns/query` | Resolve `?name=` through honk DNS and return DoH-style JSON; `?type=` defaults to `A`. |
| POST | `/cache/fakeip/flush` | Compatibility no-op returning 204; no FakeIP mappings are persisted to flush. |
| POST | `/cache/dns/flush` | Flush the live DNS cache and its persisted DNS state. |
| GET | `/providers/proxies` | Expose non-empty groups as Clash proxy providers. |
| GET | `/providers/rules` | Return the current stub document `{"providers":[]}`. |
| GET | `/ui`, `/ui/*` | Redirect `/ui` to `/ui/` and serve the configured external UI directory. |

`/traffic`, `/memory`, and `/logs` send one JSON document per line for a plain HTTP GET. `/logs` installs dynamic tracing interest only while subscribers exist. With no subscribers, the Clash tracing layer does not format events.

Each subscriber's level filter runs after the shared queue. Lagged clients skip overwritten events without a gap marker.

### Diagnostics in `/configs`

`GET /configs` preserves the existing Clash fields and adds `honk-diagnostics`.
Settings and diagnostics are read from one committed configuration snapshot.
Startup publishes only admitted file and subscription diagnostics. Failed reloads
and rejected subscription refreshes leave the active list unchanged; there is no
last-failed-attempt cache.

A successful reload with unchanged effective settings can replace diagnostics
without advancing the generation. An authorized, admitted provider refresh replaces
only that provider's diagnostics, even when its nodes are unchanged; static-file
and other-provider diagnostics remain.

Library callers pass `DiagnosticBuckets` to `ControlPlane::reload_runtime_config(config, diagnostics)`, keeping static and provider-body diagnostics separate. Programmatic inputs without diagnostics use `DiagnosticBuckets::default()`. `merge_subscription_nodes(provider, nodes, diagnostics)` accepts that provider's diagnostic vector, including for admitted providers without worker declarations.

Full configuration replacement moves the complete candidate provenance into place, while provider replacement affects only that provider. SIGHUP retains the buckets of provider bodies actually retained by rebasing. Generated topology/ECS updates preserve source provenance.

All changes publish under the existing configuration write barrier, acquiring the diagnostics lock only after the configuration lock.

Full-replacement provider buckets must have unique UUIDs. Duplicate UUIDs reject the entire reload before publication, including when the effective configuration is unchanged. The active configuration and diagnostics remain intact.

| Field | Meaning |
| --- | --- |
| `honk-diagnostics.generation` | Active configuration generation; startup begins at `0`. |
| `honk-diagnostics.sources` | Metadata-only source rows referenced by retained diagnostics or their parents. |
| `sources[].id` | Opaque numeric source ID used by `diagnostics[].source` in this snapshot. |
| `sources[].ordinal` | Original zero-based ordinal within the attempt-local source table. |
| `sources[].parent` | Opaque `id` of the parent source, or `null` for a root source. |
| `honk-diagnostics.diagnostics` | Safe diagnostics retained for the active configuration and admitted providers. |
| `diagnostics[].code` | Stable diagnostic code. |
| `diagnostics[].severity` | Lower-case severity: `info`, `warning`, or `error`. |
| `diagnostics[].source` | Opaque `sources[].id`. |
| `diagnostics[].span` | Zero-based byte range `{start, end}` with exclusive `end`, or `null` when unavailable. |
| `diagnostics[].line` | Optional physical line number, or `null`. |
| `diagnostics[].byte_column` | Optional byte column, or `null`. |
| `diagnostics[].setting` | Fixed schema path with original sequence ordinals; it never contains operator-supplied names. |
| `diagnostics[].value` | Safe value representation; private values are redacted. |
| `diagnostics[].message` | Static diagnostic message. |
| `diagnostics[].entry_index` | Optional original entry ordinal, or `null`. |
| `diagnostics[].related_indices` | Related original entry ordinals. |
| `diagnostics[].terminal` | Whether this diagnostic represents the terminal failure. |

The generation matches the active DNS runtime generation. Source IDs are
snapshot-local, not filesystem identifiers. Sources are ordered static-file first,
then providers in configured declaration order, followed by admitted non-worker
providers in retained bucket order. Each source table keeps its original order;
only referenced sources and their ancestors are included.
Paths, raw input, credentials, and provider names or IDs are never exported.

### Delay measurement

The caller selects the test URL with `?url=`. A group request fans out to at most `URLTEST_MAX_CONCURRENT` (10) proxied measurements at once.

Delay tests use the canonical HTTP check-target decoder:

- HEAD preserves the raw path/query, including dot segments and query-only `/?query`.
- Authority omits credentials and default ports.
- Fragments are never sent.

Tests share periodic health checks' HTTP implementation. They report the second request's warm-path RTT, excluding proxy dial, target TLS and the first request. HTTPS verifies certificates, negotiates HTTP/2 or HTTP/1.1, and disables server push.

Both final responses must have valid decoded 200–499 statuses. A measured-round transport failure or timeout can fall back to the validated first sample. HTTP/1 partial responses never fall back, including on timeout, while graceful HTTP/2 GOAWAY can.

HTTP/1 informational and final response heads share a 16 KiB per-round cap. H2 response header lists also have a 16 KiB cap. Session warm-up, dial, target TLS, H2 startup and each request have separate timeout budgets.

Cold reusable generation probes use guarded temporary runtimes that close afterward. HTTP/2 drivers are released on completion or cancellation, so group scans retain no new reusable runtime per tested node.

Successful measurements update the node latency history. Failures return `503` for a single node and are omitted from group results; arbitrary manual test targets do not advance real-dial failure streaks.

On-demand delay exchanges retain Alive/API latency history but do not report business outcomes or populate configured Score comparison cohorts. Actual preliminary server/session preparation may report aggregate warm-up setup only. It does not fabricate the caller's URL as its own target or provide promotion proof.

Both delay routes retain admitted jobs through measurement cleanup even if the HTTP client disconnects. Owner-admission `503` responses distinguish exhausted capacity, stopped checks, and failed workers. A QUIC probe timeout or normal close linger is a measurement result, not a failed health owner. After the bounded peer-notification grace, Quinn drivers and then packet-adapter workers are stopped and joined.

Actual owned-worker failure still closes health admission.

### Score group representation

A configured `policy: score` group is represented as Clash `type: "url_test"` for compatibility. Its `all` list keeps the same direct member tags as other groups, while `now` reports the current aggregate TCP winner rather than any one exact target's private selection. Score remains automatic and authoritative: `PUT /proxies/{name}` is rejected rather than pinning a member.

No score cell or scorer-only target data is added to proxy documents. `/stats.score` contains only the safe aggregate counters documented below. `/connections` retains its established destination metadata.

## Mode and selector mutations

`PATCH /configs` accepts a JSON object such as:

```json
{"mode":"Global"}
```

The mode update goes through `DatapathFlagsHandle`, the sole serialized writer for shared mode and `DATAPATH_FLAGS_MAP`. Updates compose with reload's NFQUEUE fence, reopen and disable rather than republishing stale readiness. Rule-derived bits belong to the immutable routing descriptor.

Mode is cached only when native is disabled. With native enabled, both APIs use the [same transient mode contract](#connection-closing-mode-and-datapath-lifecycle).

`PUT /proxies/{name}` accepts the body regardless of `Content-Type`. For a configured Selector, the target must be a direct member tag, not a leaf reachable only through a nested group. It validates and writes both TCP/UDP choices together.

GET displays TCP. Changed choices invoke per-network persistence/warm callbacks. Selector choices persist when the state cache is available, unless `experimental.cache_file.enabled` is explicitly false.

Omitting the setting retains persistence. With `interrupt_connections`, the control owner closes captured affected transports and waits for confirmation rather than removing tracker rows. Writing unchanged choices causes no interruption.

URLTest, LoadBalance, Fallback and Score reject manual selection.

`GLOBAL` is synthetic, but every `all` member is a concrete configured group/node with a top-level proxy document. `PUT /proxies/GLOBAL` accepts a member name through the same flags owner. With native disabled, the cache stores it under the `GLOBAL` selector key and unresolved display selections fall back to the first member.

With native enabled, writes resolve a stable identity and do not persist. Removing that target makes global routing fail closed, even if the legacy display projection shows another first member.

## External UI hosting

Set `experimental.clash_api.external_ui` to serve a static dashboard directory. If the directory is missing or empty, honk starts a background ZIP download. Startup does not wait, and the static route returns `404` until files are available.

`assets.ui.url` replaces the built-in zashboard URL, while `HONK_UI_DOWNLOAD_URL` remains the highest-precedence override.

Every download hop accepts only HTTP(S), with at most five redirects and a 128 MiB limit on the downloaded ZIP body. HTTPS-to-HTTP redirects and IP-literal hosts are allowed. Each hop follows routing or the effective route from `assets.ui.route` then `assets.route`.

`assets.ui.route` overrides `assets.route` for the initial request and redirects. `direct` uses the direct HTTP client. A group forces its selected outbound leaf.

With no configured route, each URL follows honk's traffic routing decision:

| Result | Download path |
| --- | --- |
| `direct` | Direct HTTP client |
| `block` | Abort |
| Proxy | Selected outbound leaf |

Each direct or proxied HTTP exchange reports the real host/IP, port, setup, first response, bytes, and terminal outcome to its traversed Score groups. Paths that traverse no Score group create no score reporter or cell.

Setup is recorded after connection/TLS preparation and before sending the HTTP request. First response still requires the real response. Shared HTTP errors preserve their original typed causes: target failures remain target-scoped, while typed carrier failures keep node attribution even after setup.

Download or extraction failures are logged and do not stop the engine.

## `GET /stats`

`GET /stats` is a userspace snapshot. It is not the eBPF `OUTBOUND_STATS` map and does not expose its packet counters. The fixed DNS, TCP, UDP, and NFQUEUE schemas create no dynamic per-node labels.

```text
{
  outbounds: [{ name, totalConns, activeConns, upload, download, errors }],
  pool: { readyHits, readyMisses, entries },
  dns: {
    socketAdmission: { refused, timeouts },
    proxyAdmission: { timeouts },
    pressure: { retiredUdpPools, retiredTransports }
  },
  quic: {
    activeConnections, srttUs, cwndBytes, flowReceivedBytes, flowSentBytes,
    receiveWindowBytes, receiveWindowAvailableBytes, streamReceiveWindowBytes,
    sendWindowBytes, sendWindowAvailableBytes, lossRatePpm, sentPackets,
    ackFrames, lostPackets,
    sentPlpmtudProbes, lostPlpmtudProbes, currentMtu, blackHoles,
    congestionEvents, txBytes, rxBytes, txDatagrams, rxDatagrams, txIos, rxIos,
    transportTxWouldBlock, transportTxDrops, transportRxDrops, sessionRxDrops,
    sendTimeouts, pathStalls
  },
  warm: {
    nodes: { preconnect, health, udp, selector, traffic },
    sessions: { anytls, vless, tuic, juicity, hysteria2 }
  },
  tcp: {
    activeFlows, limit, capacity: { rejected }
  },
  score: {
    groups: [{ name, tcp: R, udp: R, verification: { tcp: V, udp: V }, budget: { tcp: B, udp: B } }],
    businessStarts,
    cache: {
      exactCells, aggregateCells, exactEvictions, aggregateEvictions,
      comparisonCells, comparisonLogicalBytes, comparisonLogicalCapacity,
      comparisonEvictions, comparisonExpired, comparisonRejected
    }
  },
  udp: {
    endpoint: { hits, misses },
    latency: {
      route: H, dial: H, replyReady: H, firstSend: H, firstReply: H
    },
    capacity: { rejected },
    slowPermit: { accepted, rejected, closed },
    queue: { accepted, full, flowFull, globalPayloadFull, closed },
    firstSend: { failures },
    stagger: { attempts, winners, cancellations },
    warm: { attempts, successes, failures },
    nfqueue: {
      received, activeFlows, kernelQueueDepth, kernelStatsAvailable,
      kernelStatsReadErrors, kernelDropped, kernelUserDropped, heldPackets,
      heldPeak, socketReceiveBufferBytes, actorQueueFull, correlatorFull,
      actorQueueDepth, actorQueuedBytes, actorOldestAgeNanos, directAccepted,
      proxyCopied, proxyDropped, block, cancel, drop, tokenMismatch,
      tokenExhaustion, tokenRollovers, verdictErrors, receiptToVerdict: H
    }
  }
}
H = { count, sumNanos, buckets }  // buckets has 64 fixed log2 slots
R = {
  coldExplore, periodicExplore, reliabilityWinner, performanceWinner,
  incumbentHeld, insufficientEvidenceHeld, directionalTradeoffHeld, incumbentIneligible,
  freshFailureBypass, deadFiltered, ordinarySwitch, switchFlap,
  failStreakExcluded, exploreBackedOff, carrierPressure, carrierRttPressure,
  carrierLossPressure, carrierValidation
} // every R value is a u64 count
V = { provisionalSelections, usableSelections, validationSelections }
B = { businessStarts, sources: { cold, periodic, recovery }, trialStarts,
      reserved, spent, budgetBlocked, inFlightBlocked, refunded, expired,
      coldAllowance, coldAvailable, earnedAvailable, earningPeriod, scopes,
      trialSuccess, trialFailure, trialCancelled, trialSetupHistogram,
      trialSetupMillis, trialElapsedMillis }
```

### DNS fields

All `dns` fields are process-lifetime `u64` event counters shared across active and retired generations; reload does not reset them. Fields are sampled independently, so one snapshot does not imply cross-counter coherence. These totals are exposed by Clash `/stats`, not the native DNS diagnostic or history APIs.

| Field | Meaning |
| --- | --- |
| `socketAdmission.refused` | Endpoint network bootstrap refused because it needs two credits and the whole DNS socket partition is smaller than that. |
| `socketAdmission.timeouts` | Mandatory physical socket admission calls that return because their admission deadline expires. |
| `proxyAdmission.timeouts` | Mandatory proxy stream or non-raw packet preparation admission calls that return because their admission deadline expires. |
| `pressure.retiredUdpPools` | Idle UDP socket pools selected for pressure retirement, once per detached pool. |
| `pressure.retiredTransports` | Idle TCP/TLS/H2/QUIC transport pools first selected for pressure retirement; resuming retained teardown does not count again. |

`socketAdmission.refused` and `socketAdmission.timeouts` are disjoint. Initial contention, optional UDP shard-growth misses, and caller cancellation do not count as admission failures. Counters advance at admission, not once per singleflight follower or client reply. Pressure counters describe selected resources, not queries, drops, or descriptors already released; one transport pool may own multiple sockets. DNS admission failure may render as `SERVFAIL`, independently of singleflight `REFUSED`. Existing throttled failure logging is unchanged.

### TCP fields

| Field | Meaning |
| --- | --- |
| `activeFlows` | Accepted transparent TCP flows currently holding an admission permit. |
| `limit` | Current process-wide TCP-flow admission ceiling; it starts at the descriptor-derived floor and scales with idle descriptor headroom. |
| `capacity.rejected` | Monotonic count of accept-loop iterations that waited for a permit because the TCP budget was full; accepted sockets remain in the kernel backlog rather than being dropped. |

### QUIC fields

| QUIC field | Meaning |
| --- | --- |
| `srttUs`, `cwndBytes`, `currentMtu` | Average across active connections; zero when none are active |
| `receiveWindowBytes`, `receiveWindowAvailableBytes`, `streamReceiveWindowBytes` | Average across active connections; zero when none are active |
| `sendWindowBytes`, `sendWindowAvailableBytes` | Average across active connections; zero when none are active |
| `flowReceivedBytes` | Stream bytes delivered to applications |
| `flowSentBytes` | Stream bytes acknowledged by peers |

The byte counters include completed pooled connections, as do the packet, UDP-byte, I/O, loss, black-hole and congestion counters.

Pooled TUIC, Juicity and Hysteria2 connections sample flow-control state once per second.

| Window-growth input | Effect |
| --- | --- |
| Ten-second receive/send goodput EWMA, RTT at least 80 ms, and three consecutive high-BDP samples | Raise the live connection's receive or send floor toward `2 x BDP`. |
| Peer `DATA_BLOCKED` or `STREAM_DATA_BLOCKED` | Direct evidence of a constrained advertised window. Bypass the RTT gate and double the connection or stream receive floor. |
| Zero-progress sample while connection credit remains pressured | Preserve, but do not advance, the connection-level streak. |

A throttling window understates the goodput-derived estimate. Each floor has its own five-minute promotion cooldown. Automatic promotions stop at 32 MiB without lowering larger explicit configurations.

honk never shrinks a learned window because application demand is low. It never changes congestion control on a live connection.

| Counter | Meaning |
| --- | --- |
| `ackFrames` | Received ACK frames, a path-progress signal. Duplicate frames may count more than once. |
| `lossRatePpm` | Loss rate excluding PLPMTUD probes; denominator `sentPackets - sentPlpmtudProbes` |
| `lostPackets` | Packet losses excluding PLPMTUD probes |
| `sentPlpmtudProbes`, `lostPlpmtudProbes` | Separate PLPMTUD probe counters |
| `txIos`, `rxIos` | I/O counts exposing batching efficiency |
| `transportTxWouldBlock` | Full 64-packet adapter queues; Quinn retries |
| `transportTxDrops` | Datagrams intentionally discarded after the proxied transport reports congestion or timeout |
| `transportRxDrops` | Full adapter receive queues |
| `sessionRxDrops` | Full 256-packet TUIC/Hysteria2 session queues |
| `sendTimeouts` | UDP sends on a metrics-enabled connection whose deadline expired while still admitted into that connection's current no-ACK wait |
| `pathStalls` | Shared QUIC connections retired by the path watchdog after a full no-ACK grace |

`sendTimeouts` is a congestion diagnostic, not a count of all timeouts, node failures or recoveries. `pathStalls` counts neither packet loss, affected flows nor recoveries. Both are process-lifetime totals.

### Score selection-reason fields

`score.groups` is an additive part of the authenticated `/stats` response. It is an empty array when no group currently uses `policy: score`. Otherwise it contains every current Score group, including groups with no resolved leaves, sorted lexicographically by `name`.

Each group always has both `tcp` and `udp` objects, and each object always has every `R` field above. Missing network activity is represented by zeroes, never omitted fields.

Each `R` value is a saturating `u64` count, not a latency, throughput or health measurement. One authorized multi-candidate Score Apply records one final reason:

| Final reason | Meaning |
| --- | --- |
| `coldExplore`, `periodicExplore` | Validation |
| `incumbentIneligible` | Leaving an incumbent outside ordinary eligibility |
| `freshFailureBypass` | An eligible incumbent has an unresolved business failure. |
| `insufficientEvidenceHeld` | No challenger earns promotion, and the ordinary utility winner lacks a qualified shared performance comparison. |
| `directionalTradeoffHeld` | No challenger earns promotion. A comparison has at least 10% gain in one known direction but greater than 10% loss in another. |
| `incumbentHeld` | The comparison does not clear the hold margin. |
| `reliabilityWinner`, `performanceWinner` | Otherwise retain their alternative-eligibility classification. |

`performanceWinner` alone proves neither improvement nor a switch. `insufficientEvidenceHeld` does not mean reliability history is absent.

| Additional counter | Meaning |
| --- | --- |
| `ordinarySwitch` | Actual committed ordinary A→B choices |
| `switchFlap` | Returns to the prior winner within eight same-target ordinary choices |
| `deadFiltered`, `failStreakExcluded`, `exploreBackedOff` | Affected candidates per rank |

First choices, trials and missing prior history cannot add switches. Peek, API reads, singleton bypass and last resort do not increment reason counters. Nested-group ranks are not a one-to-one count of dispatched connections.

For UDP, `deadFiltered` also counts candidates excluded by protocol/configuration incapability. It is a candidate-filter count, not a count of newly failed nodes or business attempts. These exclusions do not add Score failures or exploration backoff.

`carrierPressure` counts fresh carrier-family episodes admitted into an existing group/network aggregate cell, not packets or failed connections. Duplicate heartbeat reads do not increment it. `carrierValidation` counts periodic validation selections while the ordinary winner has a carrier hint newer than the previous validation.

It is an overlapping diagnostic count, not another exclusive reason or proof that the hint alone caused the selection. Hints do not alter business reliability, qualification or health. These fields are readonly on API reads.

Carrier observations arrive from the control heartbeat independently of selection calls.

`carrierRttPressure` and `carrierLossPressure` retain the accepted episode's reason. An episode indicating both increments both reason counters but increments `carrierPressure` only once. These overlapping counts do not identify a specific carrier/transport, measure an application loss rate, or add failures.

Duplicate or stale hints increment none of them. TCP loss pressure means retransmission pressure, not confirmed application packet loss.

Counters begin at zero on process start and accumulate in process memory only. They survive a successful reload while the group name remains configured, including zero-leaf and temporary Score-to-non-Score-to-Score transitions. Non-Score groups are hidden from this response.

A committed deletion prunes that name's counters, and a recreated name starts at zero. Generation-fenced superseded managers cannot mutate counters after replacement, including after same-name recreation. The snapshot is copied before JSON serialization, so reading it cannot mutate selection state.

`/stats.score` exports group names, fixed TCP/UDP reason, verification and budget fields, a root business count, and bounded evidence-cache totals. It contains no node identity, target/domain/IP/port, raw cell, cadence key, authority or credential. Existing public member names in `/proxies` and destination metadata in `/connections` remain unchanged.

### Score verification

Score group objects in `/proxies` and `/proxies/{name}` add `scoreVerification`. Its fixed objective is `responseQualityWithAvailability`, and its scope is `aggregate`, not a certificate for every exact destination. `tcp` and `udp` each contain:

| Field | Meaning |
| --- | --- |
| `selected` | Existing public member tag for this readonly evaluation, or null with no ordinary eligible candidate. TCP `now` uses this same evaluated choice when present. |
| `state` | `provisional` or `observedUsable`; the latter requires four distinct targeted Traffic reporters with RX after setup/TX in one uninterrupted cohort, whose latest eligible RX is less than 60 seconds old. Applicable failure/reload or a 60-second gap resets the cohort; clones/repeats cannot add credits. This does not grant cold qualification. In a genuine post-failure cohort the same four credits may independently earn scoped recovery; aggregate usability does not qualify every exact target. |
| `challengers` | Fresh pairwise response comparisons between `selected` and evaluated challengers; see below. |
| `nextAction` | `nextBusinessFlow` names future real-work demand for evidence, ordinary qualification or recovery, not a reservation or dispatched I/O; inspect `waitReason`. `backoff` retains failure isolation; `none` means no actionable missing work. Missing transfer evidence never creates work; directional goodput waits for real offered load. |
| `question` | `none`, `availability`, `response`, `qualification` or `recovery`: the next unresolved evidence question. No remaining action reports `none`; backoff retains the blocked candidate's question rather than the settled winner's. |
| `waitReason` | Why work is waiting; values and aggregate-scope rules are listed below. A wait does not prove that work will succeed. |
| `coverage` | `scope` (`all` or `bounded`); `candidates` counts the whole visible candidate view, `evaluated` its intersection with the shared serving pool, and `unevaluated` the difference. The winner gets no extra slot. Parent routes and targets share that pool; TCP and UDP remain separate. Out-of-pool members receive no ordinary or optional policy work. These are not counts of distinct leaves across existing connections. `pending` counts evaluated members with an open question, including qualification or recovery work for members that already have a comparison. |
| `network`, `targetFamily`, `healthFamily`, `targetSpecific` | Transport and scope dimensions. This aggregate endpoint has no exact target and exports no domain/IP/port or raw node ID. |


| `waitReason` | Meaning |
| --- | --- |
| `none` | No wait |
| `budget` | Credit unavailable, or repeated trial failures pause trials behind a usable selection |
| `comparableTraffic` | Future comparable business is needed. |
| `inFlight` | Sufficient matching-target work exists, or the separate four-work node ceiling applies. |
| `backoff` | Failure isolation |

Aggregate reads inspect retained IPv4/IPv6 scopes without creating them:

- Both scopes budget-blocked: `budget`.
- Either scope available or unseen: future comparable traffic remains possible.
- Otherwise: retain the in-flight wait.

Readonly/Peek uses committed participant membership without reranking. Apply initializes and refreshes that membership. Before initialization, readonly reads use a temporary bounded projection.

See [evaluation-set lifecycle](../design/groups.md#conditional-verification).

`challengers` lists the selected member's current original pairs, the same pairs ordinary promotion reads, that hold a fresh qualified response metric. Members without one are omitted. The list is empty when none has one.

Each entry has `name` (the public member tag, a display label that need not be unique across nested paths), `basis` (`targetResponse`, `commonTargets` or `configuredProbe`), `relation` (`selectedFaster`, `equivalent` or `challengerFaster`), `reporters` and `validForMs`. `equivalent` uses the inclusive symmetric band `high - low <= 0.1 × low` on actual response values, including zero and sub-millisecond values.

`reporters` is the weaker side's retained distinct-reporter support: each of four blocks retains up to four IDs, and their deduplicated union can reach sixteen. This is not the exact count of every observed reporter. `validForMs` is the remaining validity of that response metric.

Business blocks last 15 seconds and expire at block start plus 60 seconds. Configured-probe blocks use `max(15s, 2I)` for the producer's interval `I`, with validity bounded by both the oldest supporting block's four-block retention deadline and the weaker side's latest support plus `max(60s, 2I)`. Existing failure/reload/incarnation fences remain.

`commonTargets` uses at most eight canonical equal-weight response-qualified shared targets, not unrelated aggregate averages. Setup and warm-up are not comparison evidence.

A relation describes measured response time only. It is not a promotion decision, a reliability or bandwidth verdict, an error probability or a guaranteed optimum. It does not certify the selected member against members absent from the list. Ordinary switching still applies its own completion-dependent margin and reliability, availability and directional protections.

Reads do not dispatch validation or change counters.

`/stats.score.groups[].verification.tcp` and `.udp` add saturating counters: `provisionalSelections`, `usableSelections` and `validationSelections`. They advance only on authorized Apply.

### Score work budget and observed costs

`/stats.score.businessStarts` counts unique original Score business starts across nested groups. `/stats.score.groups[].budget.tcp` and `.udp` aggregate retained target-family scopes. Nested group totals must not be summed as unique businesses.

Original work counts even when selected as a trial. Continuations, including a different network or target family, earn no additional original credit. Node-specific work starts before proxy DNS or physical-dial admission waits, independently of the reporter's physical/logical I/O boundary.

DNS query lifecycle admission is a synchronous open/closed check before that work, not a physical-admission wait.

Budget counters report recorded ledger values. Readonly wait and cold-start decisions also account for credit refundable from expired pending reservations; they do not update `refunded`, `expired` or other counters.

| Fields | Meaning |
| --- | --- |
| `businessStarts` | Original starts summed over retained scopes. |
| `scopes` | Retained scope count. |
| `earningPeriod` | Fastest current earning period `q` across scopes: 16 normally. A scope uses 8 when its group sees at least two flows/second and recent trials mostly succeed. Before any scope exists, the value is 0. This is not a denominator for a combined-scope budget formula. Each scope freezes cold allowance `B` at creation and earns `1/q` per original start using the then-current `q`. Per scope, `spent + reserved` never exceeds `B` plus whole earned credit. |
| `sources.cold`, `sources.periodic`, `sources.recovery` | Started work by source: cold-token trial, earned-token trial, or budget-neutral continuation. `recovery` includes TCP replacement, DNS rerouting/UDP-to-TCP fallback, and UI and subscription redirects, not only retries after errors. It is neither an optional trial nor new original business. Ordinary non-trial work has no source bucket. |
| `trialStarts`, `spent`, `reserved` | Begun optional trials, cumulative spent tokens, and outstanding unbegun token reservations. Begin spends once; cancellation after begin does not refund. |
| `coldAllowance`, `coldAvailable`, `earnedAvailable` | Summed frozen initial allowances and current available credit. Each scope retains at most eight unspent earned tokens. Time, reads, target churn and evidence expiry earn none; retained reload/membership changes do not reset currency. |
| `budgetBlocked`, `inFlightBlocked`, `refunded`, `expired` | Denied reservation counts (`budgetBlocked` also counts candidates a scope refuses while failing trials pause it), last-reference/unbegun invalidation refunds, and expired in-flight tracking entries. Only unbegun reservations refund; tracking expiry never refunds begun work. |
| `trialSuccess`, `trialFailure`, `trialCancelled` | Exactly-once outcomes of begun optional trials. Rejection/shutdown/neutral cancellation belongs to `trialCancelled`. `trialFailure` is actual observed failure, not the extra failures caused by choosing a trial instead of an unobserved alternative. |
| `trialSetupHistogram`, `trialSetupMillis`, `trialElapsedMillis` | Eight fixed log2-millisecond setup buckets (slot 0 includes 0–1 ms; final slot includes 128 ms and above), summed observed setup duration, and summed start-to-settlement duration. These measure actual trial cost, not causal extra latency or overhead. |

`/stats.score.cache.comparisonCells` is capped at 512. `comparisonLogicalBytes` charges the comparison store, vector capacity and owned key capacity. `comparisonLogicalCapacity` is its implementation-sized worst-case allocation bound, no greater than 1 MiB.

Neither is measured process RSS or the size of all Score state. Allocator overhead and other process allocations are excluded. `comparisonEvictions`, `comparisonExpired` and `comparisonRejected` count store removal/admission events.

Readonly expiry can invalidate support before physical removal increments a counter. Existing exact/aggregate LRU fields are unchanged.

### Outbound and ready-pool fields

| Field | Meaning |
| --- | --- |
| `outbounds[].name` | Outbound name. |
| `outbounds[].totalConns` | Connections started through the outbound. |
| `outbounds[].activeConns` | Connections currently open through the outbound. |
| `outbounds[].upload` | Userspace bytes from client to proxy. |
| `outbounds[].download` | Userspace bytes from proxy to client. |
| `outbounds[].errors` | Failed connection attempts attributed to the outbound. |
| `pool.readyHits` | Ready bare-connection pool hits. |
| `pool.readyMisses` | Ready bare-connection pool misses. |
| `pool.entries` | Current ready bare-connection entries. |

### Histogram format

Each `H` is `{count, sumNanos, buckets}`. `count` is the number of observations and `sumNanos` is their nanosecond sum. `buckets` is a 64-element array of non-cumulative counts: slot $n$ covers $2^n$ through $2^{n+1}-1$ ns, slot 0 also includes zero, and the final slot saturates at `u64::MAX`.

### UDP fields

| Field | Meaning |
| --- | --- |
| `endpoint.hits` | Packets handled by an already-established UDP endpoint fast path. |
| `endpoint.misses` | Cold-flow endpoint lookup misses. |
| `latency.route` | Cold route-selection latency. |
| `latency.dial` | Cold UDP dial-attempt latency. |
| `latency.replyReady` | Synchronous reply-socket preparation before endpoint-driver commit. |
| `latency.firstSend` | First-send attempt latency. |
| `latency.firstReply` | Time until the first reply is successfully reinjected to the client. |
| `capacity.rejected` | Exact endpoint-capacity reservation rejections. |
| `slowPermit.accepted` | Admissions into the active UDP slow path. |
| `slowPermit.rejected` | Slow-path admissions rejected because the shared connection semaphore is full. |
| `slowPermit.closed` | Slow-path admissions rejected while the generation is draining. |
| `queue.accepted` | Packets admitted to a bounded endpoint-driver queue. |
| `queue.full` | Aggregate retained-queue drop-newest events. |
| `queue.flowFull` | Drop-newest events caused by one flow's packet-slot bound. |
| `queue.globalPayloadFull` | Drop-newest events caused by the global retained-payload byte bound. |
| `queue.closed` | Queue attempts against a closing or closed endpoint driver. |
| `firstSend.failures` | First-send errors or timeouts; both are treated as ambiguous sends. |
| `stagger.attempts` | Cold URLTest speculative preparation attempts started. |
| `stagger.winners` | First eligible staggered preparations that succeeded. |
| `stagger.cancellations` | Started speculative preparations cancelled after another candidate won. |
| `warm.attempts` | Generation-owned UDP warm dispatches started. |
| `warm.successes` | Warm dispatches returning `Ready`. |
| `warm.failures` | True warm failures while the generation remains live. `NotApplicable` is neutral. |

`queue` measures the endpoint-driver queue. It is distinct from `slowPermit`, which measures admission to the UDP slow path.

### NFQUEUE fields

| Field | Meaning |
| --- | --- |
| `received` | Packets delivered by the NFQUEUE listener. |
| `activeFlows` | Current flow cells owned by the pending-verdict correlator. |
| `kernelQueueDepth` | Current queued packet count for the active kernel queue instance. |
| `kernelStatsAvailable` | Whether the latest kernel queue-statistics read succeeded. |
| `kernelStatsReadErrors` | Cumulative kernel queue-statistics read failures. |
| `kernelDropped` | Packets dropped because the kernel NFQUEUE reached its queue limit, accumulated for the process lifetime across hard queue rebinds. |
| `kernelUserDropped` | Packets dropped while the kernel delivered NFQUEUE messages to userspace, accumulated for the process lifetime across hard queue rebinds. |
| `heldPackets` | Current delivered packets whose verdict guards remain held. |
| `heldPeak` | Peak simultaneous held verdict guards reported by the queue service. |
| `socketReceiveBufferBytes` | Effective netlink socket receive-buffer size. |
| `actorQueueFull` | Packets dropped fail-closed because the bounded ingest actor queue was full. |
| `correlatorFull` | Packets dropped at either hard correlator limit: 4,096 flow cells or 64 retained verdicts per flow. |
| `actorQueueDepth` | Current ingest actor queue entries. |
| `actorQueuedBytes` | Current payload bytes retained in the ingest actor queue. |
| `actorOldestAgeNanos` | Age in nanoseconds of the oldest current ingest actor item. |
| `directAccepted` | Successful marked `NF_ACCEPT` verdicts for direct decisions. |
| `proxyCopied` | Payload ownership transfers into the canonical UDP initializer. |
| `proxyDropped` | Successful original-packet `NF_DROP` verdicts for proxy decisions. |
| `block` | Successful policy-block drop verdicts. |
| `cancel` | Successful cancellation drop verdicts. |
| `drop` | Other successful fail-closed drop verdicts. |
| `tokenMismatch` | Stale or mismatched decision-token/flow-identity events. |
| `tokenExhaustion` | Observations that the persistent decision-token allocator is exhausted. |
| `tokenRollovers` | Successful exhausted-token generation rotations. |
| `verdictErrors` | Failed `NF_ACCEPT` or `NF_DROP` operations. |
| `receiptToVerdict` | Histogram from listener receipt to a successful terminal verdict; it is not kernel queue residence time. |

A one-second sampler reads the owned kernel queue independently of packet dispatch. After a failed read, the previous `kernelQueueDepth`, `kernelDropped`, and `kernelUserDropped` remain visible, while local held-packet and receive-buffer gauges continue to refresh.

### Warm-resource fields

| Field | Meaning |
| --- | --- |
| `warm.nodes.preconnect` | Warm nodes attributed to startup bare-TCP preconnect. |
| `warm.nodes.health` | Warm nodes observed during health probing. |
| `warm.nodes.udp` | Warm nodes attributed to the UDP warm coordinator. |
| `warm.nodes.selector` | Warm nodes retained as configured Selector leaves. |
| `warm.nodes.traffic` | Warm nodes with no explicit attribution mark, therefore attributed to traffic. |
| `warm.sessions.anytls` | Retained AnyTLS pool sessions. |
| `warm.sessions.vless` | Retained VLESS pool sessions. |
| `warm.sessions.tuic` | Occupied TUIC client slots. |
| `warm.sessions.juicity` | Occupied Juicity client slots. |
| `warm.sessions.hysteria2` | Occupied Hysteria2 client slots. |

A node may count under several explicit reasons. The gauges follow the current runtime generation; drained resources disappear from the next snapshot.

## Related docs

- [Experimental configuration](./experimental.md)
- [NFQUEUE design](../design/nfqueue.md)
- [Control-plane design](../design/control-plane.md)
