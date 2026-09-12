# The honk dialect of dae configuration

honk reads dae configuration syntax as a dialect: where honk and dae interpret the same text differently, honk's documented behavior is the contract. This page describes the source-backed parser's current rules. The dae column covers only its grammar (`dae_config.g4`), not value conversion.

## Lexical rules

| Input | dae grammar | honk |
|---|---|---|
| `#` inside a bare value, `log_file: /tmp/a#b`, `use_host: /tmp/a#b`, or `group(hk#suffix)` | `#` is a safe character inside a bare literal | Glued `#` is data, with `legacy-glued-hash` at the formerly truncated boundary. Scalar paths retain `/tmp/a#b`; the subgroup name is `hk#suffix`. Insert whitespace before an intended comment. |
| `#` glued to an outbound name in a routing rule, `domain(x) -> proxy#c` | one bare literal, `proxy#c` | Literal target `proxy#c`, with `legacy-glued-hash`; normal target validation still applies. Write `-> proxy # comment` for a comment. |
| `/* … */` | block comment, skipped | No block-comment syntax. A statement beginning with `/*` receives `unsupported-comment` and is ignored; following physical lines still participate in configuration. Use `#` on each intended comment line. |
| `[key: value]` after a declaration, `filter: name(x) [add_latency: -500ms]` | accepted as an annotation | Not recognised; the filter is reported as unparseable and ignored. honk has no per-node latency bias. |
| An apostrophe inside a bare scalar, `log_file: /tmp/don't`, or an opened traffic argument quote | lexer error for the bare apostrophe | `/tmp/don't` is literal. Ordinary quotes open only at token head or immediately after unquoted `(` or `,`; root `include` additionally recognizes adjacent quoted paths. A traffic quote that does not close on its physical line fails with located `unterminated-quote`; close the quote rather than relying on brace recovery. |
| Braces inside quotes, `secret: 'a}b'`, or comments | data | Quoted braces and token-head-comment braces are data. Entry-tail compatibility after a glued `#` does not hide separated structural braces. Changed legacy comment-brace interpretation emits `legacy-comment-brace`; put the real closing brace outside the comment. |
| Block opener without a space, `global{ … }` | whitespace is skipped, so this is a block | `block-delimiter-spacing` error, whether inline or line-final. Separate block braces from the header with whitespace. Compact empty blocks such as `global {}` remain accepted. |
| An extra `}`, or an empty file | an extra `}` is rejected; empty or comment-only input is accepted | Extra closers are ignored with `unmatched-close`; a document without a block is rejected. Extra-close compatibility will be reviewed after the first PR2 release. |
| Group names, `123 {`, `香港 {`, `Hong Kong {` | a block name is one `ID` | The raw header before separated `{` is the dynamic group name. Unknown top-level names are diagnosed and skipped, not interpreted as plugins. |
| Two declarations on one line, `global { log_level: debug log_file: x }` | whitespace-separated declarations | One declaration: `log_level` is `debug log_file: x`. One `key: value` per line; one-line blocks hold one statement. |
| The opening brace on the next line, `global` newline `{` | whitespace, newlines included, is skipped | Ordinary split headers fail. Only top-level `include` retains a split opener, including intervening blank/comment lines, with located `legacy-include-opener`. Put `{` on the include header line; compatibility will be reviewed after the first PR2 release. |

## Scalars and lists

| Input | dae grammar | honk |
|---|---|---|
| A bare value with colons, `bind: 127.0.0.1:53` | not one literal; must be quoted | Accepted bare: the value is everything after the first `:`. |
| A call-shaped value, `client_subnet: auto(9.9.9.9)` | function expression | The text `auto(9.9.9.9)` is the value; the setting parses it itself. |
| Quoted list items, `lan_interface: 'eth0', 'eth1'` | two literals | Split the list first, then remove one enclosing quote pair per item: `eth0`, `eth1`. Changed legacy quoting emits `legacy-list-quoting`. Whole-quoted comma aggregates remain compatible for check-target lists, with `legacy-quoted-list`; prefer individually quoted or bare items. |
| Booleans `t`, `y`, `f`, `n` | bare literals | Lenient settings (case-insensitive): `true`, `yes`, `1`, `on` are true; `false`, `f`, `no`, `n`, `0`, `off`, `t`, `y` are false. The four single-letter shorthands emit `legacy-bool-shorthand`; unknown spellings are false with a diagnostic. Prefer `true` or `false`. `global.nfqueue_enable` and legacy `experimental.udp_nfqueue.enabled` remain strict and reject shorthands. |
| Marks, `so_mark_from_dae: 0x10` and `so_mark_from_dae: 10` | bare literals | Both are read as hexadecimal: 16 and 16. An unparseable mark falls back to 0 with a diagnostic. |
| Fractional seconds in a millisecond setting, `check_tolerance: 1.5s` | bare literal | 1500 ms. Unparseable millisecond durations (`check_tolerance`, `sniffing_timeout`) fall back to the setting's default with a diagnostic; unparseable second durations (`check_interval`, subscription `interval`) fall back to `0` with a diagnostic. |
| `fixed_domain_ttl` entries `x: 60#note`, `y: '60'`, `z: 60 ignored` | `60#note` and `'60'` are literals, `60 ignored` is two tokens | Exactly one decimal scalar is required. `y` stores 60 with `legacy-ttl-quoting`; `x` is omitted with `invalid-ttl`, and `z` with `trailing-value`. Use `60` or quoted `60`; put explanations after ` # `. |
| An unknown `policy`, `policy: mystery(...)` | any function expression | Falls back to `selector` with a diagnostic; the argument text is never echoed. |

## Node and subscription entries

| Input | dae grammar | honk |
|---|---|---|
| A tag on a share link or subscription | `ID ':' literal`; a bare literal cannot contain `:`, so links are quoted | For a bare head, the text before the first `:` is the tag unless that colon starts `://`; for a quoted head, only a `:` right after the closing quote declares a tag, so a colon in an unquoted User-Agent or comment suffix is suffix data. Links may be bare; tags and links may be quoted. In `subscription` only, a wholly quoted value with a tag inside (`'paid:https://…'`) is split after unquoting, and an entry without a tag is named after its URL host; in `node` a quoted value is the whole link (`'paid:socks5://…'` is an unknown scheme). |
| A trailing comment on an entry line | comment when `#` starts a token | A `#` after a space or tab ends the line. Inside a bare value, glued `#` is data (`…#hk1`, `?filter='hk'#token`, `/tmp/a#b`). After a closing node/link quote or one balanced subscription `(UA)` suffix, a glued `#` truncates the entry tail with `legacy-glued-hash`, but is not a lexical comment: a separated brace after it still changes block structure. Put whitespace before an intended comment. Other trailing text skips the entry with `trailing-entry-text` or `legacy-ua-boundary`. |
| `'url'(User-Agent)` after a subscription link | not in the grammar | honk extension: the parenthesised text is the User-Agent; a `#` after a space inside unquoted parentheses ends the line, so quote such a User-Agent. |
| A subscription block, `paid: {` followed by `url: …`, `ua: …`, `interval: …` on their own lines and `}` | `ID ':' '{'` is not a declaration | honk extension: the block form of a subscription; its settings are one per line like any block. |
| A bare tag with a space before the colon in `node`, `edge : 'socks5://…'` | tag `edge` | Whitespace around the colon is normalized: the node is retained with tag `edge` and an `entry-tag-normalized` informational diagnostic. `edge: …` and quoted tags remain accepted. |

## Routing

| Input | dae grammar | honk |
|---|---|---|
| Bare prefix matchers, `!geosite:cn -> proxy`, `domain:example.com -> proxy` | not function calls; rejected | Accepted as matchers (`geosite`, `geoip`, `domain`, `suffix`, `keyword`, `regex`, `full` prefixes). |
| Two arrows, `domain(x) -> proxy->backup` | rejected | The outbound is literal `proxy->backup`, with `legacy-arrow-target`. Retained for compatibility; normal target validation applies. |
| `-> proxy( must )` | call with parameter `must` | Only the exact suffix `(must)` is the must marker; `proxy( must )` is an outbound named `proxy( must )`. |
| Whitespace before the parentheses, `dport (443) -> proxy` | accepted | Located `unknown-traffic-predicate` error. Remove whitespace before matcher parentheses. |
| An unknown matcher in a conjunction, `dport(443) && domian(x) -> direct` | accepted by the grammar; validation is outside it | Located `unknown-traffic-predicate` error, also for negated terms. Correct the matcher; no term is silently discarded. |
| Arguments with several colons, `dip(2001:db8::/32)`, `mac(00:11:22:33:44:55)` | not literals; quote them | Kept whole: only a recognised `prefix:` (`geosite:`, `geoip:`, `domain:`, `suffix:`, `keyword:`, `regex:`, `full:`) is split at its colon. |

## DNS

| Input | dae grammar | honk |
|---|---|---|
| Unquoted `//` in a request or response rule | not a comment | `//` is data, never a comment. Trailing slash-comment text such as `-> asis // note` omits the malformed rule with `legacy-slash-comment`; quoted slashes remain literal. Replace DNS trailing `//` comments with `#`. |
| `#` in a request or response rule, `qname(a#b) -> reject # note` | `a#b` is a literal, `# note` a comment | Only an unquoted token-head `#` starts a comment, after a space or tab. The pattern remains `a#b` and the action is `reject`; changed old reading emits `legacy-dns-hash`. Keep literal glued hashes; separate comments with whitespace outside quotes. |
| `->` in a request or response rule | one arrow | The rule splits at the first unquoted `->`; further arrows stay in the action with `legacy-arrow-target`. The whole action is lowercased and must match a declared upstream exactly: `MixedCase` selects `mixedcase`, not a declaration named `MixedCase`. This action/reference namespace is unchanged. |
| A matcher call split across lines, `qname(` newline `a.example) -> reject` | whitespace, newlines included, is skipped | DNS never assembles lines. Each incomplete nonblank line is omitted with located `incomplete-dns-rule`, so this example produces two warnings. Put the DNS call and action on one line. An unterminated quote has one lexical diagnostic, not an additional incomplete-line warning; recovery requires every open block to close outside quoted data. |
| An upstream with an outbound, `u: 'udp://1.1.1.1:53' -> proxy` or `u: 'udp://1.1.1.1:53' outbound: proxy` | the arrow form is rejected (a declaration cannot carry `->`); the `outbound: proxy` form is two adjacent declarations | honk extension: both forms make upstream `u` dial through outbound `proxy`; both suffixes are read only outside quoted URI data. |
| Text after a matcher call, `dport(443)junk -> proxy`, `qname(a.example)junk -> reject` | rejected: the arrow must follow the call | Traffic rejects the configuration with located `trailing-matcher-text`; DNS warns and omits the whole rule. Remove trailing matcher text. |
| A trailing comment on an upstream line, `v: 'udp://8.8.8.8:53' # note` | comment | An unquoted token-head `#` starts a comment, so the address is `8.8.8.8:53`; the changed interpretation emits `legacy-upstream-comment`. Use ordinary trailing `#` comments; quotes protect address data. |
| `->` or `outbound:` inside a quoted upstream URL | data | Only unquoted descriptor suffixes select detours; `'https://dns.example/q?x=outbound:proxy#frag'` stays one URI. A changed old split emits `legacy-upstream-separator`; put the detour outside URL quotes. |
| `qtype(...)` | function arguments | Names `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`, `SOA`, `SRV`, `HTTPS`, `SVCB`, `ANY`, `*` (case-insensitive) or decimal `u16`; unknown names emit `invalid-qtype` and omit the whole rule, including mixed or negated lists. Correct unknown names or use their numeric code. Explicit `qtype()` remains match-nothing; `qtype('a,aaaa')` still selects both types with `legacy-quoted-list`. Prefer bare or individually quoted items. |

## Groups

| Input | dae grammar | honk |
|---|---|---|
| `group('hk,jp')` | one literal | Two subgroup tags, split on `,` and `\|`. |
| `filter: group()` | call without parameters | Retained as an explicit empty contribution through serde and refresh, with `empty-subgroup`. Remove the filter for all nodes; explicit `group()` now selects none. |

## Sections and includes

| Input | dae grammar | honk |
|---|---|---|
| Unknown content in `experimental` | any declaration | Unknown outer settings and unsupported legacy `udp_nfqueue` content, including nested blocks, are errors. Unknown scalar keys inside `clash_api` and `cache_file` receive `unknown-key` and are ignored; this forward-compatibility boundary does not weaken NFQUEUE validation. |
| Unknown nested blocks in `global`, `dns`, `routing`, group settings, or recognized experimental children | any expression | One `unknown-block` warning at the header; skip the complete balanced subtree, including DNS child contexts. Descendant settings and rules no longer leak into the parent. Move known settings to their documented block level. |
| Node/subscription wrappers and nested subscription-setting wrappers | not a separate wrapper feature | Retained bounded compatibility traversal, with `legacy-wrapper` at each wrapper. Arbitrary names at group root are real groups, not wrappers. Wrapper compatibility will be reviewed after the first PR2 release. |
| Unknown root statements and scalar keys | arbitrary identifiers | Warn and omit after structure recognition; unknown root blocks are skipped as complete subtrees. Names of groups, entry tags, upstreams and TTL owners are dynamic names, not unknown schema keys. Traffic lines without arrows are diagnosed and omitted unless they declare a fallback. |
| `include { … }` | a block like any other | Patterns expand only on file loading, with the ordering and confinement rules in the [configuration guide](../configuration.md); string parsing checks structure without opening files. Adjacent quoted paths such as `'first.dae''quoted # name.dae'` retain quoted hashes and braces during initial token acquisition, in both modes. Every quote must close on its physical line. Only token-head `#` starts a comment; `absolute.dae#note` is a literal pattern with `legacy-include-hash`, and normal `.dae` filtering still applies. |
