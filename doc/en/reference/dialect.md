# The honk dialect of dae configuration

honk reads dae's configuration syntax, but it is a dialect: where honk and dae read the same text differently, honk's reading is the contract and these differences are not adjusted to follow dae. This page lists every known difference so that a file written for one can be checked against the other. The "dae" column states only what dae's grammar (`dae_config.g4`) says; dae's value conversion is not described here. The "honk" column is what the parser does on the commit this page was written against (`main` at `66fc946`, after #190): every example was loaded through `parse_dae_config` and the result recorded, so any row can be re-checked by loading the same text.

## Lexical rules

| Input | dae grammar | honk |
|---|---|---|
| `#` inside a bare value, `log_file: /tmp/a#b` | `#` is a safe character inside a bare literal: the value is `/tmp/a#b` | Scalar settings cut at the first `#` outside quotes, glued or not: `/tmp/a`. Quote the value to keep a `#`. |
| `#` glued to an outbound name in a routing rule, `domain(x) -> proxy#c` | one bare literal, `proxy#c` | Routing statements cut at any unquoted `#`: the outbound is `proxy`. |
| `/* … */` | block comment, skipped | Not recognised. The text is not skipped: `/* log_level: debug */` is a line whose key is `/* log_level`, which is unknown and ignored, but braces or a valid `key: value` inside such a span are read as configuration. |
| `[key: value]` after a declaration, `filter: name(x) [add_latency: -500ms]` | accepted as an annotation | Not recognised; the filter is reported as unparseable and ignored. honk has no per-node latency bias. |
| An unmatched quote in a scalar, `log_file: /tmp/don't` | lexer error | Ordinary text: `/tmp/don't`. A routing statement with an unterminated quote is an error (`routing line N: unterminated quote`). |
| Braces inside quotes, `secret: 'a}b'` | data | Data. Braces inside an unquoted trailing comment are still structure: keep such comments on their own line. |
| Block opener without a space, `global{ … }` | whitespace is skipped, so this is a block | Error ``unexpected `{` ``: an inline opener needs whitespace before `{`; a line-final `{` does not. |
| An extra `}`, or an empty file | an extra `}` is rejected; empty or comment-only input is accepted | An extra `}` is ignored with a diagnostic; a file with no `{` and `}` fails with `not a dae config file`. |
| Block names, `123 {`, `香港 {`, `Hong Kong {` | a block name is one `ID` | A line-final `{` names a block with any text before it. |
| Two declarations on one line, `global { log_level: debug log_file: x }` | whitespace-separated declarations | One declaration: `log_level` is `debug log_file: x`. One `key: value` per line; one-line blocks hold one statement. |
| The opening brace on the next line, `global` newline `{` | whitespace, newlines included, is skipped | Error ``unexpected `{` at line 2``: a block opens on the line that carries its `{`. Only a top-level `include` may put `{` on the following line. |

## Scalars and lists

| Input | dae grammar | honk |
|---|---|---|
| A bare value with colons, `bind: 127.0.0.1:53` | not one literal; must be quoted | Accepted bare: the value is everything after the first `:`. |
| A call-shaped value, `client_subnet: auto(9.9.9.9)` | function expression | The text `auto(9.9.9.9)` is the value; the setting parses it itself. |
| Quoted list items, `lan_interface: 'eth0', 'eth1'` | two literals | For interface lists the quotes are removed from the whole value before it is split on commas, and items are not unquoted, so the items become `eth0'` and `'eth1`. `tcp_check_url` and `udp_check_dns` additionally strip single quotes per item. Write list items bare: `lan_interface: eth0, eth1`. |
| Booleans `t`, `y`, `f`, `n` | bare literals | Lenient settings (case-insensitive): `true`, `yes`, `1`, `on` are true; `false`, `f`, `no`, `n`, `0`, `off`, `t`, `y` are false; any other spelling is false with a diagnostic. `global.nfqueue_enable` and the legacy `experimental.udp_nfqueue.enabled` are strict: `t`, `y`, `f`, `n` and unknown spellings are errors. |
| Marks, `so_mark_from_dae: 0x10` and `so_mark_from_dae: 10` | bare literals | Both are read as hexadecimal: 16 and 16. An unparseable mark falls back to 0 with a diagnostic. |
| Fractional seconds in a millisecond setting, `check_tolerance: 1.5s` | bare literal | 1500 ms. Unparseable millisecond durations (`check_tolerance`, `sniffing_timeout`) fall back to the setting's default with a diagnostic; unparseable second durations (`check_interval`, subscription `interval`) fall back to `0` with a diagnostic. |
| `fixed_domain_ttl` entries `x: 60#note`, `y: '60'`, `z: 60 ignored` | `60#note` and `'60'` are literals, `60 ignored` is two tokens | `x` and `y` are reported and ignored (the value must be a bare decimal); `z` stores 60 and ignores the trailing text. |
| An unknown `policy`, `policy: mystery(...)` | any function expression | Falls back to `selector` with a diagnostic; the argument text is never echoed. |

## Node and subscription entries

| Input | dae grammar | honk |
|---|---|---|
| A tag on a share link or subscription | `ID ':' literal`; a bare literal cannot contain `:`, so links are quoted | The text before the first `:` is the tag unless that colon starts `://`; links may be bare; tags and links may be quoted. In `subscription` only, a wholly quoted value with a tag inside (`'paid:https://…'`) is split after unquoting, and an entry without a tag is named after its URL host; in `node` a quoted value is the whole link (`'paid:socks5://…'` is an unknown scheme). |
| A trailing comment on an entry line | comment when `#` starts a token | A `#` after a space or tab ends the line; in a bare link a glued `#` stays in the link (`…#hk1`, `?filter=(hk)#token`). A tagless quoted node uses only the quoted span, whatever follows it. After a quoted subscription URL, a `#` right after the closing quote or after the `(UA)` suffix is also a comment. |
| `'url'(User-Agent)` after a subscription link | not in the grammar | honk extension: the parenthesised text is the User-Agent; a `#` after a space inside unquoted parentheses ends the line, so quote such a User-Agent. |
| A subscription block, `paid: {` followed by `url: …`, `ua: …`, `interval: …` on their own lines and `}` | `ID ':' '{'` is not a declaration | honk extension: the block form of a subscription; its settings are one per line like any block. |
| A bare tag with a space before the colon in `node`, `edge : 'socks5://…'` | tag `edge` | The whole line is taken as the link, rejected by the share-link parser, and skipped with a message on stderr; the rest of the file loads. Write `edge: …` or quote the tag. |

## Routing

| Input | dae grammar | honk |
|---|---|---|
| Bare prefix matchers, `!geosite:cn -> proxy`, `domain:example.com -> proxy` | not function calls; rejected | Accepted as matchers (`geosite`, `geoip`, `domain`, `suffix`, `keyword`, `regex`, `full` prefixes). |
| Two arrows, `domain(x) -> proxy->backup` | rejected | The outbound is the literal text `proxy->backup`. |
| `-> proxy( must )` | call with parameter `must` | Only the exact suffix `(must)` is the must marker; `proxy( must )` is an outbound named `proxy( must )`. |
| Whitespace before the parentheses, `dport (443) -> proxy` | accepted | The matcher is not recognised and the condition is dropped: the rule loads with no port condition. Write `dport(443)`. |
| An unknown matcher in a conjunction, `dport(443) && domian(x) -> direct` | accepted by the grammar; validation is outside it | The unknown matcher is dropped and the rule loads as `dport(443) -> direct`. Check spelling; see issue #161. |
| Arguments with several colons, `dip(2001:db8::/32)`, `mac(00:11:22:33:44:55)` | not literals; quote them | Kept whole: only a recognised `prefix:` (`geosite:`, `geoip:`, `domain:`, `suffix:`, `keyword:`, `regex:`, `full:`) is split at its colon. |

## DNS

| Input | dae grammar | honk |
|---|---|---|
| Unquoted `//` in a request or response rule | not a comment | Comment, taking precedence over `#`; a quoted `//` is data. |
| `#` in a request or response rule, `qname(a#b) -> reject # note` | `a#b` is a literal, `# note` a comment | Only the first `#` outside quotes is examined, and it is a comment only when preceded by a space: here it is glued, so nothing is cut and the action becomes the text `reject # note`, which is not `reject`. Put the comment on its own line. |
| `->` in a request or response rule | one arrow | The rule splits at the first unquoted `->`; further arrows stay in the action (`-> up->stream` is an upstream named `up->stream`). The whole action text is lowercased: `Reject` is `reject`, and `-> MixedCase` names an upstream `mixedcase`, which does not match an upstream declared as `MixedCase`. |
| A matcher call split across lines, `qname(` newline `a.example) -> reject` | whitespace, newlines included, is skipped | Request and response rules are read line by line; neither line is a complete rule, so the rule is dropped without a diagnostic. |
| An upstream with an outbound, `u: 'udp://1.1.1.1:53' -> proxy` or `u: 'udp://1.1.1.1:53' outbound: proxy` | the arrow form is rejected (a declaration cannot carry `->`); the `outbound: proxy` form is two adjacent declarations | honk extension: both forms make upstream `u` dial through outbound `proxy`. |
| Text after a matcher call, `dport(443)junk -> proxy`, `qname(a.example)junk -> reject` | rejected: the arrow must follow the call | The text after the first unquoted `)` is ignored and the matcher stands (routing and DNS rules; node filters `name(...)`/`subtag(...)` instead require the call to end the expression). |
| A trailing comment on an upstream line, `v: 'udp://8.8.8.8:53' # note` | comment | Not stripped: the address becomes `8.8.8.8:53' # note`. Keep upstream comments on their own line. |
| `->` or `outbound:` inside a quoted upstream URL | data | The upstream reader searches the whole line, quotes included: `'https://dns.example/q?x=outbound:proxy#frag'` becomes address `dns.example/q?x=` with outbound `proxy#frag`. Do not put these separators in an upstream URL. |
| `qtype(...)` | function arguments | Names `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `PTR`, `SOA`, `SRV`, `HTTPS`, `SVCB`, `ANY`, `*` (case-insensitive) or a decimal `u16`; an unknown name is silently omitted, and a `qtype` whose list ends up empty is kept as a condition that matches nothing. `qtype('a,aaaa')` splits the quoted text on commas. |

## Groups

| Input | dae grammar | honk |
|---|---|---|
| `group('hk,jp')` | one literal | Two subgroup tags, split on `,` and `\|`. |
| `filter: group()` | call without parameters | The empty subgroup filter is dropped; with no other `filter:` line the group falls back to every node. See issue #161. |

## Sections and includes

| Input | dae grammar | honk |
|---|---|---|
| Unknown content in `experimental` | any declaration | An unknown line directly in `experimental` is an error (`unknown experimental setting: …`); unknown keys inside `clash_api` and `cache_file` are ignored; unknown keys inside the legacy `udp_nfqueue` are errors. |
| Unknown nested blocks in `global`, `dns`, `routing` | any expression | Their lines are read as if they were at the section's level. |
| `include { … }` | a block like any other | Patterns are expanded only when a file is loaded, with the rules in the [configuration guide](../configuration.md); parsing a configuration string still scans the block's braces (an unclosed include is an error) but does not read its patterns. Inside an include block an unquoted `#` ends a pattern. |
