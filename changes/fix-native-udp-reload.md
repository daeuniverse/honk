Fixed

- Keep admitted Native ordinary UDP Direct flows on their original path across routing, mode and scoped-DNS changes while new flows use current policy; retain active or still-owned claims and reclaim eligible idle caches with exact activity checks. The claim map value grows to 40 bytes and requires a joined cold restart with matching diagnostics. TCP lifecycle and full Native acceptance remain separate.
- Skip needless periodic Native publication closure after a complete stable scan finds no retirement candidates, without weakening closed retirement or map-error handling.
