## Codex, three runs

| Flaw | codex-1 | codex-2 | codex-3 |
|---|---|---|---|
| F01 | FOUND | FOUND | FOUND |
| F02 | FOUND | FOUND | FOUND |
| F03 | FOUND | FOUND | FOUND |
| F04 | FOUND | FOUND | FOUND |
| F05 | FOUND | FOUND | FOUND |
| F06 | FOUND | FOUND | FOUND |
| F07 | FOUND | FOUND | FOUND |
| F08 | FOUND | FOUND | FOUND |
| F09 | FOUND | FOUND | FOUND |
| F10 | FOUND | FOUND | FOUND |
| F11 | FOUND | FOUND | FOUND |
| F12 | FOUND | FOUND | FOUND |
| F13 | FOUND | FOUND | FOUND |
| F14 | FOUND | MISSED | FOUND |
| F15 | FOUND | FOUND | FOUND |
| P01 | MISSED | FOUND | FOUND |
| P02 | MISSED | MISSED | FOUND |
| P03 | MISSED | FOUND | FOUND |
| P04 | FOUND | MISSED | FOUND |
| P05 | MISSED | FOUND | FOUND |
| P06 | MISSED | MISSED | MISSED |
| P07 | FOUND | FOUND | FOUND |
| P08 | FOUND | FOUND | FOUND |
| P09 | FOUND | FOUND | FOUND |
| P10 | FOUND | MISSED | MISSED |
| P11 | FOUND | FOUND | FOUND |
| P12 | FOUND | FOUND | FOUND |
| P13 | PARTIAL | FOUND | FOUND |
| P14 | MISSED | MISSED | MISSED |
| P15 | MISSED | FOUND | FOUND |

| Output | Found | Partial | Missed | Verdict | Finding units | Lead units | Flagged false positive units | Precision (flagged) |
|---|---|---|---|---|---|---|---|---|
| codex-1 | 22 | 1 | 7 | NOT READY | 73 | 11 | 1 (NP3) | 0.957 |
| codex-2 | 24 | 0 | 6 | NOT READY | 104 | 8 | 2 (NP3) | 0.938 |
| codex-3 | 27 | 0 | 3 | NOT READY | 92 | 22 | 1 (NP3) | 0.968 |

Stability over 3 outputs: 21 of 30 flaws have the same status in every output (share 0.7). Verdicts: NOT READY, NOT READY, NOT READY; verdict stable: yes. Unstable: F14, P01, P02, P03, P04, P05, P10, P13, P15.

## Codex, Free scope

| Flaw | codex-1 | codex-2 | codex-3 |
|---|---|---|---|
| F01 | FOUND | FOUND | FOUND |
| F02 | FOUND | FOUND | FOUND |
| F03 | FOUND | FOUND | FOUND |
| F04 | FOUND | FOUND | FOUND |
| F05 | FOUND | FOUND | FOUND |
| F06 | FOUND | FOUND | FOUND |
| F07 | FOUND | FOUND | FOUND |
| F08 | FOUND | FOUND | FOUND |
| F09 | FOUND | FOUND | FOUND |
| F10 | FOUND | FOUND | FOUND |
| F11 | FOUND | FOUND | FOUND |
| F12 | FOUND | FOUND | FOUND |
| F13 | FOUND | FOUND | FOUND |
| F14 | FOUND | MISSED | FOUND |
| F15 | FOUND | FOUND | FOUND |

| Output | Found | Partial | Missed | Verdict | Finding units | Lead units | Flagged false positive units | Precision (flagged) |
|---|---|---|---|---|---|---|---|---|
| codex-1 | 15 | 0 | 0 | NOT READY | 73 | 11 | 2 (NP3) | 0.889 |
| codex-2 | 14 | 0 | 1 | NOT READY | 104 | 8 | 2 (NP3) | 0.905 |
| codex-3 | 15 | 0 | 0 | NOT READY | 92 | 22 | 1 (NP3) | 0.952 |

Stability over 3 outputs: 14 of 15 flaws have the same status in every output (share 0.933). Verdicts: NOT READY, NOT READY, NOT READY; verdict stable: yes. Unstable: F14.

## Deterministic, three runs

| Flaw | det-1 | det-2 | det-3 |
|---|---|---|---|
| F01 | MISSED | MISSED | MISSED |
| F02 | FOUND | FOUND | FOUND |
| F03 | MISSED | MISSED | MISSED |
| F04 | MISSED | MISSED | MISSED |
| F05 | FOUND | FOUND | FOUND |
| F06 | MISSED | MISSED | MISSED |
| F07 | FOUND | FOUND | FOUND |
| F08 | FOUND | FOUND | FOUND |
| F09 | MISSED | MISSED | MISSED |
| F10 | FOUND | FOUND | FOUND |
| F11 | MISSED | MISSED | MISSED |
| F12 | FOUND | FOUND | FOUND |
| F13 | MISSED | MISSED | MISSED |
| F14 | MISSED | MISSED | MISSED |
| F15 | FOUND | FOUND | FOUND |
| P01 | MISSED | MISSED | MISSED |
| P02 | MISSED | MISSED | MISSED |
| P03 | MISSED | MISSED | MISSED |
| P04 | MISSED | MISSED | MISSED |
| P05 | MISSED | MISSED | MISSED |
| P06 | MISSED | MISSED | MISSED |
| P07 | MISSED | MISSED | MISSED |
| P08 | MISSED | MISSED | MISSED |
| P09 | FOUND | FOUND | FOUND |
| P10 | MISSED | MISSED | MISSED |
| P11 | MISSED | MISSED | MISSED |
| P12 | MISSED | MISSED | MISSED |
| P13 | MISSED | MISSED | MISSED |
| P14 | MISSED | MISSED | MISSED |
| P15 | MISSED | MISSED | MISSED |

| Output | Found | Partial | Missed | Verdict | Finding units | Lead units | Flagged false positive units | Precision (flagged) |
|---|---|---|---|---|---|---|---|---|
| det-1 | 8 | 0 | 22 | none | 15 | 0 | 0 | 1 |
| det-2 | 8 | 0 | 22 | none | 15 | 0 | 0 | 1 |
| det-3 | 8 | 0 | 22 | none | 15 | 0 | 0 | 1 |

Stability over 3 outputs: 30 of 30 flaws have the same status in every output (share 1). Verdicts: none, none, none; verdict stable: no. Unstable: none.
