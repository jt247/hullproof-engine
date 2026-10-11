# Phase 0 stability measurement, 2026-10-10

This measures run to run stability: the same kit, the same tool and model, the same blind copy of the demo, run three times. It covers three Codex runs and three runs of the deterministic scanners. The matching method is in `docs/SCORING.md`, and the scorer and class file are unchanged since commit fa478c9.

**The Claude Code stability runs are pending.** All three were started and all three stopped at the Claude plan session limit after about 38 to 42 minutes, before any findings record or report was written. Each log holds one line saying the session limit was hit. They will be rerun by the lead after the engine work finishes, and this file will get a Claude section then. No Claude number below.

## How to reproduce the scores

```
./bench/run-stability.sh
```

It checks the inputs (the raw audit outputs, which are not published) against a list of SHA-256 sums, scores them against the demo key (the private copy of the demo answer key, which lists requirement IDs for every flaw (the `DEMO-ANSWER-KEY.md` published in the hullproof-demo repository shows none for the Pro flaws)) with `bench/keys/demo-classes.json`, and writes `bench/results/stability-2026-10-10.md` and `.json`. Two runs gave the same JSON (SHA-1 dc77e7fe).

## Setup

Each run had its own fresh workspace under the session scratchpad (`scratchpad/stab/codex-N`, `claude-code-N`). Each was built the same way: the Pro 0.3.1 zip unpacked, the demo copied without `.git` and `DEMO-ANSWER-KEY.md`, the kit folder copied into the root, the README replaced with a two line notes app description, the layout banner replaced with "Notes app.", the package description set to "Notes app", the kit installer run for the tool, `docs/security/reports` created, then `git init` and one commit.

| Tool | Git tree hash, all three workspaces |
|---|---|
| Codex | e29ab807f9ab05050f32aadb5c61d5c2ac86e709 |
| Claude Code | f44cb5eee921d858949b3c5a315dc66199d011ce |

The `src` tree is 5e0116f7 in every workspace, the same as in the baseline copies.

Two things to know about the blind copy:

1. The demo's `SECURITY.md` stayed in the copy, as it did in the earlier baseline copies. It says the flaws are deliberate and names the answer key file. The run protocol says to remove it. The brief for this run did not, so I kept the copy comparable with the baseline. The next round should decide this once and apply it to every tool.
2. `package.json` was rewritten by a JSON serializer when the description changed, so its bytes differ from the baseline copies. Only formatting and the description differ.

## Runs

| Run | Tool and model | Start (UTC) | Duration | Result |
|---|---|---|---|---|
| codex-1 | Codex CLI 0.147.0, gpt-5.6-sol, reasoning medium, read only sandbox | 01:33 | 367 s | complete, report printed |
| codex-2 | same | 01:33 | 557 s | complete, report printed |
| codex-3 | same | 01:33 | 698 s | complete, report printed |
| claude-1 | Claude Code 2.1.291, claude-opus-5-5 | 01:47 | 2505 s | incomplete: session limit, only profile and round 1 checkpoints written |
| claude-2 | same | 01:47 | 2387 s | incomplete: session limit, same |
| claude-3 | same | 01:47 | 2305 s | incomplete: session limit, same |
| det-1 to det-3 | Semgrep 1.176.0 with the 28 kit rule files, Gitleaks 8.30.1 with the kit config, on `src`, `supabase`, `.github`, `next.config.js` and `package.json` | 01:39 | 3 to 6 s each | complete |

The three Codex runs ran at the same time on one account, and so did the three Claude runs.

## Codex: results per run, all 30 flaws

| Run | Found | Partial | Missed | Free found (of 15) | Verdict | Finding units | Flagged false positive units | Flagged precision |
|---|---|---|---|---|---|---|---|---|
| codex-1 | 22 | 1 | 7 | 15 | NOT READY | 73 | 1 (NP3) | 0.957 |
| codex-2 | 24 | 0 | 6 | 14 | NOT READY | 104 | 2 (NP3) | 0.938 |
| codex-3 | 27 | 0 | 3 | 15 | NOT READY | 92 | 1 (NP3) | 0.968 |

Found: minimum 22, maximum 27, mean 24.3.

## Codex: stability

| Measure | Value |
|---|---|
| Flaws with the same status in all three runs, all 30 | 21 of 30 (0.70) |
| Of those, FOUND in all three | 19 |
| Of those, MISSED in all three | 2 (P06, P14) |
| Flaws that changed status | F14, P01, P02, P03, P04, P05, P10, P13, P15 |
| Flaws FOUND in at least one run | 28 |
| Same status in all three runs, Free scope only | 14 of 15 (0.933); only F14 changed |
| Verdict | NOT READY in all three, stable |
| Flagged false positive | NP3 (the in memory AI budget) in every run |

Per flaw:

| Flaw | codex-1 | codex-2 | codex-3 |
|---|---|---|---|
| F14 | FOUND | MISSED | FOUND |
| P01 | MISSED | FOUND | FOUND |
| P02 | MISSED | MISSED | FOUND |
| P03 | MISSED | FOUND | FOUND |
| P04 | FOUND | MISSED | FOUND |
| P05 | MISSED | FOUND | FOUND |
| P10 | FOUND | MISSED | MISSED |
| P13 | PARTIAL | FOUND | FOUND |
| P15 | MISSED | FOUND | FOUND |

All other flaws have one status in all three runs. The full table is in `bench/results/stability-2026-10-10.md`.

## Deterministic scanners: stability

| Run | Found | Partial | Missed | Free found (of 15) | Hits | Output SHA-256 |
|---|---|---|---|---|---|---|
| det-1 | 8 | 0 | 22 | 7 | 13 | 0a56bbb6... |
| det-2 | 8 | 0 | 22 | 7 | 13 | 0a56bbb6... |
| det-3 | 8 | 0 | 22 | 7 | 13 | 0a56bbb6... |

The three outputs are byte identical, so 30 of 30 flaws have the same status. There is no verdict, because the scanners do not give one. The 13 hits and the 8 found match the deterministic row of the baseline.

## Conclusions

1. Codex with kit 0.3.1 gave the same verdict, NOT READY, in all three runs. That verdict is correct for this demo.
2. Codex found between 22 and 27 of the 30 planted flaws. Nine flaws changed status between runs, eight of them Pro only flaws. On the 15 Free flaws it was close to stable: 15, 14 and 15 found.
3. A single Codex run is not a reliable measure of the kit. The 0.3.0 to 0.3.1 change seen in the baseline (24 to 25 found) is smaller than the spread between three runs of 0.3.1 here (22 to 27).
4. Together the three runs found 28 of 30. P06 and P14 were missed every time.
5. The same flagged false positive, NP3, came back in every Codex run.
6. The deterministic scanners are fully stable, byte for byte, but find 8 of 30.
7. Claude Code stability is not measured yet; see the pending note at the top.

## Raw outputs

Kept with a `SHA256SUMS` file, not published:

| File | Source |
|---|---|
| codex-1.out.md, codex-2.out.md, codex-3.out.md | `scratchpad/stab/codex-N.out.md`, the final report each Codex run wrote with `-o` |
| deterministic-1.md, deterministic-2.md, deterministic-3.md | `scratchpad/stab/det-N.md`, made from the Semgrep JSON and Gitleaks JSON of each run |

Secret check: before copying, every candidate file was searched for the demo's webhook signing secret literal from `src/lib/config.ts`, by count of the full value and of its first 8 characters, without printing it. The three Codex reports, the three deterministic outputs and the Semgrep and Gitleaks JSON files have zero matches. The three Codex session logs (`scratchpad/stab/codex-N.log`) contain the full value, because the agent read `config.ts` and the log echoes tool output, so they were not copied. The copied files were checked again after copying. The Claude logs hold only the session limit line and were not copied; the Claude checkpoint files stay in their workspaces and were not scored.
