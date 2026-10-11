# Phase 1 engine on the demo, 2026-10-10

The deterministic engine (no model) was run on a scratch clone of `hullproof-demo` at commit 3e7c205 ("Correct the answer key"), three times, and scored with `bench/score.ts` against the private copy of the demo answer key, which lists requirement IDs for every flaw (the `DEMO-ANSWER-KEY.md` published in the hullproof-demo repository shows none for the Pro flaws) and `bench/keys/demo-classes.json`, the same key and class file as the Phase 0 baseline. The demo repository itself was only read; all output went to a scratch folder.

## How it was run

```
git clone ../hullproof-demo <scratch>/demo
node src/cli.ts scan   <scratch>/demo --out <scratch>/runN     # N = 1, 2, 3
node src/cli.ts report <scratch>/demo --out <scratch>/runN
node src/cli.ts gate   <scratch>/demo --out <scratch>/runN
node bench/score.ts --key <path to the private demo answer key> --classes bench/keys/demo-classes.json \
  findings=<run>/<commit>/report.findings.md report=<run>/<commit>/report.md
```

Defaults: Pro edition, stage LAUNCH (the demo has no `docs/security/STAGE.md`), network off. Tools on this machine: Semgrep 1.176.0 and Gitleaks 8.30.1 ran; OSV Scanner was skipped (network not allowed); Trivy was skipped (no infrastructure files). The scanner adapters used were the scanner agent's working copy of `src/scanners/` and `rules/` on this date, not yet committed when these runs were made, with the engine's own Semgrep rules in `rules/semgrep/`.

## Result

| Output | Found | Partial | Missed | Free flaws found (of 15) | Verdict | Flagged false positives |
|---|---|---|---|---|---|---|
| Findings record (`report.findings.md`), each of the 3 runs | 21 | 1 | 8 | 13 | none (records carry no verdict) | 0 |
| Report (`report.md`), run 1 | 21 | 0 | 9 | 13 | NOT READY | 0 |
| Phase 0 baseline, deterministic row (Semgrep and Gitleaks only) | 8 | 0 | 22 | 7 | none | 0 |

Flaws not found by the findings record: F03 (export route with no authentication), F14 (prompt injection into tool calls), P10 (no model input, output or time caps), P11 (upload size and type), P12 (open redirect), P13 (no audit record for admin actions), P14 (no self service account deletion), P15 (unbounded page size). P09 (write all CI token) is PARTIAL: it was found, but its requirement is a GROWTH requirement, so at the default LAUNCH stage it is reported as a lead outside the run's scope and never reaches the gate. In `report.md` the same lead is not counted, which is the one flaw where the two outputs differ.

What moved from the baseline's 8: the engine checks found F01 (row level security), F04 (read by id without owner), F06 (webhook fails open), F09 (admin role check), F11 (token in logs), F13 (AI tool without owner check), and P01 to P08 (rate limit, password length, cookie flags, security headers, stack trace, unsupported Next.js line, lockfile and CI install, actions pinned by tag). F02, F05, F07, F08, F10, F12 and F15 were found by the Semgrep and Gitleaks hits, as in the baseline, and F10, F12 and F15 by an engine check as well.

The gate exits 1 with NOT READY on every run: all 110 BLOCKER and CRITICAL requirements in scope are open (18 FAIL, 92 NOT ASSESSED), G-1, G-2, G-7 (OSV Scanner did not run) and G-8 are not met, and the findings record is marked incomplete because no verifier ran.

## Stability

The three runs wrote byte identical files: the sha256 over every file in the scan folder except `run.json` and `scan/run.json` (timings) was `004c826d2e1e3745dc1835f829335620de88425bf8055fd56c0e03a218a0a71b` for each run, including `report.md`, and the gate output was identical (sha256 `a49225749d98a4c46f643e0085a5806a493caf502a504320c0fe35d023107bad`). Per flaw status was the same in all three findings records (30 of 30).

## Limits of this number

1. The checks were written while reading this demo and its answer key, so 21 is an upper estimate of what they catch on an app they have not seen. The measurement on public targets in `bench/PHASE1-INDEPENDENT-2026-10-10.md` is the honest measure.
2. The checks are pattern based. Each finding is SUSPECTED until a person or a verifier confirms it, and the report says so.
3. The scorer counts a finding on the right file with the right defect words; it does not check that the whole compound flaw is covered (`docs/SCORING.md`, section 8).
4. OSV Scanner did not run (network off), so dependency advisories are not in this number.
