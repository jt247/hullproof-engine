# How the benchmark scorer matches findings

This describes `bench/score.ts`. The scorer is strict and deterministic on purpose: the same inputs give the same bytes out, and no model runs in it. Every rule below has a unit test in `bench/score.test.ts`.

## 1. Inputs

1. An answer key in the demo key format: Markdown tables under a heading containing "Free edition" and a heading containing "Pro only", one row per flaw, with the flaw id, the description, the locations as `` `path:line` `` (several joined by `<br>`), and the requirement IDs with severity and edition.
2. A class file (`bench/keys/<key>-classes.json`). The demo key format does not say what kind of defect each flaw is in a form a program can test, so the class file adds, per flaw, a short list of case insensitive patterns, and lists what the key says is done correctly on purpose (`not_planted`), each with its files and patterns. Patterns for flaws that share a file are written to tell them apart.
3. One or more audit outputs: a findings record file (the `hullproof-findings` block, or a block tagged `json` that holds `records`, because one audit run wrote its records that way), a Markdown report, or plain text.

## 2. Units

The output is cut into units, and every match happens inside one unit.

1. Findings record: each record is a unit. `fail` is a finding. `routed` and `observation` are leads. `refuted` is ignored. Files come from `evidence`, `trace`, `where` and `preventing_layer`, and from any path in the record text.
2. Markdown or text: a heading that names a finding id such as `F-12` makes one unit of everything up to the next heading. Otherwise each list item, each table row and each paragraph is a unit. Fenced code is skipped.
3. A unit is skipped when any heading above it, or the paragraph that leads its list, names a section that does not report findings: passed controls, coverage ledger, refuted, dropped, next actions, fix order, recommended, limits, tool output, provenance, strengths, scorecard, evidence hashes, raised by, merge record, disagreements, discovery, owner questions, surface coverage, header, system profile, gates, applicability, verifier outcomes. A unit that says `PASS (static)`, `NOT APPLICABLE` or `REFUTED` is skipped.
4. A unit that says `NOT ASSESSED`, `NEEDS DYNAMIC TEST`, `NEEDS DASHBOARD`, `NEEDS BUILD`, `ASK OWNER` or `UNKNOWN`, or that sits under a heading about leads, routed items or unverified controls, is a lead. Everything else is a finding.

## 3. Files

A path in a unit counts as a key file when it equals a file named in the key (or in `not_planted`), or is a suffix of exactly one such file on a folder boundary. `payfake/route.ts` resolves; `route.ts` alone matches many files and resolves to nothing. Line numbers are not required. The JSON output records whether a cited line is within 3 lines of a key line (`line_hit`), for information only.

## 4. Defect class

A unit matches a flaw's class when it names at least one of the flaw's requirement IDs from the key, or its text matches one of the flaw's patterns.

## 5. Status per flaw

1. FOUND: a finding unit cites one of the flaw's files and matches its class.
2. PARTIAL: a finding unit matches the class and cites no file named in the key (it cites none, or only files outside the key), or a lead unit cites one of the flaw's files and matches its class.
3. MISSED: anything else, including a finding about the right defect placed on a key file that belongs to a different flaw.

## 6. Precision

The key does not list every true finding, so the scorer reports a flagged precision: finding units that match a planted flaw (as in FOUND or the no file case of PARTIAL), against finding units that match a `not_planted` item (file and pattern) and no planted flaw. Units that match neither are counted as unmatched and not judged. This is an upper bound and is labelled that way everywhere.

## 7. Verdict and stability

The verdict is the first of `NOT READY`, `READY WITH CONDITIONS` or `READY` found in the output, else `none`. A findings record carries no verdict. Given N outputs of the same commit, stability is the share of flaws whose status is the same in all N, plus whether all N verdicts are equal and not `none`.

## 8. Known limits of the method

1. It cannot tell "right area, vague defect" from "wrong defect". A careful reader can. Such cases score MISSED here.
2. It does not check that every part of a compound flaw is covered (upload size and upload type). A finding that covers one part on the right file scores FOUND.
3. A requirement ID on the right file counts as the class even when the finding describes a different defect in its text. Merged findings therefore credit every flaw whose ID they list.
4. Units are cut by layout. A report that repeats a finding in a summary list and in its own section is counted twice in the precision units. Flaw status is not affected.
5. Class patterns are written by a person who has read the key. They are part of the benchmark and are versioned with it; a pattern change can change a score, so the class file sits in git and every baseline names its commit.
