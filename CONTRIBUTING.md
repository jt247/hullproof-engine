# Contributing

Thank you for looking at the Hullproof Engine. This file says what helps and how to send it.

## Before you start

Open an issue first for anything bigger than a small fix, so we can agree on the direction before you spend time on it. Bugs, a wrong or missing stack detection and a false positive in a rule are all useful issues. For a wrong detection, include the file and the line that shows the stack, and the `stack.json` the engine wrote.

Report a security problem in the engine privately, as described in SECURITY.md.

## What the engine keeps true

1. It is deterministic. The same commit, the same engine and the same tool versions give the same bytes. No model runs in it, and nothing in the output depends on the clock or on the order files happen to be read.
2. It never installs a scanner and never reaches the network unless `--allow-network` is given.
3. It never runs code from the repository it scans.
4. A check or a rule says what it saw and where. It does not claim that a project is secure.

A change that breaks one of these needs a very good reason.

## How to work on it

You need Node 22.18 or later. The source is TypeScript that Node runs directly, so there is no build step.

```
npm install
npm test
npm run typecheck
```

Some tests need a Hullproof kit. Point `HULLPROOF_KIT` at the `kit` folder of a checkout of https://github.com/jt247/hullproof-free, or put that checkout next to this repository in a folder called `hullproof-free`. Tests that need a scanner skip themselves when the scanner is not installed.

## Adding a rule or a check

1. A Semgrep rule goes in `rules/semgrep/` with a fixture in `test/fixtures/rules/` that shows a hit and a non hit. `test/rules.test.ts` runs them with `semgrep --test`.
2. An executable check is a JSON file in `checks/` (or a TypeScript check in `src/checks/code/`) with a `pass` and a `fail` fixture folder in `test/fixtures/checks/`. Every check must fail on its fail fixture and must not fail on its pass fixture.
3. A new taint rule (`taint-*.yaml`) starts as a lead. See the README section on how much a rule is trusted.

## Style and writing

Keep functions small and files focused. Write plain English in messages, comments and documents, without marketing words. Do not claim more than a test or a measurement shows.

## Licence

By sending a contribution you agree that it is licensed under the Apache License 2.0, the same as the rest of the repository.
