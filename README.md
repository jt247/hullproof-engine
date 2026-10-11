# Hullproof Engine

The Hullproof Engine reads a repository built with AI coding tools, works out what the app is made of, runs proven scanners and executable checks against it, and writes a report and a release gate result. The same commit, the same engine and the same tool versions give the same bytes, every run.

It is made for people who build apps with AI coding tools and want a repeatable answer to one question: what does this repository show, before I ship it?

It is not a general purpose scanner, and it does not wrap a language model. No model runs anywhere in it. It is a deterministic engine in five steps:

1. Discover the stack. It finds the languages, frameworks, data stores, auth and payment providers, AI providers, hosting, cloud and CI setup from the files, and records the file and line that proved each one. What it sees and cannot name is listed as unknown. It does not guess.
2. Map the code. It lists every entry point it can find (HTTP routes, webhooks, server actions, jobs, AI tools and similar), with the file and line of each, what protects it (a session read, a role check, an owner filter, a signature check, a rate limit, a schema) and which data stores and outbound calls it touches. Each fact carries a confidence. Where it cannot read a language, the report says the map is incomplete for it.
3. Run the scanners you already have installed (Semgrep, Gitleaks, OSV Scanner and Trivy) and its own executable checks, which read the repository files and the code map and say exactly what they saw and where.
4. Map every result to a Hullproof requirement ID, using the requirements in the Hullproof Free kit.
5. Write a report in plain English and a release gate result. A requirement that nothing settled is listed as NOT ASSESSED with what would settle it. It is never reported as a pass.

The engine is open under the Apache License 2.0. Release 0.4.0 comes as a zip on the GitHub releases page of this repository.

## Requirements

1. Node 22.18 or later. Node runs the TypeScript source directly, so there is no build step and nothing to install to run the engine. It has no runtime dependencies.
2. Git, and a repository with at least one commit. Results are tied to the commit.
3. The Hullproof Free kit from https://github.com/jt247/hullproof-free. The engine reads the requirement IDs and severities from the kit's controls file, runs the kit's release gate, and checks its own findings record with the kit's validator. The engine does not copy any of these files.
4. Any of these scanners that you want used: Semgrep, Gitleaks, OSV Scanner and Trivy. The engine detects what is on your machine and never installs anything. A scanner that is missing is listed in the report as not run, and the requirements it would have settled stay NOT ASSESSED. The versions the engine was tested with are Semgrep 1.176.x, Gitleaks 8.30.x, OSV Scanner 2.6.x and Trivy 0.75.x. A different version still runs, and the report marks it as not a tested version.

## Quick start

Get the engine and the Free kit in two separate folders, outside the project you want to check. Clone them, or unzip the release zips.

```
git clone https://github.com/jt247/hullproof-engine.git
git clone https://github.com/jt247/hullproof-free.git
```

Then, from the root of your project:

```
ENGINE=/path/to/hullproof-engine
KIT=/path/to/hullproof-free/kit

node $ENGINE/src/cli.ts discover .
node $ENGINE/src/cli.ts map .
node $ENGINE/src/cli.ts scan . --kit $KIT --edition free --rule-pack $KIT/tools/hullproof/rules
node $ENGINE/src/cli.ts report .
node $ENGINE/src/cli.ts gate .
```

What each command does:

1. `discover` writes `.hullproof/stack.json`. It only reads files. It runs no program and uses no network.
2. `map` writes `.hullproof/codemap.json`, the entry points of the repository and what protects each one. It needs no kit and no scanner, and `scan` runs it for you.
3. `scan` runs discovery, the code map, the scanners and the checks, and writes everything for the current commit to `.hullproof/<commit>/`. It refuses a repository whose git configuration could run code. The `--rule-pack` option adds the Semgrep rules of the Free kit to the rules the engine carries itself. Leave it out and only the engine's own rules run.
4. `report` writes `report.md` in that folder.
5. `gate` applies the release gate and prints NOT READY, READY WITH ACCEPTED RISK or READY.

`report` and `gate` find the kit the scan used, so `--kit` is only needed on `scan`. Add `.hullproof/` to your `.gitignore`, because the report lists failures that someone could exploit.

A scan of files alone ends NOT READY on every project. Most BLOCKER and CRITICAL requirements are settled by evidence that is not in the code, such as a provider dashboard export or a test against the running app. The gate section below says how that evidence is supplied.

You can also copy the kit into your project, the way the Free kit's own install does (`cp -Rn path/to/hullproof-free/kit/. .`). The engine then finds it without `--kit`. It also scans the kit's own files as part of your project, which adds findings from the kit's test samples, so keeping the kit in a separate folder gives a cleaner report.

## How the engine finds the kit

In this order:

1. The `--kit` option.
2. The `HULLPROOF_KIT` environment variable.
3. The scanned repository itself, when the kit is installed in it.
4. A folder called `hullproof-free/kit` next to the engine folder.

A folder counts as a kit when it holds `docs/hullproof/security-controls.json`. `--edition free|pro` picks which requirements are in scope. With the Free kit use `free`. `--stage LAUNCH|GROWTH|SCALE` picks the stage, and the default is `docs/security/STAGE.md` in your project, else LAUNCH.

## What it writes

`scan` writes these files to `.hullproof/<commit>/` (or to `--out DIR/<commit>/`):

| File | What it holds |
|---|---|
| `stack.json` | The discovered stack, with evidence |
| `scan/<tool>.json` and `.meta.json` | Each scanner's hits mapped to requirement IDs, and how the scanner was run |
| `checks.json` | The result of every executable check |
| `codemap.json` | The code map: entry points, gates, Supabase and Firebase maps, and which languages were not fully read |
| `results.json` | One row per requirement in scope, in the form the kit's gate reads |
| `report.findings.md` | The findings record, validated with the kit's validator before the scan ends |
| `surface.json`, `scan.json` | What was covered, and the run settings |
| `report.md` | The report (written by `report`) |

Every file except `run.json` and `scan/run.json` is byte identical for the same commit, engine, kit files and tool versions. Tool paths and times live only in the two `run.json` files.

The report lists findings by severity with the fix in plain words, then what could not run and why, then every requirement that nothing settled, as NOT ASSESSED, with what settles it.

## The code map

`codemap.json` is written by `hullproof map` and by `scan`. It holds:

1. Every entry point the engine found, with its kind (HTTP route, webhook, server action, page, AI tool, job, GraphQL resolver, RPC procedure, message consumer), framework, file and line, method and path, and a confidence.
2. What protects each one: a session read, a role check, an owner filter, a signature check, a rate limit, a schema, an audit record. Each protection says where it sits (the handler, a wrapper, the router, a middleware or guard, or a global setting), what matched, whether a failed check stops the request, and a confidence of high, medium or low.
3. The data stores each entry point reads and writes (SQL, Prisma, Mongoose, Supabase, Django and SQLAlchemy models and others), and its outbound calls (HTTP, AI models, email, payments, processes and redirects), with whether the value comes from the request.
4. The Supabase tables from the migration SQL (row level security, policies, grants, columns) and the Firebase rules.
5. A coverage table: for each language, whether an extractor read it (`mapped`), read it with a framework it does not know (`partly mapped`), or has no extractor yet (`not mapped`). A language that is not mapped gives no entry points, and the report says the map is incomplete for it instead of saying nothing.

The extractors are TypeScript written for this engine (no parser library, no runtime dependency). They cover:

1. Node and TypeScript: Next.js route handlers, pages and server actions, Express and the Koa, Fastify and Hono style, NestJS, tRPC, cron jobs and queue workers, Supabase edge functions.
2. Python: Flask, FastAPI, Django and REST framework, Celery and scheduler jobs.
3. Go: net/http (including the `GET /path` patterns), chi, gin, echo, fiber and gorilla/mux, with groups, `Use`, `With`, `Route` and `Mount` followed in order.
4. Ruby on Rails: `config/routes.rb` (resources, namespaces, scopes, member and collection routes, devise's `authenticate` blocks, mounted engines) joined to the controller actions, with the `before_action` filters each action runs, inherited from parent controllers and included concerns, minus `skip_before_action`.
5. PHP and Laravel: `routes/*.php` (verbs, `match`, resources, groups, prefixes, `controller()` groups, closures and invokable controllers) joined to the controller methods, with route, group and controller middleware, policies, form requests and the api throttle group.
6. Expo and React Native: Expo Router screens and API routes, the deep links in `app.json` and `app.config`, deep links handled with `Linking`, and the sign in guards in the layouts above each screen. A layout guard is a client side redirect and says so in the map; it is not a server check.

Names the vocabulary does not know: a project can list its own sign in and role helpers in `.hullproof/kit.local.json` (`{"auth_helpers": ["requireMember"], "role_helpers": ["isBillingAdmin"]}`). A call, decorator, filter or middleware with one of those names counts as a session read or a role check with medium confidence, in every language above. `codemap.json` copies the names it used, and it lists the names that look like sign in helpers and were not recognised (`config.auth_helper_candidates`) so you know what to add.

The checks that read the map are named `check.map.*`. They decide requirements a file can settle, for example that every route that changes data has a session read, that every webhook checks its signature before it uses the event, that every admin route has a role check, and that no update by id leaves out the owner. They start as leads: the report lists them with their evidence under the leads, and they never fail a requirement or hold the gate until `rules/tiers.json` records a measured precision of 0.80 or better for them. A tier entry can also carry `needs_judged`, a number of judged findings it must reach first, and the report then says how many it has and how many it needs.

The report has a section "Entry points and what protects them" with the coverage table and one row per entry point.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. For `gate`: READY or READY WITH ACCEPTED RISK |
| 1 | Open items. For `gate`: NOT READY |
| 2 | Bad input, a refused run, or a problem in the records |

## The gate and the owner file

`gate` applies conditions G-1 to G-8 of the Hullproof standard on top of the kit's own checklist gate. Evidence that no file settles goes in an owner file:

```json
{
  "audit_report": "docs/security/reports/AUDIT.md",
  "rollback": "docs/security/ROLLBACK.md",
  "results": [{"id": "SEC-DB-007", "result": "PASS", "notes": "anon query test, 2026-10-09"}],
  "acceptances": [{"id": "SEC-DB-007", "owner": "...", "approver": "...", "compensating_control": "...", "effective": "2026-10-01", "expires": "2026-12-01"}]
}
```

```
node $ENGINE/src/cli.ts gate . --owner owner.json
```

An owner row never overrides a FAIL that the engine found. An acceptance follows the kit's limits: a CRITICAL requirement for at most 90 days and at most 3 per release, never a BLOCKER, never a protected class, and the approver is not the owner.

## How much a rule is trusted: leads and findings

Every Semgrep rule has a tier in `rules/tiers.json`, with the measurement behind it: how many hits were judged, how many were real, on which benchmark and when.

1. A gate rule's hit is a finding. It fails its requirements and can hold the release gate.
2. A lead rule's hit is listed in the report under "Leads from rules still being measured". It never fails a requirement and never holds the gate. Read the code at each place it names.

A rule becomes a lead when at least 3 of its hits were judged and the share that were real (its precision) came out below 0.80. It moves up to gate when a later measurement reaches 0.80 or more. A rule with fewer than 3 judged hits keeps its default. The engine's own taint rules (`taint-*.yaml`) start as leads until they are measured. The rules copied from the Free kit start as gate.

Two kinds of finding are never leads: secrets (any Gitleaks hit, and any rule mapped to a secrets requirement), because a live key is a leak wherever it is committed, including in test files; and the engine's own checks that read files, with one exception: the checks that read the code map (`check.map.*`) are leads until they are measured.

Hits in test, fixture, spec, mock and example paths are kept, marked as test code and reported apart. They do not fail a requirement, with the same exception for secrets.

## Honest limits

1. The engine does not certify an app. It tells you what the repository shows. A clean report means the checks it ran found nothing, and the report lists the requirements it could not assess.
2. A scan of files alone cannot reach READY. The gate needs the evidence only an owner can supply.
3. Findings come from pattern matching. Some are false alarms and some real problems are missed. Treat each finding as a place to look, and use the check step in the report to confirm it.
4. Coverage depends on what is installed. Without Semgrep and Gitleaks most code and secret checks do not run. OSV Scanner sends package names to osv.dev, so it runs only when you pass `--allow-network`. The engine uses the network for nothing else.
5. Discovery names a stack only when it has evidence in the files. Anything else stays in `unknown`.
6. The Semgrep taint rules cover SQL injection, XSS, command injection, path traversal and SSRF in Python, JavaScript and TypeScript, Java, PHP and Go. They are leads until measured, and the benchmark files show where they are weak.
7. The code map comes from pattern reading, not from a parser or from running the app. It misses routes that are registered in loops, built from strings or generated, resources created at run time by a library (for example Juice Shop's generated model endpoints), protections applied by a gateway or a platform setting, and anything in a language without an extractor. Treat each cell in the entry point table as a place to look.
8. With the Free kit the engine maps results to the Free requirements only. A scanner hit that maps to no Free requirement is kept as an unmapped observation.
9. It was developed and tested on macOS.

## Reading the benchmark files

The `bench/` folder holds the scorer and the results of every measurement made so far. This README gives no detection figures on purpose. The numbers sit in the files, each with its limits, and a number is only meaningful with its limits beside it.

1. `bench/BASELINE-2026-10-10.md`: the first scored baseline. Audit outputs for the Hullproof demo app, a repository with 30 planted flaws, scored against its answer key with `bench/score.ts`.
2. `bench/STABILITY-2026-10-10.md`: the same measurement repeated, to show how much model audits and the deterministic scan vary from run to run.
3. `bench/PHASE1-DEMO-SCORE.md`: this engine on the demo. The checks were written while reading the demo and its answer key, so this is an upper estimate of what they catch on an app they have not seen.
4. `bench/PHASE1-INDEPENDENT-2026-10-10.md`: this engine on public vulnerable projects and datasets that the checks were not written for. This is the file to read for an honest view. Its limits section matters.
5. `bench/CVE-SUBSET-2026-10-10.md`: the engine on the vulnerable and the fixed commit of 25 public CVEs, to see whether it flags the vulnerable code and stops flagging it after the fix.
6. `bench/results/`: the scorer's output behind the first two files.
7. `bench/PHASE2-MEASURED-2026-10-11.md` and `bench/PHASE2-ENTRYPOINTS.md`: the code map measured on the demo, Juice Shop and BenchmarkPython, with the hand counts, the seeded samples and the hand checked findings. Read its limits before any number.

Some rows in these files come from runs that also used the Pro edition's additional rules (not published), which are not part of this repository. Each file says which run used what. Some runs used a private copy of the demo answer key that lists a requirement ID for every flaw. The published `DEMO-ANSWER-KEY.md` in https://github.com/jt247/hullproof-demo hides the IDs of the Pro flaws, so a rerun with the published key matches those flaws by the patterns in `bench/keys/demo-classes.json` and can score differently. To score a scan yourself:

```
node $ENGINE/bench/score.ts --key DEMO-ANSWER-KEY.md --classes $ENGINE/bench/keys/demo-classes.json .hullproof/<commit>/report.findings.md
```

The matching rules are in `docs/SCORING.md`. The raw audit outputs of the baseline runs are not published.

## Tests

```
npm install
npm test
npm run typecheck
```

`npm install` adds two development dependencies only, `typescript` and `@types/node`, for the type check. The tests run the discovery on small fixture projects for many stacks, the executable checks on pass and fail fixtures, the scanner adapters, the report and gate, and the scorer. Tests that need a kit read it from `HULLPROOF_KIT` or from a `hullproof-free` folder next to the engine folder. Tests that need a scanner skip themselves when it is not installed.

## Licences

1. The engine code, its rules and its checks: Apache License 2.0 (`LICENSE`), copyright Rare Phronesis Limited.
2. The external scanners are called, not bundled. Semgrep is LGPL-2.1, Gitleaks is MIT, OSV Scanner and Trivy are Apache-2.0. `NOTICE` lists them, with where the rules in `rules/` come from.
3. The Hullproof requirements and the controls file are in the Free kit, under the licences in its `LICENSING.md`.

## Roadmap

1. Model assisted hunting, as a separate step on top of this deterministic base, so the base report never changes because a model ran.
2. A proof sandbox that tries to confirm a finding by running the app in isolation.
3. An npm package, in addition to the release zip.

## Layout

| Path | What it is |
|---|---|
| `src/cli.ts` | The `hullproof` command |
| `src/discover/`, `detectors/` | File listing, manifest and import readers, and the detector rules as data |
| `src/map/` | The code map: text helpers, extractors per language, the protection vocabulary, and the Supabase and Firebase readers |
| `src/scanners/`, `src/mapping/` | Scanner adapters and the mapping to requirement IDs |
| `src/checks/`, `checks/` | Executable checks, as code and as JSON; `src/checks/map/` holds the checks that read the code map |
| `src/report/`, `src/gate/`, `src/commands/` | The report, the records and the release gate |
| `schemas/` | JSON schemas for every file the engine writes |
| `rules/` | Semgrep rules, the Gitleaks configuration and the rule tiers |
| `docs/` | The file formats and how the scorer matches findings |
| `test/` | Tests and synthetic fixture projects |
| `bench/` | The scorer and the benchmark files |

See `CONTRIBUTING.md` to work on the engine and `SECURITY.md` to report a vulnerability.
