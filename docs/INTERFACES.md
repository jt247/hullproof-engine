# Hullproof Engine: files and interfaces

This file describes what the engine writes and reads: the output folder, `stack.json`, the detector rule files, the scanner adapters, the executable checks, `results.json`, the findings record and the exit codes. The JSON schemas are in `schemas/` and the shared types are in `src/types/`.

## 1. Output folder

Every command takes the repository path (default the current folder) and `--out DIR` (default `.hullproof/` inside the repository). Files inside it:

| File | Written by | Type | Schema | In the byte identical contract |
|---|---|---|---|---|
| `stack.json` | `discover` (built) | `Stack` | `schemas/stack.schema.json` | yes |
| `scan/<tool>.json` | each adapter | `HitsFile` | `schemas/scan-hits.schema.json` | yes |
| `scan/<tool>.meta.json` | each adapter | `ToolMeta` | `schemas/scan-meta.schema.json` | yes |
| `checks.json` | check interpreter | `CheckResultsFile` | `schemas/check-results.schema.json` | yes |
| `codemap.json` | map step (`hullproof map` and `scan`) | `CodeMap` in `src/types/codemap.ts` | `schemas/codemap.schema.json` | yes |
| `results.json` | report step | `ResultsFile` | `schemas/results.schema.json` | yes |
| `report.findings.md` | report step | `FindingsFile` inside a `hullproof-findings` block | `schemas/findings.schema.json` | yes |
| `scan/<tool>.detail.json` | each adapter | `DetailFile` in `src/scanners/types.ts` | none (schema version 0.1.0 inside) | yes |
| `scan.json` | scan step | `ScanInfo` in `src/commands/scan.ts` | none | yes |
| `surface.json` | scan step | `SurfaceFile` in `src/report/surface.ts` | none | yes |
| `report.md`, `results.md` | report step | text | none | yes |
| `run.json` | any | free form timings | none | no |
| `kit.local.json` | scan step | the kit folder (absolute path) and its controls sha256, read by report and gate | none | no |

## 2. stack.json

Type `Stack` in `src/types/stack.ts`. Top level fields:

| Field | Meaning |
|---|---|
| `schema_version` | `"1.0.0"` |
| `engine_version` | from `src/version.ts` |
| `detectors_sha256` | sha256 over the list of per file sha256 sums of `detectors/*.json`, sorted by name (the method `scan.sh` uses for rule folders) |
| `commit` | HEAD commit read from `.git` files without running git; `null` outside a git repository |
| `confirmed_by_user` | always `false` until a later `--confirm` flag exists |
| `files` | `listed`: files discovery considered; `scanned_for_imports`: source files read for imports |
| `limits` | the file cap, the per file byte cap (512 KiB), whether a cap was reached, and the files read only in part |
| `skipped` | each folder or file not read, with the reason: `gitignore`, `dependency folder`, `build output`, `tool folder` or `symlink` |
| 13 categories | `languages`, `runtimes`, `frameworks`, `package_managers`, `data_stores`, `auth`, `payments`, `ai`, `hosting`, `iac`, `containers`, `ci`, `mobile`. Each is an array of items sorted by `id`. |
| `unknown` | what discovery saw and could not name: file extensions with no detector, configuration files with no detector (repository root and one level inside dot folders), Terraform providers with no detector, and `package.json` files with no lockfile |

Each item (`StackItem`):

| Field | Meaning |
|---|---|
| `id` | lower case id. The full list of possible ids per category is the `id` of each entry in `detectors/<category>.json`. Match on these strings. |
| `confidence` | the best confidence among its evidence |
| `evidence` | up to 5 entries (3 for languages found by extension). The first entry of each file comes first, so the sample spans files. |
| `evidence_count` | all evidence found, including entries not listed |
| `versions` | `package@declared version` as written in the manifest, for example `next@15.0.0`, `django@==5.0.6` |
| `file_count` | languages only: files with that language's extensions |
| `kind` | hosting only: `platform` (Vercel, Netlify, Render, Railway, Fly, Heroku, Cloudflare, Supabase, Firebase) or `cloud` (AWS, Azure, Google Cloud, DigitalOcean, Alibaba Cloud, Oracle Cloud, IBM Cloud) |
| `clouds` | iac only: providers named in those files, using the hosting ids |
| `lockfiles`, `manifests` | package_managers only |

Evidence (`Evidence`): `file`, then exactly one of `line` (1 based) or `key`, then `rule` and `confidence`. `key` is a JSON key path such as `dependencies.express`, or `(present)` when the file itself is the signal (for example `vercel.json`, `Dockerfile`), or `(extension)` for a language found by file extension. `rule` is `<category>.<id>.<kind>[.<n>]`, where kind is `dep.<ecosystem>`, `import.<language>`, `content.<n>`, `file.<n>` or `extension`.

Confidence classes:

| Class | Means |
|---|---|
| `high` | A manifest or lockfile declares it, a file whose only purpose is this thing exists (`vercel.json`, `fly.toml`, `Chart.yaml`), or a pattern that cannot mean anything else matched (a Terraform `provider "aws"` block, `AWSTemplateFormatVersion`). |
| `medium` | A source file imports it, an SDK for a service is declared (the code talks to AWS; it does not prove it is hosted there), or a looser content pattern matched (an image name in a compose file). |
| `low` | Reserved for weak hints. No detector uses it today. |

How a module uses it: `applies(stack)` of an adapter and `applies_when` of a check read item ids only. Do not read evidence to make decisions; evidence is for the report.

Phase 1 discovery reads files, not deployments. Anything set only in a dashboard is invisible to it, and the report must say so.

## 3. Detector rule files

`detectors/<category>.json` is `{ "category": "<one of the 13>", "entries": [ ... ] }`. Each entry:

| Field | Meaning |
|---|---|
| `id` | item id |
| `attrs` | scalar fields copied onto the item, for example `{"kind": "cloud"}` |
| `extensions` | languages only: file extensions without the dot |
| `deps` | ecosystem to package names. Ecosystems: `npm`, `pypi`, `go`, `cargo`, `rubygems`, `composer`, `maven` (Maven and Gradle, as `group:artifact`), `nuget`, `pub`, `swiftpm`, `cocoapods`, `hex`, `terraform` (provider names). A name matches exactly, or as a prefix on the ecosystem separator (`/` for npm, go, composer, cocoapods, swiftpm; `:` for maven; `.` for nuget), or as a prefix when it ends with `*`. Python names are compared lower case with `_` read as `-`. |
| `deps_confidence` | default `high`; a string, or an object per ecosystem with `"*"` for the rest |
| `imports` | import language to module names, same matching. Languages: `js` (JS, TS, Vue, Svelte, Astro), `python`, `go`, `ruby`, `php`, `jvm` (Java, Kotlin, Scala, Groovy), `swift`, `dart`, `csharp`, `rust`. |
| `imports_confidence` | default `medium` |
| `signals` | list of `{files, regex?, all?, ignore_case?, confidence?, attrs?}`. `files` are globs: a glob without `/` matches the file name at any depth, a glob with `/` matches the whole path, `**/` matches any folders. With no `regex`, the file being there is the signal (default `high`). With `regex` (multiline mode), the first match gives the line (default `medium`); every pattern in `all` must also match the same file. `attrs` adds list fields to the item, and `"$file"` is replaced by the matching path. |

Manifests read: `package.json`, `composer.json`, `requirements*.txt`, `pyproject.toml`, `Pipfile`, `setup.py`, `go.mod`, `Cargo.toml`, `Gemfile`, `pom.xml`, `build.gradle(.kts)`, `pubspec.yaml`, `*.csproj`, `packages.config`, `Package.swift`, `Podfile`, `mix.exs`, `*.tf`.

## 4. Scanner adapters

Types in `src/types/scan.ts`: `ScannerAdapter`, `RunContext`, `Hit`, `HitsFile`, `ToolMeta`.

1. One file per scanner at `src/scanners/<tool>.ts`, exporting an `Adapter` (`src/scanners/types.ts`, which extends the shared `ScannerAdapter`) as `adapter`. The runner calls `execute(opts, env)`, which may run several commands and returns detail hits, files scanned and tool errors; `command()` and `parse()` stay as the minimal shared descriptor. Built: `semgrep`, `osv-scanner`, `gitleaks`, `trivy`. `checkov` is named in the type and not built.
2. An adapter never installs anything. When the tool is missing, write `scan/<tool>.meta.json` with status `skipped: not installed` and list in `not_assessed_sec_ids` the IDs that stay NOT ASSESSED because of it. `osv-scanner` without `--allow-network` is `skipped: network not allowed`.
3. Run with an argv array, network off unless allowed. Before any git command, the scan step checks the repository's git configuration; adapters do not run git themselves.
4. Normalise: repository relative paths, sorted hits (file, line, tool, rule_id), no tool message text (use `message_key`, normally `<tool>:<rule_id>`), no secret values, no timings.
5. Map to requirement IDs: Semgrep from each rule's `metadata.sec_ids`; the others from `maps/<tool>.json`, shaped `{"tool": "<tool>", "rows": [{"rule_id": "...", "sec_ids": ["SEC-..."]}]}` with rows sorted by `rule_id`. A hit with no row keeps `sec_ids: []` and is an unmapped observation: shown in the report, never in the gate.
6. `version_tested` is false when the installed version is outside `testedVersions`; the report says so in one line.
7. `Hit` stays as it is. Rule version, end line, masked evidence, the reason a tool did not run, every command run, and OSV advisory data with the policy decision live in `scan/<tool>.detail.json`, which is part of the byte identical contract. The report reads `not_run_reason` from it.
8. Gate rule for hits: a hit with `sec_ids: []` never reaches the gate. An OSV advisory the dependency policy only reports carries `sec_ids: []`, and the IDs it would fail are in `advisory.mapped_sec_ids` of the detail file.
9. `ToolMeta.argv` holds the first command only (Gitleaks runs `dir` and, with history, `git`); every command is in `commands` of the detail file.
10. `RunContext.history` is set by the scan step after its git configuration check, and only then may an adapter run a command that runs git (`gitleaks git`). `RunContext.kit` is the kit folder the scan resolved.
11. Semgrep rule pack: `ScanOptions.rulePack` (CLI `--rule-pack DIR`, else `HULLPROOF_RULE_PACK`) adds the rule files in that folder to `rules/semgrep/`. A pack file with the same name as an engine file replaces it; a rule id in two files after the merge fails the Semgrep run. `scan.json` records the pack folder name, its file names and its sha256 (never a path), and `report.md` says which pack ran.

## 5. Executable checks

Types in `src/types/check.ts`. Definition schema `schemas/check.schema.json`, results schema `schemas/check-results.schema.json`.

1. One JSON file per check at `checks/<id without the check. prefix>.json`, id shaped `check.<area>.<name>`.
2. `applies_when` names stack categories and the item ids that make the check apply, or `"*"` for any item. `{}` means always.
3. `op` is one of the ten operations, with `params` op specific (documented in `src/checks/README.md`), or `code` for a check written as TypeScript (`CodeCheckDefinition` in `src/types/check.ts`: no `params`, and `module` names the file in `src/checks/code/`). The five code checks keep this metadata in their module and are registered in `src/checks/run.ts`; they have no JSON file.
4. `on_true` and `on_false` are result words. `PASS (static)` only for repo authority requirements; the gate rejects it otherwise. A check may FAIL the part of a runtime authority requirement that a file settles (decision 3 of 2026-10-10) and must never PASS it.
5. An absence result records its search in `absence_search` (pattern, file globs, files searched, matches).
6. Every check ships `test/fixtures/checks/<name>/pass/` and `.../fail/`, and its test runs both.
7. `ctx.files` is what discovery lists (skipped folders left out). `ctx.tracked()` is every file in the git index, sorted, including files inside folders discovery skips such as `.vercel/` and `.netlify/`, or null outside a git repository. Use it for checks on committed link or build files.

## 6. results.json

An array of `{id, result, notes}` sorted by id: the JSON form the kit gate (`hullproof-gate.mjs`) already reads, so `hullproof gate` can run the kit's `evaluate()` unchanged. Result words: `FAIL`, `PASS (static)`, `NOT APPLICABLE` (needs a reason in `notes`), `NOT ASSESSED: <state>` with state `NEEDS DASHBOARD`, `NEEDS BUILD`, `NEEDS DYNAMIC TEST`, `ASK OWNER`, `ATTESTATION` or `UNKNOWN`.

## 7. Findings record 1.1.0

Types in `src/types/findings.ts`. The schema is the kit's `docs/hullproof/findings.schema.json`, copied to `schemas/findings.schema.json`; `test/schemas.test.ts` fails when the copy and the kit file differ. Version 1.1.0 adds `machine_evidence` to a `fail` record: `{tool, rule_id, tool_version, config_sha256}`. A fail record with `machine_evidence` may be class `finding` without a `trace`; the rule hit and its file and line are the evidence. The engine writes `schema_version: "1.1.0"`, `raised_by: ["hullproof-engine"]`, and records sorted by fingerprint (`<SEC id>:<file>:<slug>`). When a fail record needs a verifier outcome (a BLOCKER or CRITICAL record), the engine writes `run_status: "incomplete"` with `incomplete_reason: "deterministic_only"`: the kit reason (findings schema 1.1.0) for a run with no model, where no verifier ran by design. The kit validator then requires `agent_calls: 0` and `machine_evidence` on every fail record (rule F15). Cross field rules live in the kit's `validate-findings.mjs`; run it on any record file you write.

Test code (added 2026-10-10): a scanner hit or check evidence in a test, fixture, spec, mock or example path (`src/report/test-code.ts`, which lists the folder and file name conventions per language) is kept in `scan/<tool>.json` and `checks.json` but never fails a requirement. In the findings record it becomes an observation whose fingerprint slug starts with `test-code-` and whose title starts with `Test code:`, and `report.md` lists these in their own section. The exception is a requirement about shipped test material (test routes, seed scripts and sample code; seed and fixture data in the migration chain; listed in `rules/test-artifact-ids.json`), which still fails from a test path. Secret findings (any Gitleaks hit, any rule mapped to a SEC-SECRETS ID) are never test code: they fail from any path, with one exception (added 2026-10-15): a hit the scanner adapter marked as an example value. `scan/gitleaks.json` then carries `noise` with the reason (`src/scanners/secret-noise.ts`): the line holds only placeholder or published example values, or a rule with no vendor shape (`generic-api-key`, `curl-auth-header`, `curl-auth-user`, `jwt`, `hullproof-url-with-password`) matched in documentation, fixture data, an example env file, a lockfile, vendored or generated code or a migration. It becomes an observation whose title starts with `Example value:` (fingerprint slug still `test-code-`) and does not fail a requirement. A rule with a vendor shape, and any rule in source, config and test source files, still fails.

Leads (added 2026-10-10): a hit of a Semgrep rule whose tier in `rules/tiers.json` or the pack's `tiers.json` is `lead` (`src/report/tiers.ts`, explained in `README.md`) is an observation whose fingerprint slug starts with `lead-` and whose title starts with `Lead:`; it never fails a requirement. `report.md` lists leads in their own section.

Kit used by the scan (added 2026-10-10): `scan` writes `kit.local.json` (`kit_dir`, an absolute path, and `controls_sha256`) next to `run.json`. Like `run.json` it is outside the byte identical contract, because it holds a machine path. `report` and `gate` use it when neither `--kit` nor `HULLPROOF_KIT` is given, and still refuse a kit whose controls sha256 differs from `scan.json`.

## 8. Exit codes

`0` done or settled, `1` open BLOCKER or CRITICAL items or a run that cannot support READY, `2` bad input or a refused run, `3` reserved for a command that exists but is not built yet (none today).

## 11. Hunt files and the confirmation engine (added 2026-10-14, Phase 3)

A hunt asks a model for leads, one entry point at a time. A lead is a claim with a place in the code. The engine decides what a lead is worth; the model never does. Types are in `src/types/hunt.ts`, the schemas in `schemas/hunt-output.schema.json` and `schemas/hunt-result.schema.json`, the code in `src/confirm/`.

### Files under `<out>/<commit>/hunt/`

| File | What it holds | In the byte identical contract |
|---|---|---|
| `plan.json` | The entry point ids in hunting order and the number of runs | yes |
| `run-<n>/<entry>.json` | One saved answer: one call, one entry point, one run. Written the moment it arrives. Holds the model's JSON as received, the provider and model names, a sha256 of the context, whether the context was cut, token counts, and for a call that did not finish the reason | no (it is the recorded input) |
| `result.json` | What the engine confirmed from the saved answers: confirmed findings, leads, incomplete calls, hallucination and malformed counts, token totals | yes, and it is rewritten by `hullproof hunt --replay` with the same bytes |
| `synthesis.json` | The plain English summary of all runs and one explanation per known finding or lead key | no |
| `skipped.json` | Why the hunt did not run, for example that no provider key is set | no |

A new `hullproof scan` keeps this folder. The saved answers took model calls to get, so a rescan never deletes them.

### The lead (what a model returns)

`lead_id`, `entry_point` (exactly the entry point hunted), `requirement_ids` (1 to 6 ids), `claim` (up to 500 characters), `path` (1 to 12 steps of file, line and note, the entry point first and the sink last), `quoted_code` (the code at the sink) and `evidence_proposal`. A lead that breaks a limit is malformed and is counted apart from a hallucination.

### The honesty check

Every cited file must exist inside the repository (no absolute path, no `..`, no link), every cited line must be inside its file, and the quoted code must appear in the sink file on or within two lines of the sink line (white space is ignored). A lead that fails is dropped and counted as a hallucination, with the reason. Nothing reads the claim.

### Identity and agreement

A lead's identity is its entry point, its requirement ids and its sink (file and line). Runs that raise the same identity are one lead with a count of runs. The count only orders the list. No count ever confirms a lead, and a confirmed lead raised once is as confirmed as one raised three times.

### Ways a lead becomes a finding

1. A map query. The proposal holds a query in the small language of `src/confirm/query.ts`: `all`, `any`, `not`, `some` and `none` over a list field, and `field` comparisons with `eq`, `ne`, `in`, `contains`, `startsWith`, `exists`, `gt` and `lt`. There are no regular expressions and no code. The query runs on the lead's entry point in `codemap.json`. It confirms only when the entry point matches, the query does not match every entry point of a map of three or more, and at least one fact the query matched (a data touch, a protection, a read or an outbound call) lies on or within two lines of a line the lead cites.
2. A generated Semgrep rule with a negative control. The rule must hold exactly one rule, must match the cited lines in the real file, and must not match a safe sample supplied with it. Semgrep must really scan both files, so a rule for another language cannot pass by matching nothing. If Semgrep is not installed the outcome is `not_run` and the lead stays a lead.
3. A test run in the proof sandbox (`hullproof prove`, section 14). Until a test proves the flaw 3 of 3 times the lead stays a lead.

### Confirmed findings and the gate

Only the `confirmed` list of `result.json` is read by `report` and `gate`. Each confirmed finding with a requirement in the run's scope becomes a fail record of findings schema 1.1.0 with `machine_evidence` (`tool` is `hullproof-hunt` for a query or `semgrep` for a rule, `rule_id` names the query hash or the rule, `config_sha256` hashes the query or the rule) and its requirement becomes a FAIL row. A BLOCKER or CRITICAL record in a run that was complete is recorded as `incomplete` with the reason `deterministic_only`, because no verifier ran. Leads, claims, agreement counts and the synthesis are never read by the gate: adding, removing or changing them cannot change the verdict. `test/hunt-gate.test.ts` checks this on the whole path.

### Replay

`hullproof hunt --replay` reads `plan.json` and the saved answers, runs the honesty check and the confirmation again, and rewrites `result.json`. It calls no model. The same saved answers, repository and tool versions give the same bytes.

### Provider stops

A call that a provider stops (a refusal, a safety stop, a rate limit, a timeout, an answer cut off at the output limit, an answer that is not JSON) is saved as an incomplete answer with the reason and is listed in the report. It is never retried, reworded or sent to another model. `--resume` does not repeat it either; remove its file under `run-<n>/` to try that call again.

## 12. The proof sandbox (added 2026-10-14, Phase 4)

`hullproof prove` runs a test against a local copy of the app and keeps the request and response transcripts as evidence. A test is a spec: data in a small step language, never code. The engine runs the steps. Types are in `src/types/prove.ts`, the code in `src/prove/`.

### Safety rules

1. Nothing runs without `--allow-run` and the owner's typed confirmation (the exact phrase `I own this app and approve running it`, typed on a terminal or passed with `--confirm`). No environment variable and no CI setting stands in for it.
2. The command accepts no address. `--target` is refused. The step executor builds a request only for a path on the sandbox's own loopback address and port.
3. No secret enters. The copy that goes into the sandbox leaves out environment files, key files, credential files, `.git`, tool folders and symbolic links. The app gets a generated dummy value for each environment variable the source reads.
4. The container runs as a non root user with a read only root filesystem, all capabilities dropped, no privilege escalation, no host mounts, no published ports, and limits on memory, processor, processes and time. While tests run it has no network. The build phase installs from the lockfile without install scripts, and it can reach the package registry: Docker has no flag that limits a build to one host, so the engine does not filter that traffic. What limits the exposure is that only the lockfile is installed, the registry address is fixed in the command, nothing from the host is mounted, and no secret is in the copy. `--allow-install-scripts` (off by default) lets dependency install scripts run inside the build container, which is third party code with that network access; `hullproof prove` prints a warning when it is on. A Postgres store runs in a second container on an internal network that has no route out.
5. The container backend speaks the docker command line, so Colima, Docker Desktop and Podman work with the same commands (`--runtime podman`, or `HULLPROOF_CONTAINER_BIN`). `assertSafeRunArgs` refuses any argument list that weakens these rules before a container starts.
6. A plain local process backend exists for the engine's own fixture apps. It is labelled unsafe, must be created with `acknowledgeUnsafe: true`, refuses any folder outside the fixture folders of this engine, and the command line does not offer it.

### Start recipe

Derived from `stack.json`, the code map and the repository: base image, install command (`npm ci --ignore-scripts` from a lockfile, or nothing when the repository carries its own `node_modules`), seed step, start command, port, health path and data store. Two recipes exist. The Python recipe (`python-flask`) reads a Flask app with a local SQLite file: it needs a `requirements.txt` with every line pinned by `==`, installs with `pip install --only-binary=:all:` (so no package build script runs; `--allow-install-scripts` lets a package without a wheel build from source), reads the database path from `DATABASE_URL`, `DB_PATH` or a similar variable (`os.environ`, `os.getenv`), starts the app with `python <file>` when the file calls `app.run()` under `__main__` and with the flask command otherwise, runs a `seed.py` if there is one, and builds on `python:3.12-slim` with the node binary copied in from the Node image, because the step executor runs as Node inside the sandbox. The Node recipe is: a Node app on Express with a local SQLite file (its path read from `DATABASE_URL`, `DB_PATH` or a similar variable, placed in a writable memory backed folder) or an ephemeral Postgres (read from `DATABASE_URL`, built from a `migrations` folder and `seed.sql`). A hosted service, another stack, a data store of another kind, a native module that needs an install script (unless `--allow-install-scripts` is given), a missing lockfile or a database path written into the code gives the result `not provable here` with the reason. Nothing is guessed and nothing is faked.

### The spec

| Key | Meaning |
|---|---|
| `spec_id`, `title`, `claim` | Identity and a plain sentence |
| `lead_key` | The hunt lead this spec tests, or null |
| `target` | `entry_point`, `file` and `line` of the code the spec is about |
| `requirement_ids` | 0 to 6 requirement ids |
| `actors` | 1 to 6 named callers. Each may carry `headers`, sent once every `{{variable}}` in them has been captured. An actor with no headers is anonymous |
| `steps` | 2 to 24 steps: setup steps, then control steps, then attack steps |
| `expect` | `{"outcome": "flaw_present"}`: the attack assertions describe the flaw and all hold when it is there |

A step has `id`, `phase`, `actor`, `method` (GET, HEAD, POST, PUT, PATCH, DELETE), `path` (a path on the app: one leading slash, no host, no scheme, no `..`), optional `headers` and `body`, optional `captures` (a value read from the JSON body, a header or the status, usable later as `{{name}}`), and `assert`. Assertions are `status` (eq, ne, in), `json` (a dotted path with eq, ne, contains, exists, absent), `text` (contains, absent) and `header`.

Rules the validator enforces: a positive control (a control step with a 2xx status assertion, before the first attack step), at least one attack step that asserts what got through and not a denial, setup steps first, variables captured before use, no assertion on or comparison with a secret, no header that changes the host or the framing, and no payload built to damage data, read files or run code.

### Verdicts and evidence

Each spec runs three times, each in a fresh container with a fresh seeded store. One run is `proven` (control passed and the attack assertions held), `not_proven` (control passed and the app refused), `invalid` (the setup or the control failed, so the harness or the spec is wrong) or `error`. A spec is `proven` only when all 3 runs are proven. Mixed runs are `unstable`. Anything the sandbox could not start is `not_provable`. No outcome is ever called a pass.

Files under `<out>/<commit>/prove/`:

| File | What it holds | In the byte identical contract |
|---|---|---|
| `specs/<spec_id>.json` | A spec, written by hand, passed with `--spec`, or generated from a lead (Pro) | no (it is the input) |
| `recipe.json`, `meta.json` | The recipe used, the runner name, the hash of the recipe and why a run was not provable, if it was not | yes |
| `runs/<spec_id>/run-<n>.json` | One run: the redacted request and response of every step, the assertion results, the outcome and a sha256 over the whole record | no (it is the recorded evidence) |
| `result.json` | Per spec: outcome, reason, and the outcome and hash of each run; counts; files dropped; what was left behind | yes |
| `specgen.json`, `specgen/` | Spec generation (Pro): counts of specs written, declined, dropped and incomplete, and the saved model answers | no |

Transcripts are redacted before they are stored: header values that could hold a credential, fields named like a password, token, secret or key, JWTs and long hex or random strings. Every assertion is judged on the stored, redacted form, so `hullproof prove --replay` rebuilds `result.json` from the files alone, with no sandbox and no app, and gives the same bytes every time. A transcript that was edited after the run, or a spec that changed, no longer matches its hash and the spec becomes an error, never a proof.

### Findings and the gate

A spec proven 3 of 3 becomes a confirmed finding: a fail record of findings schema 1.1.0 with `machine_evidence` where `tool` is `hullproof-prove`, `rule_id` is `prove.test.<first 12 characters of the spec hash>` (the `prove.test.` prefix is what marks a test, because the frozen schema has no separate kind field) and `config_sha256` is the spec hash. It makes its requirement a FAIL row and enters the gate like any other confirmed finding, if the requirement is in the run's scope. When the spec tests a hunt lead, the test replaces the weaker evidence on that lead. Specs that are not proven, invalid, unstable, in error or not provable are shown in the report with their reason and are never read by the gate. `test/prove-gate.test.ts` checks this on the whole path.

## 13. hullproof ci (added 2026-10-14, Phase 5)

`hullproof ci [repository]` runs discovery, the scanners, the code map, the checks and the gate in one command, with no model and no container. It is the one command that CI, the pre-commit hook, the MCP server and the tool front ends all sit on. The code is in `src/commands/ci.ts` and `src/ci/`.

| File | What it holds |
|---|---|
| `findings.json` | The findings record, schema 1.1.0 (`schemas/findings.schema.json`), after any confirmed hunt or proven findings are merged in |
| `report.md` | The plain English report, as `hullproof report` writes it |
| `results.sarif` | SARIF 2.1.0. One result per fail record, one rule per requirement, paths relative to the repository root, the record fingerprint in `partialFingerprints` |
| `pr-comment.md` | The pull request summary. The first line is the marker `<!-- hullproof-ci -->` so a job can update its own comment |

The four files go to `<out>/<commit>/` and to a flat folder (`--artifacts`, default `<out>/ci`). For the same commit, engine, kit and scanner versions they are byte identical. The engine checks the SARIF file with a strict structural check before it writes it (`src/ci/sarif-check.ts`); that check covers the parts of the SARIF 2.1.0 schema the engine uses and is not the full schema. The scanners read untracked files in the working tree, so files left inside the repository change the next run.

Exit codes: 0 nothing at or above `--fail-on` failed; 1 something did; 2 bad input, a refused run, or a records problem. `--fail-on` takes `blocker` (default), `critical`, `high`, `medium`, `low` or `none`. Only fail records count: observations, leads and routed items never do, as in the release gate. The full release gate verdict is printed as information; a scan of files alone cannot reach READY, so it is not what CI exits on.

Editions: with no `--edition`, a kit that holds Pro requirements runs the full set and the Free kit runs the BLOCKER and CRITICAL requirements. `--hunt` (Pro only) runs the model hunt first, using a provider key from the environment. In this mode no `.env.local` file is read, because the repository under test is untrusted and must not name the provider address.

## 14. The pre-commit hook (added 2026-10-14, Phase 5)

`hullproof hooks install [repository]` adds the hook; `hullproof hooks uninstall` removes it; `hullproof hooks run` is what the hook calls. The code is in `src/hooks/` and `src/commands/hooks.ts`.

| Mode | Where the hook goes | Chosen when |
|---|---|---|
| `husky` | One marked block in `.husky/pre-commit` | The repository has a `.husky` folder, lists Husky in `package.json`, or sets `core.hooksPath` to it |
| `pre-commit` | One marked `repo: local` entry at the end of `.pre-commit-config.yaml` | The file exists and Husky is not used |
| `git` | `.git/hooks/pre-commit` (or the folder named by `core.hooksPath`) | Neither of the others |

`--mode` overrides the choice and `--dry-run` writes nothing. A hook file that is not ours is never overwritten or removed. A `.pre-commit-config.yaml` with keys after `repos:` is not edited; the entry is printed instead. The hook script blocks the commit only when the check exits 1; a missing command or any other code lets the commit through.

`hooks run` looks at the staged files only. It exports the index to a temporary folder (so it sees what the commit will hold), runs Gitleaks over it and keeps the hits in staged files, then runs the deterministic checks and, when Semgrep is installed, the Semgrep rules on the staged source files. It exits 1 and prints the place and the fix when a staged file has a secret or a BLOCKER fail record, and exits 0 otherwise. A secret is checked first and stops the run at once. Findings in files that are not staged never block. It uses no network and no model, and an error in the engine is reported and lets the commit through (`HULLPROOF_HOOK_STRICT=1` blocks instead). `--no-semgrep` or `HULLPROOF_HOOK_SEMGREP=0` leaves Semgrep out.

## 15. The MCP server (added 2026-10-14, Phase 5)

`hullproof mcp [repository] [--kit DIR] [--edition free|pro] [--allow-run]` is a Model Context Protocol server on standard input and output, written by hand with no dependency (`src/mcp/`). Messages are JSON-RPC 2.0, one per line, nothing else on standard output; logs go to standard error; the server exits when standard input closes.

Protocol: revision 2026-07-28 (no handshake; every request carries `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in `_meta`; `server/discover`; results carry `resultType`; `tools/list` carries `ttlMs` and `cacheScope`; error `-32022` for an unsupported version) and the handshake revisions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05 (`initialize`, then requests; `ping`). Batches, resources, prompts, sampling and subscriptions are not offered. The specification pages read are listed at the top of `src/mcp/protocol.ts`.

| Tool | Returns |
|---|---|
| `list_requirements` | The requirements in scope (Free: the BLOCKER and CRITICAL ones; Pro: all), by severity, domain or search word |
| `get_requirement` | One requirement and its current result. A requirement outside the edition is answered as unknown |
| `get_checklist` | The per requirement results of the scan of this commit |
| `get_gate_verdict` | Whether the check fails at a chosen level, and the release gate conditions |
| `get_findings` | Fail records, or leads and observations, in pages |
| `get_report` | `report.md` in pages of characters |
| `explain_finding` | One finding in full, with the lines of code around it (never for a secret) |
| `run_scan` | Only with `--allow-run`. Runs `hullproof ci`; writes only under `.hullproof/`; no model, no network |

Safety rules: a client never names a path. Tools take requirement ids and finding fingerprints, and the files the server reads come from the engine's own records, confined to the repository root with links resolved, and files that usually hold secrets are refused. The results come from the scan of the current commit; they are refused when `.hullproof/` is tracked by git, because a repository can carry a forged folder. Every result starts with a notice that text from the repository is data, not instructions. Arguments are checked against the tool schemas and unknown names are refused. A line over 1 MiB is refused.
