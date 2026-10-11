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

Test code (added 2026-10-10): a scanner hit or check evidence in a test, fixture, spec, mock or example path (`src/report/test-code.ts`, which lists the folder and file name conventions per language) is kept in `scan/<tool>.json` and `checks.json` but never fails a requirement. In the findings record it becomes an observation whose fingerprint slug starts with `test-code-` and whose title starts with `Test code:`, and `report.md` lists these in their own section. The exception is a requirement about shipped test material (test routes, seed scripts and sample code; seed and fixture data in the migration chain; listed in `rules/test-artifact-ids.json`), which still fails from a test path. Secret findings (any Gitleaks hit, any rule mapped to a SEC-SECRETS ID) are never test code: they fail from any path.

Leads (added 2026-10-10): a hit of a Semgrep rule whose tier in `rules/tiers.json` or the pack's `tiers.json` is `lead` (`src/report/tiers.ts`, explained in `README.md`) is an observation whose fingerprint slug starts with `lead-` and whose title starts with `Lead:`; it never fails a requirement. `report.md` lists leads in their own section.

Kit used by the scan (added 2026-10-10): `scan` writes `kit.local.json` (`kit_dir`, an absolute path, and `controls_sha256`) next to `run.json`. Like `run.json` it is outside the byte identical contract, because it holds a machine path. `report` and `gate` use it when neither `--kit` nor `HULLPROOF_KIT` is given, and still refuse a kit whose controls sha256 differs from `scan.json`.

## 8. Exit codes

`0` done or settled, `1` open BLOCKER or CRITICAL items or a run that cannot support READY, `2` bad input or a refused run, `3` reserved for a command that exists but is not built yet (none today).
