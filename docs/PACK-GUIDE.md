# Writing a stack pack

A stack pack is how the engine learns one stack well. This guide explains what a pack holds, how its depth level is decided, and how to add one, using the Node and TypeScript pack as the worked example. You do not need to know how the rest of the engine works to follow it.

Outside contributions open after release 0.5.0. Until then this guide is for the maintainers. When contributions open, a pull request that adds or changes a pack needs a DCO sign off (`git commit -s`), a pack that passes `hullproof pack validate`, and a fixture benchmark result that supports the level the pack declares.

## 1. What a pack is

Every stack gets the generic checks: secrets, dependencies, infrastructure files, and the generic rules. That is level L0 and it needs no pack. A pack is the extra work for one stack, written down in one folder:

```
packs/node-ts/
  pack.json             the manifest: what the pack holds and the level it declares
  fixture-result.json   what was measured on the fixture app, recorded
  answer-key.json       the answer key, only when the fixture is synthetic and its key may live in the repository
```

The manifest names parts that live elsewhere in the engine (the extractor source, the rule files, the checks). The pack folder itself stays small.

## 2. The levels

| Level | Name | What it means |
|---|---|---|
| L0 | Generic | Secrets, dependencies, infrastructure and cloud configuration, and the generic rules. Runs on any stack. |
| L1 | Detected | The stack is recognised and its configuration files are checked. |
| L2 | Mapped | Entry points and their protections are written to `codemap.json`. |
| L3 | Checked | Executable checks and stack rules, measured on a fixture with a blind answer key. |
| L4 | Provable | A start recipe, so the proof sandbox can run the app and prove a flaw. |

Levels build on each other. A pack cannot be L3 without being L2.

The level is not an opinion. The pack declares one, and `hullproof pack validate` compares the declaration with the recorded fixture result. The rules are these, and they are written once in `src/packs/manifest.ts`:

1. L1 needs every stack id the pack expects to be found by discovery on the fixture.
2. L2 needs a measurement where the map matched every item of the answer key (entry points, or tables and rules for a configuration pack), with no extra item, and the output the same bytes in three runs. If the pack has a measurement on a real third party app, a seeded sample of its route registrations must be found in the map at 90 percent or better, with the same bytes in three runs. A real app that falls short holds the pack at L1.
3. L3 needs a measurement with a blind answer key where the pack's checks and rules found at least half of the planted flaws and reported nothing false on the fixed copy.
4. L4 needs, for the scope it is declared for, every planted flaw proven by the sandbox 3 of 3 times, no proof on the fixed copy, and three identical runs.

A pack can also declare a higher level for a narrower scope. The Node pack is L3, and L4 for Express with SQLite. The Python pack is L3, and L4 for Flask with SQLite. Those two are the only stacks with a start recipe.

A blind answer key is a list of the planted flaws and of the entry points, written before the pack is measured and kept outside the repository (`../bench-targets/answer-keys/<pack id>.json`, local only). It is blind to the extractor: nobody tuned the extractor by looking at it. A key kept in the repository, for a fixture the pack author wrote, is not blind. It still proves the extractor reads what its author expected, so it supports L2 and no more.

Real application checks are a separate measurement and are reported separately. A real application has no planted flaws, so it can test the map and cannot test recall of flaws: it adds a `third_party` measurement with a seeded sample of the application's route registrations (found by a grep that does not use the extractors, with a seed; the sampler is a maintainer script), written in the `recorded` list of the answer key so that a new measure keeps it. If a pack has such a measurement and fewer than 90 percent of the sample is found, or the output is not the same bytes in three runs, the pack is held at L1. The coverage table says `route sample on N real apps` for a pack that has one, and a pack with none says it was measured on synthetic fixtures only.

## 3. The manifest

`packs/node-ts/pack.json`, shortened (the real file lists every check):

```json
{
  "schema": 1,
  "id": "node-ts",
  "name": "Node and TypeScript",
  "summary": "Next.js, Express and Fastify family, NestJS and tRPC.",
  "edition": "free",
  "languages": ["javascript", "typescript"],
  "frameworks": ["nextjs", "express", "fastify", "koa", "hono", "nestjs", "trpc"],
  "level": "L3",
  "scopes": [{ "where": "Express with SQLite", "level": "L4" }],
  "parts": {
    "detectors": ["javascript", "typescript", "nextjs", "express", "nestjs"],
    "extractors": [{ "file": "src/map/js-express.ts" }, { "file": "src/map/js-next.ts" }],
    "auth_patterns": [{ "file": "src/map/vocab.ts" }],
    "sources_sinks": [{ "file": "rules/semgrep/taint-javascript.yaml" }],
    "rules": [{ "file": "rules/semgrep/taint-javascript.yaml", "tests": ["test/fixtures/rules/taint-javascript.js"] }],
    "checks": [{ "id": "check.map.mutating-route-without-auth" }, { "id": "check.map.input-without-schema", "pro": true }],
    "mapping": [{ "file": "src/checks/map/entry-checks.ts" }],
    "start_recipe": { "file": "src/prove/recipe.ts", "recipe": "node-express" }
  },
  "fixture": {
    "dir": "test/fixtures/map/fail",
    "fixed_dir": "test/fixtures/map/pass",
    "answer_keys": ["in_repo"],
    "result": "packs/node-ts/fixture-result.json"
  }
}
```

Field by field:

| Field | Meaning |
|---|---|
| `id` | Words joined with hyphens. It must equal the folder name. |
| `edition` | `free` when the pack's own files ship in the open repository. |
| `languages`, `frameworks` | Stack ids as discovery writes them in `stack.json`. Each framework must be an id in `detectors/*.json`. |
| `level` | The level the pack declares for everything it lists. |
| `scopes` | Narrower scopes that reach a higher level. A scope must be higher than the pack level. |
| `parts.detectors` | Detector ids the pack relies on. Needed from L1. |
| `parts.extractors` | The source files that read entry points or configuration. Needed from L2. |
| `parts.auth_patterns` | The files that name session, role and signature patterns for the stack. Needed from L2. |
| `parts.sources_sinks` | Taint rule files (request data in, dangerous call out). Optional. |
| `parts.rules` | Semgrep rule files, each with the fixture files that test them. A rule with no test is refused. |
| `parts.checks` | Executable checks that apply to the stack. Needed from L3. |
| `parts.mapping` | Where the checks and rules map to requirement IDs. Needed from L3. |
| `parts.start_recipe` | How the proof sandbox starts the app. Needed for L4. |
| `fixture` | The fixture app with planted flaws, its fixed copy, where the answer keys are, and the recorded result. Always needed. |

A part marked `"pro": true` belongs to the Pro edition. The open edition's copy of the manifest leaves it out, and the validator skips it where the Pro folders are not present.

## 4. Adding a stack, step by step

1. Detect it. Check that discovery already names the stack (`detectors/`). If not, add a detector entry first. That alone is L1 once the fixture result shows it.
2. Write the extractor in `src/map/`. It reads the route registrations and turns each into an entry point with its protections. Follow `src/map/go.ts` for a pattern based reader. No parser library and no runtime dependency.
3. Name the auth patterns. Session reads, role checks, signature checks and rate limits for the stack go in the vocabulary file the extractor uses. Prefer exact library calls (high confidence) over name guesses (medium or low).
4. Write taint rules if the stack has request sources and dangerous sinks, in `rules/semgrep/`, with a fixture file under `test/fixtures/rules/` that has `ruleid:` and `ok:` lines for every rule id.
5. Add checks. The map checks (`check.map.*`) already read any stack's entry points, so most packs only list them. A new check needs a pass and a fail fixture.
6. Build the fixture app: a small app with planted flaws (for example a write route with no sign in, an admin route with no role check, a webhook that does not check its signature), and a fixed copy that repairs each one. Keep both small and written for this purpose. Never copy third party code into a fixture.
7. Write the answer key before you run anything: every entry point the fixture has, and every planted flaw as a pair of check and stack. Put it outside the repository for L3.
8. Measure: `node bench/packs-measure.ts --write <pack id>`. It reads the key, builds the code map and the checks three times on the fixture and on the fixed copy, and writes `fixture-result.json`.
9. Validate: `hullproof pack validate`. It must pass. Then `hullproof pack table` shows the row your pack gets.
10. For L4, add a start recipe to the proof sandbox and prove the planted flaws on a container runtime (the Phase 4 exit test: every planted flaw proven 3 of 3, nothing proven on the fixed copy), then record the result in the answer key file's `proof` list.

If the numbers do not reach a level, declare the lower level. A pack at its true level is useful. A pack that claims more is refused by the validator and by the test that compares the README table with the recorded results.

## 5. What `hullproof pack validate` refuses

| Code | When |
|---|---|
| `manifest_missing`, `manifest_unreadable` | There is no `pack.json`, or it is not JSON. |
| `schema`, `field`, `id` | A required field is missing, or the id does not match the folder. |
| `level` | A level is not L0 to L4, or a scope is not higher than the pack level. |
| `part_missing` | The declared level needs a part the manifest does not have. |
| `file_missing` | A file named by a part does not exist. |
| `detector_unknown`, `check_unknown`, `recipe_unknown` | An id is not one the engine knows. |
| `rule_without_test` | A rule file has no test files, or a rule id in it has no `ruleid:` line or no `ok:` line in them. |
| `fixture_missing` | The fixture folders or the answer key kinds are missing. |
| `fixture_result_missing`, `fixture_result_invalid` | There is no recorded fixture result, or it is malformed. |
| `level_too_high` | The pack declares a level its recorded result does not support. |

The command reads files only. It runs no scanner, no model and no network. Exit code 1 means a pack failed.

## 6. Open or Pro

The split follows the open core rule: a check belongs to the open engine when it settles at least one Free requirement. The manifest, the extractor, the vocabulary, the recorded result and the checks that settle at least one Free requirement are part of the open engine. A check or rule file that settles only Pro requirements is Pro, and the manifest marks it `"pro": true`. The planted flaw fixtures are internal and ship in neither edition. The answer keys outside the repository stay on the maintainer's machine.

## 7. Honest levels in the report and the README

The coverage table in the README and the section "Stack coverage" in `report.md` are generated from the packs by `src/packs/coverage.ts`. Nothing in them is typed by hand. A test fails if the README table differs from the generator output, or if a table row shows a level above what the recorded result supports.
