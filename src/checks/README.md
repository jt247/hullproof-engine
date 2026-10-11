# Executable checks

A check settles part of one or more requirements from the files of a commit. It returns PASS (static), FAIL or a NOT ASSESSED sub state through its `on_true` and `on_false` words, or it does not run and says why in `checks.json` under `not_run` (`not applicable: ...` or `cannot run: ...`). No check runs a program, uses the network or a model.

Rules every check follows:

1. `PASS (static)` only when every requirement it names has repo authority. A check may FAIL a dashboard or runtime requirement for the part a file settles and never PASS it (STANDARD.md, "A file can fail what it cannot pass"). `test/checks.test.ts` enforces this against the kit's controls file.
2. A check that does not apply never becomes NOT APPLICABLE for its requirement: the requirement stays NOT ASSESSED.
3. Every check has `test/fixtures/checks/<name>/pass` and `.../fail`.
4. Checks never search `.hullproof/`, the kit's own folders or `docs/security/` (`LEFT_OUT` in `context.ts`).

Two forms:

1. Declarative: `checks/<area>.<name>.json`, shaped by `schemas/check.schema.json`, run by `ops.ts`.
2. TypeScript, for what no op can say: `src/checks/code/*.ts`, each exporting a `CodeCheck` (`types.ts`) and listed in `CODE_CHECKS` in `run.ts`.

## Op parameters

| Op | Params | True when |
|---|---|---|
| `file_exists` | `files` (globs), `exclude`, `note` | a listed file matches |
| `file_absent` | same | no listed file matches; the matches are the evidence |
| `file_exists_for_each` | `manifests`: manifest name to lockfile names, `note` | every manifest has a lockfile in its folder or a parent |
| `regex_present` | `files`, `exclude`, `only_if` (a file is searched only if it matches), `pattern`, `ignore_case`, `each_file` (every file must match), `when_no_files` (`not_applicable`, `true`, `false`), `precondition` {`files`, `exclude`, `pattern`} (no file meets it: not applicable; when nothing is found, its files are the evidence), `note`, `missing_note`, `precondition_note`, `not_applicable_reason` | the pattern is found (in every file with `each_file`) |
| `regex_absent` | the same | the pattern is found nowhere; the matches are the evidence |
| `sql_every_table_has` | `files`, `schemas` (default `public`) | every table created in those schemas has row level security enabled later in file order |
| `workflow_uses_pinned_sha` | `files` (default GitHub workflows) | every third party `uses:` ends in a 40 character SHA |
| `workflow_permissions` | `files` | every workflow declares permissions at the top or on every job, and none says `write-all` |
| `version_in_table` | `table` (kit relative path), `frameworks`: stack id to {`heading`, `package`, `digits`} | every declared version of a listed framework is on a line the kit's support table marks Supported |
| `json_value` | | not built; no check needs it yet |

Regex ops record an `absence_search` (pattern, file globs, files searched, matches) on every result.
