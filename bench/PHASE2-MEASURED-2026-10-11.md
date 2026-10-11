# Phase 2 code map, measured 2026-10-11

This file holds every number from the Phase 2 measurement, each with its limits beside it. The hand counts the map was compared with are in `bench/PHASE2-ENTRYPOINTS.md`. Nothing here is a claim for the README.

## 1. How it was run

| Item | Value |
|---|---|
| Engine | `src/` as of commit a3035af on branch dev (version 0.4.0). Commits after it change only documents, `rules/tiers.json` and one test, and do not change what the runs below produced |
| Phase 1 engine, for the baseline | commit e4b3ac6 (`git archive`), run the same way on the same demo clone |
| Tools | Semgrep 1.176.0, Gitleaks 8.30.1 and Trivy 0.75.0 ran (Trivy only where a target has infrastructure files, which is Juice Shop). OSV Scanner 2.6.0 is installed and was skipped (network not allowed) |
| Machine | macOS (Darwin 25.6.0), Node 22.23.2 |
| Options | defaults: Pro edition, stage LAUNCH, network off, the Pro kit, with the Pro edition's additional rules (not published) unless a row says open core |
| Targets | `hullproof-demo` 3e7c205, OWASP Juice Shop 0e6d909, OWASP BenchmarkPython f129148, all read only. `git status` in every target was clean after the runs. The demo was cloned to a scratch folder for the scans. No target code was copied into this repository |
| Runs | `scan`, `report`, `gate --date 2026-10-11`, three times per target (Juice Shop and BenchmarkPython), and three times on the demo with the Pro edition's additional rules (not published) |
| Sampling | `node bench/sample.ts --seed 20261011`, described in `bench/PHASE2-ENTRYPOINTS.md` section 3 |

The new checks start as leads (`rules/tiers.json` default for `check.map.*`). Every number below was taken with that default. After the hand checks in section 4 the tier file was updated by the existing rule (section 6).

## 2. The demo

### 2.1 Entry points

| Item | Result |
|---|---|
| Hand count (written before the extractors, `bench/PHASE2-ENTRYPOINTS.md` section 2) | 27 entry points: 19 HTTP handlers, 1 server action, 4 pages, 3 AI tools |
| Found by the map | 27 of 27, each at the hand counted file and line. 0 extra entries |
| By kind | 18 http_route, 1 webhook, 1 server_action, 4 page, 3 ai_tool |
| Protection facts compared with the hand table (20 handlers, 6 columns) | 44 of 44 cells where both gave an answer agree. In 5 more cells the hand table answered and the map makes no claim (a column that does not apply to that handler) |
| Time for `hullproof map` | about 30 to 70 milliseconds inside the process |
| Gate | 1 gate: the middleware, which only checks that a cookie named `session` exists (a weak sign, low confidence) and only for the `/admin` and `/api/admin` prefixes |

`node bench/compare-entrypoints.ts` and `node bench/demo-protections.ts` reproduce the two comparisons.

### 2.2 Planted flaws

Scored with `bench/score.ts` against the private demo key and `bench/keys/demo-classes.json`, the same inputs as Phase 1. The findings record is `report.findings.md`. The score counts a lead (an observation) as PARTIAL when it names the right file and defect.

| Engine and rule set | FOUND | PARTIAL | MISSED | Free flaws found | Flagged false positives |
|---|---|---|---|---|---|
| Phase 1 (e4b3ac6), open core rules | 20 | 1 | 9 | 12 | 0 |
| Phase 1, with the Pro edition's additional rules (not published) | 21 | 1 | 8 | 13 | 0 |
| Phase 2, open core rules, new checks as leads (the default) | 20 | 7 | 3 | 12 | 0 |
| Phase 2, with the Pro edition's additional rules (not published), new checks as leads (the default) | 21 | 6 | 3 | 13 | 0 |
| Phase 2, open core rules, if the new checks counted as gate | 26 | 1 | 3 | 14 | 0 |
| Phase 2, with the Pro edition's additional rules (not published), if the new checks counted as gate | 26 | 1 | 3 | 14 | 0 |

The Phase 1 rows reproduce the earlier numbers (20 and 21 of 30). With the checks at their default tier (leads) the FOUND count does not move, because a lead never fails a requirement. What the new checks add is leads on the right files: PARTIAL goes from 1 to 7 with the open core and from 1 to 6 with the Pro edition's additional rules (not published). The two "if gate" rows are a scenario, made with a scratch rule pack whose `tiers.json` lists the 17 checks as gate. They show what the checks would add if they were trusted, not what ships.

What the new checks add, per flaw (open core to the Pro edition's additional rules (not published)):

| Flaw | Phase 1 | Phase 2 as leads | If gate | Check that points at it |
|---|---|---|---|---|
| F02 clients write their own role and plan | MISSED (open core), FOUND (the Pro edition's additional rules (not published)) | PARTIAL (open core), FOUND (the Pro edition's additional rules (not published)) | FOUND | `supabase-privileged-column-grant`, `privileged-field-from-request` |
| F03 export route has no authentication | MISSED | PARTIAL | FOUND | `data-read-without-auth` |
| P11 uploads have no size limit or type check | MISSED | PARTIAL | FOUND | `upload-without-limits` |
| P12 open redirect | MISSED | PARTIAL | FOUND | `redirect-from-request` |
| P13 no audit record for admin actions | MISSED | PARTIAL | FOUND | `privileged-action-without-audit` |
| P15 page size from the query string with no maximum | MISSED | PARTIAL | FOUND | `page-size-from-request` |

Still missed by every row: F14 (prompt injection into tool calls), P10 (no caps on model calls) and P14 (no self service account deletion). P09 stays PARTIAL because its requirement is a GROWTH requirement and the run is at LAUNCH, as in Phase 1.

The 17 checks on the demo (evidence items): `admin-route-without-role` 3, `auth-endpoint-without-rate-limit` 2, `data-read-without-auth` 1, `page-size-from-request` 1, `privileged-action-without-audit` 2, `privileged-field-from-request` 2, `redirect-from-request` 1, `request-url-fetched` 1, `supabase-open-table` 1, `supabase-privileged-column-grant` 1, `upload-without-limits` 1, `webhook-verify-before-use` 1, `write-by-id-without-owner` 3. `input-without-schema`, `mutating-route-without-auth` and `supabase-policy-trusts-claims` found nothing, which is right for the demo: every body is parsed with zod and every mutating route reads the session. `firebase-auth-only-rule` did not apply.

### 2.3 Stability

Three runs with the Pro edition's additional rules (not published): the sha256 over every file of the scan folder except `run.json` and `kit.local.json` was `c91218e46085fe98...` in all three (codemap.json alone: `2d4ea607c8401f8b...`). The gate output was identical in all three and identical to the Phase 1 gate output on the demo (`a49225749d98a4c4...`).

### 2.4 Limits of the demo numbers

1. The demo key was read before the check list was written, and the list contains a check for each of P11, P12, P13 and P15. The demo is therefore an upper estimate of what these checks catch on an app they were not shaped by. Section 3 and 4 are the independent measure.
2. The extractors were shaped by the demo, so the 27 of 27 and the 44 of 44 are not blind.
3. The scorer counts a finding on the right file with the right words. It does not check that a compound flaw is covered in full.

## 3. Entry points on Juice Shop and BenchmarkPython

### 3.1 Results

| Item | Juice Shop (Express, TypeScript) | BenchmarkPython (Flask) |
|---|---|---|
| Sampled routes found in the map (25 drawn with seed 20261011) | 25 of 25 | 25 of 25 |
| Registrations by a separate reading of the code | 117 registration lines | 2463 `@app.route(` decorators |
| Entry points in the map | 143: 118 HTTP routes, 25 AI tools | 2463 HTTP routes (1233 GET, 1230 POST) |
| Registration lines without an entry point | 0 | 0 |
| Entry points without a registration line | 5 chained `.get(` `.put(` `.delete(` lines after `app.route(`, found by the map and missed by the line based reading, and 1 extra entry because one registration has two paths | 0 |
| Of the 25 AI tool entries in Juice Shop | 4 in `routes/chat.ts` are real tools. 21 are in `data/static/codefixes/`, code snippets that the app shows as lessons and does not serve | none |
| Seeded precision sample of the map entries (25 drawn with the same seed) | 21 real, 4 not real (all four are `codefixes` snippets). 21 of 21 outside that folder | not sampled: every entry is one of the 2463 decorators |
| Language rows | typescript: partly mapped (socket.io is seen and not read), javascript: partly mapped for the same reason, python: mapped (3 files, none with routes) | python: partly mapped (aiohttp and tornado are detected as dependencies and not read), javascript: mapped |
| Time for the whole `scan` with the Pro edition's additional rules (not published), three runs | 76.15, 89.46 and 90.38 seconds | 13.94, 14.07 and 15.21 seconds |
| Size of `codemap.json` | 166 KB | 1.96 MB |

### 3.2 What the map does not see

On Juice Shop: the 14 model resources that `finale.resource` turns into REST routes at run time (up to 70 routes, `server.ts` lines 502 to 530), the 40 `app.use('/path', ...)` lines that mount a static folder or a middleware (they are gates in the map, not entry points), and the socket.io handlers. On BenchmarkPython nothing was missed that the decorators show. These are the same limits the README states in general terms.

### 3.3 Limits of the entry point numbers

1. The extractors were developed while looking at the route files of both targets. 25 of 25 is a recall check on code the extractors were shaped by.
2. The candidate lines come from a broad `grep`, which keeps the draw independent of the extractors. A route that registers itself in a way no `grep` pattern for `get(`, `post(` or `route(` would show (a loop, a string built at run time) is outside both the draw and the count.
3. Twenty five is a small sample. The full comparison (117 and 2463 lines against the map) is the stronger number, and it is also against lines a `grep` can find.

## 4. New findings on Juice Shop and BenchmarkPython

A new finding is one evidence item of a `check.map.*` result: a place the check says is wrong. The checks start as leads, so none of these fails a requirement or holds the gate.

### 4.1 Counts

| Check | Juice Shop | BenchmarkPython |
|---|---|---|
| `mutating-route-without-auth` | 45 | 1193 |
| `input-without-schema` | 17 | 287 |
| `data-read-without-auth` | 5 | 0 |
| `admin-route-without-role` | 2 | not applicable (no admin area) |
| `write-by-id-without-owner` | 2 | not applicable |
| `auth-endpoint-without-rate-limit` | 1 | not applicable |
| `privileged-field-from-request` | 1 | not applicable |
| `upload-without-limits` | 1 | not applicable |
| Total | 74 | 1480 |

The other checks found nothing to judge on these two targets (no webhook, no database policy file, no Firebase rules, no audit area). The scan of BenchmarkPython failed on its first run because 1480 lead records passed the 200000 character limit of the kit validator. That is fixed (section 5) and the runs here are after the fix.

### 4.2 Hand checked sample of 20 per target

The 20 are drawn with `node bench/sample.ts --seed 20261011 --n 20` from the list of `check|file:line` evidence items of run 1. A finding is TRUE when the place does what the check says: for a route check, the route really lacks the protection, and for `mutating-route-without-auth` the handler really changes something (data, a file, a session store or other shared state). It is FALSE when the code at that place has the protection by some other means, when the route is blocked for everyone, or when the handler only reads and renders. One reviewer (this agent) made every call, by reading the handler.

Juice Shop (8 of 20 TRUE):

| # | Check | Where | Verdict | Why |
|---|---|---|---|---|
| 1 | data-read-without-auth | `routes/userProfile.ts:41` | FALSE | the handler looks the caller up with `security.authenticatedUsers.get(req.cookies.token)` and refuses when there is none; the map does not know that call as a session read |
| 2 | mutating-route-without-auth | `server.ts:664` POST /rest/web3/walletExploitAddress | TRUE | adds the address to a shared set and starts a listener, no sign in |
| 3 | data-read-without-auth | `routes/wallet.ts:12` | FALSE | registered with `security.appendUserId()`, which answers 401 without a valid token; not known to the map |
| 4 | input-without-schema | `server.ts:648` POST /rest/deluxe-membership | TRUE | reads `req.body` with no schema |
| 5 | mutating-route-without-auth | `server.ts:408` PUT /api/Recycles/:id | FALSE | `security.denyAll()` blocks the route for everyone |
| 6 | input-without-schema | `routes/dataErasure.ts:74` | TRUE | reads the body with no schema |
| 7 | input-without-schema | `server.ts:639` POST /rest/user/data-export | TRUE | reads the body with no schema |
| 8 | mutating-route-without-auth | `server.ts:460` DELETE /api/Cards/:id | FALSE | registered with `security.appendUserId()` |
| 9 | write-by-id-without-owner | `routes/likeProductReviews.ts:50` | FALSE | the update is a like, which any signed in user may add to any review; the owner is not the point |
| 10 | mutating-route-without-auth | `server.ts:409` DELETE /api/Recycles/:id | FALSE | `security.denyAll()` |
| 11 | input-without-schema | `server.ts:664` | TRUE | reads `req.body.walletAddress` with no schema |
| 12 | mutating-route-without-auth | `server.ts:390` DELETE /api/Products/:id | FALSE | `security.denyAll()` |
| 13 | mutating-route-without-auth | `server.ts:329` POST /profile/image/file | FALSE | the handler checks `security.authenticatedUsers.get(req.cookies.token)` first |
| 14 | data-read-without-auth | `routes/orderHistory.ts:27` | FALSE | registered with `security.isAccounting()`, a role check that also needs a valid token |
| 15 | mutating-route-without-auth | `server.ts:633` PUT /rest/continue-code/apply/:continueCode | TRUE | solves challenges for the instance, no sign in |
| 16 | input-without-schema | `server.ts:644` PUT /rest/order-history/:id/delivery-status | TRUE | reads the body with no schema (a role check is present) |
| 17 | privileged-field-from-request | `routes/memory.ts:17` | FALSE | the record is built from named fields, and `UserId` is set by `appendUserId()`; the whole request object is not passed on |
| 18 | mutating-route-without-auth | `server.ts:690` POST /snippets/verdict | TRUE | marks a challenge as found, no sign in |
| 19 | mutating-route-without-auth | `server.ts:392` POST /api/Challenges | FALSE | `security.denyAll()` |
| 20 | mutating-route-without-auth | `server.ts:411` POST /api/SecurityQuestions | FALSE | `security.denyAll()` |

BenchmarkPython (12 of 20 TRUE):

| # | Check | Where | Verdict | Why |
|---|---|---|---|---|
| 1 | input-without-schema | `testcode/BenchmarkTest00257.py:27` | TRUE | reads the form, no schema |
| 2 | mutating-route-without-auth | `BenchmarkTest00965.py:27` | TRUE | writes the remember me session store, no sign in |
| 3 | mutating-route-without-auth | `BenchmarkTest00608.py:27` | FALSE | loads YAML from a header and returns text; changes nothing |
| 4 | mutating-route-without-auth | `BenchmarkTest00322.py:27` | TRUE | appends a hash to a file |
| 5 | mutating-route-without-auth | `BenchmarkTest00824.py:27` | FALSE | LDAP search, read only |
| 6 | mutating-route-without-auth | `BenchmarkTest00403.py:27` | TRUE | writes the session store |
| 7 | mutating-route-without-auth | `BenchmarkTest00750.py:27` | TRUE | opens a file for writing |
| 8 | mutating-route-without-auth | `BenchmarkTest00967.py:27` | TRUE | writes the session store |
| 9 | mutating-route-without-auth | `BenchmarkTest01216.py:27` | TRUE | unpickles input and sets a shared module variable (weak) |
| 10 | mutating-route-without-auth | `BenchmarkTest01050.py:27` | TRUE | writes the session store |
| 11 | mutating-route-without-auth | `BenchmarkTest01039.py:27` | FALSE | XPath query, read only |
| 12 | input-without-schema | `BenchmarkTest00212.py:27` | TRUE | reads the form, no schema |
| 13 | mutating-route-without-auth | `BenchmarkTest00321.py:27` | TRUE | appends a hash to a file |
| 14 | mutating-route-without-auth | `BenchmarkTest00331.py:27` | TRUE | appends a hash to a file |
| 15 | mutating-route-without-auth | `BenchmarkTest00374.py:27` | FALSE | XPath query, read only |
| 16 | mutating-route-without-auth | `BenchmarkTest00294.py:27` | FALSE | XML parse, read only |
| 17 | mutating-route-without-auth | `BenchmarkTest00015.py:34` | FALSE | XPath query, read only |
| 18 | mutating-route-without-auth | `BenchmarkTest01218.py:27` | FALSE | XPath query, read only |
| 19 | mutating-route-without-auth | `BenchmarkTest00183.py:27` | FALSE | reads a file |
| 20 | input-without-schema | `BenchmarkTest00198.py:27` | TRUE | reads the form, no schema |

### 4.3 Precision

| | Juice Shop | BenchmarkPython | Both |
|---|---|---|---|
| All checks | 8 of 20 (0.40) | 12 of 20 (0.60) | 20 of 40 (0.50) |
| `mutating-route-without-auth` | 3 of 10 | 9 of 17 | 12 of 27 (0.44) |
| `input-without-schema` | 5 of 5 | 3 of 3 | 8 of 8 (1.00) |
| `data-read-without-auth` | 0 of 3 | none drawn | 0 of 3 |
| `write-by-id-without-owner` | 0 of 1 | none drawn | 0 of 1 |
| `privileged-field-from-request` | 0 of 1 | none drawn | 0 of 1 |

A 95 percent interval for 8 of 20 is roughly 0.22 to 0.61, for 12 of 20 roughly 0.39 to 0.78, and for 20 of 40 roughly 0.35 to 0.65 (Wilson). The samples are small, one reviewer made every call, and both targets are deliberately vulnerable teaching apps, which makes a TRUE more likely than in an ordinary app. The checks that never fired on a target (webhooks, policies, rules) were not measured here at all; their only evidence is the fixtures.

Why the FALSE calls happened, in order of how many they cover (nothing below was changed after the measurement):

1. A route protected by a middleware or a handler line whose name the vocabulary does not know: `appendUserId` and the app's own token map (`authenticatedUsers.get(req.cookies.token)`) on 4 routes, and `denyAll`, which blocks the route for everyone, on 5. That is 9 of the 12 FALSE calls on Juice Shop.
2. A role check middleware (`isAccounting`) is not counted as authentication by the data read check, although a role check needs a signed in user. 1 call.
3. In BenchmarkPython the check calls every POST a route that changes state. 8 of its 20 calls were handlers that only read or parse. This is a design weakness of using the method as the sign of a state change.
4. `write-by-id-without-owner` flagged a like, where ownership is not the point. `privileged-field-from-request` took an explicitly built record for a whole request object.

### 4.4 Stability

Three runs per target, the sha256 over every file of the scan folder except `run.json` and `kit.local.json`:

| Target | Files per run | Folder sha256 (first 16), all 3 runs | codemap.json (first 16) | checks.json (first 16) | Gate output (first 16) |
|---|---|---|---|---|---|
| BenchmarkPython | 20 | 3ab871d565f00b7c | 59d9fa2788653aed | 8f815ad7ea0d9ff9 | 9c2c67af4539681b |
| Juice Shop | 20 | c2ddf65954a4488f | b67e27e9085558f1 | a303a63fd427d700 | 59bc9e58bab8792c |

All three runs were byte identical for each target. The gate outputs are the same bytes as the Phase 1 of the Pro edition's additional rules (not published) gate outputs on the same commits (`9c2c67af4539681b` and `59bc9e58bab8792c`), because the new findings are leads. On BenchmarkPython `checks.json` is also byte identical to the one from the first run, before the fix in section 5, which shows that the fix changed only how the findings record is written.

## 5. What the measurement found and fixed

1. Over the kit limit (commit 85a6ff9). 1480 lead records on BenchmarkPython passed the 200000 character limit of the kit validator, so `scan` exited 2. A check lead in more than 20 files is now one record that says how many places there are; every place stays in `checks.json`.
2. Wrong file under a line number (commit a3035af). For a route registered in one file with its handler in another (Juice Shop), the evidence of a data or outbound finding carried the handler's line number under the registering file. It now names the handler's file.

## 6. Known misses and weaknesses, not fixed

These are queued. None was changed after the measurement, so the numbers above describe the engine as it is.

1. Allowlist words in comments. The guard test for an outbound call (`URL_GUARD`) and for a redirect runs on the handler text including comments. Juice Shop's `profileImageUrlUpload` has a comment that names an SSRF challenge, so its `fetch(url)` counted as guarded and `request-url-fetched` missed a real SSRF. The test should run on text with comments blanked.
2. Vocabulary. The map did not know `appendUserId`, `denyAll`, `authenticatedUsers.get(token)` or a role middleware as authentication (section 4.3). A role check or a signature check should imply a signed in caller for the data read check.
3. POST is not proof of a state change. The check should look at what the handler does (a write to a data store, a file or a session) and not at the method.
4. `app.use('/path', handler)` mounts that serve content, and run time generated routes, are not entry points.
5. Express routes defined by `app.route(path).get().put()` chains are found; Koa style `router.use` stacks and Hapi style `server.route({...})` objects are not (the coverage row says partly mapped when the framework is detected).

## 7. The tier file after the measurement

By the rule in the README (at least 3 judged, a lead moves to gate at precision 0.80 or more), `rules/tiers.json` now lists:

| Check | Judged | True | Precision | Tier |
|---|---|---|---|---|
| the Pro edition's additional rules (not published) | 8 | 8 | 1.00 | lead (held until about 20 are judged, decision of 2026-10-11) |
| `check.map.mutating-route-without-auth` | 27 | 12 | 0.44 | lead |
| `check.map.data-read-without-auth` | 3 | 0 | 0.00 | lead |
| `check.map.write-by-id-without-owner` | 1 | 0 | 0.00 | lead (fewer than 3 judged) |
| `check.map.privileged-field-from-request` | 1 | 0 | 0.00 | lead (fewer than 3 judged) |

The other 12 checks have no judged finding and stay leads by default.

the Pro edition's additional rules (not published) first moved to gate on these 8 judged findings from two teaching apps. The maintainer reversed that on 2026-10-11: it stays a lead until about 20 findings are judged, including a repository that is not a teaching app. The tier entry says so with `"needs_judged": 20` beside the measured precision, the report gives the reason as fewer judged findings than needed, and no number in this file changed. That check settles only Pro requirements, so its entry is in the Pro tier file and not in the open `rules/tiers.json`.

## 8. How to repeat it

```
node src/cli.ts map TARGET --out -
node src/cli.ts scan TARGET --out OUT --kit KIT [--rule-pack PACK/semgrep]
node bench/compare-entrypoints.ts --hand bench/PHASE2-ENTRYPOINTS.md --section "2. The demo" OUT/<commit>/codemap.json
node bench/demo-protections.ts OUT/<commit>/codemap.json
node bench/sample.ts --seed 20261011 --n 20 LIST.txt
node bench/score.ts --key DEMO-ANSWER-KEY.md --classes bench/keys/demo-classes.json findings=OUT/<commit>/report.findings.md
```

The gate scenario rows in section 2.2 use a scratch rule pack: a folder with a `semgrep/` subfolder and a `tiers.json` beside it that lists the 17 checks with `"tier": "gate"`, passed to `--rule-pack`.

## 9. Second wave: Go, Rails, Laravel and Expo (added 2026-10-11, after sections 1 to 8)

The extractors for Go, Ruby on Rails, PHP and Laravel, and Expo and React Native were built the same way as the Node and Python ones: TypeScript written for this engine, no runtime dependency, the same bytes for the same files. What each reads is in `README.md`. The numbers below are the whole measurement, with its limits.

### 9.1 What was run

`node bench/second-wave.ts` on the synthetic apps in `test/fixtures/map-more`. Each stack has a fail copy with planted flaws and a pass copy with the flaws fixed: Go (chi plus net/http patterns), Go (gin), Rails, Laravel and Expo. The entry points were counted by hand from the sources before the extractors were run on them. The checks are the ones of section 4, unchanged.

| Stack | Hand counted entry points | Found, fail copy | Found, pass copy | Planted flaws flagged | Flags in the pass copy |
|---|---|---|---|---|---|
| Go (chi) | 9 | 9 | 9 | 13 of 13 | 0 |
| Go (gin) | 3 | 3 | 3 | 4 of 4 | 0 |
| Rails | 9 | 9 | 9 | 13 of 13 | 0 |
| Laravel | 9 | 9 | 9 | 13 of 13 | 0 |
| Expo | 9 | 9 | 9 | 2 of 2 | 0 |

1. Entry points: 39 of 39 hand counted, 0 extra, in both copies. For Expo the nine are four screens, one API route and four deep links (three from `app.json`, one from a `Linking` listener).
2. Planted flaws: 45 of 45 flagged in the fail copies, 0 flags in the pass copies. The open edition loads 9 of the 13 map checks; the other 4 settle only Pro requirements, so the open run counts 9 planted flaws per stack where the table says 13. The table above is the Pro working copy.
3. Stability: three runs gave the same `codemap.json` bytes for both copies (sha256 prefixes `20865b73dec5` fail, `e25f9dd0b861` pass).
4. Protection facts read from the right place: a webhook whose signature check does not stop the request is recorded as ignored in all three server stacks; a group, router or controller middleware, a Rails `before_action` (inherited, skipped by action, and from an included concern), a Laravel constructor middleware with `only` and `except`, and an Expo layout guard each reach the entry points under them, and not the ones outside them. `test/codemap-more.test.ts` asserts each of these.
5. Negative control: 8 Go, Ruby and PHP files that sit in the third party JavaScript projects of the local CVE subset (test pages, a documentation plugin, a push client) gave 0 entry points.
6. Regression: after the changes the demo is still 27 of 27 entry points and 44 of 44 protection cells, and the check counts on the demo, Juice Shop and BenchmarkPython are the same as in sections 2.2 and 4.1.

### 9.2 One fix found while building the Expo screens

A Supabase client call such as `supabase.from('notes').select('*')` was not read as a data touch in JavaScript and TypeScript, because the statement scan started inside the call and stopped at the first closing bracket. It now starts at the `.from` and reads the whole chain. The measured targets above do not contain such a call in a handler, which is why no number moved.

### 9.3 Limits

1. The fixtures were written by the person who wrote the extractors, in the same session, knowing which checks exist. The 45 of 45 and the 39 of 39 are an upper estimate. They show that the extractors read the forms the fixtures use and nothing about how often real code uses other forms.
2. No real Go, Rails, Laravel or Expo application was available locally, and no third party target was downloaded for this pass. So there is no precision figure, no hand checked sample of findings and no recall figure on real code for these four stacks. Every finding from these stacks is a lead until a measurement exists.
3. Routing forms read but only covered by a small inline test or by hand probes, not by the fixtures: net/http patterns with a method, echo, fiber and gorilla/mux, a chi router mounted from a function, Rails `namespace`, `scope`, `member`, `collection`, `authenticate` blocks and mounted engines, Laravel `Route::group` with an array, `controller()` groups, invokable controllers and resources with dots.
4. Not read: Rails `concern` blocks in `routes.rb` and `devise_for` routes (their controllers are library code), Laravel Livewire, Inertia and Volt components, route files loaded by a package, Go routes registered through reflection or a generated router, Expo screens defined outside `app/` and React Navigation screen names. The coverage table says so for the languages it can tell.
5. Expo layout guards are client side redirects. They keep a signed out person from seeing a screen. They do not stop a request to your server, so the map records them with `via` set to `expo layout guard (client side)`, scope `router` and confidence `medium`, and no check treats a screen guard as a server check. No check reads the Expo entry points yet.
6. The 8 file negative control is small.
