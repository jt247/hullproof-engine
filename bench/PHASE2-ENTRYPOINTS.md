# Phase 2 entry point hand count, 2026-10-11 (internal)

This file holds the hand counts the code map is measured against. They were made by reading the target, before the extractors were written, so the count does not depend on what the engine can find. The measured results are in `bench/PHASE2-MEASURED-2026-10-11.md`.

## 1. What counts as an entry point

An entry point is a unit of code that something outside the process can trigger:

1. An HTTP handler, one per method and path (a route file that exports GET and POST is two).
2. A server action.
3. A page route that the framework serves (one per `page` file).
4. A function handed to a model as a tool.
5. A webhook, which is an HTTP handler (counted once, as an HTTP handler).
6. A background job, schedule, message consumer, RPC or GraphQL resolver, and a mobile deep link, where the target has any.

Middleware is not an entry point. It is a gate that sits in front of entry points, and the map records it as a gate.

## 2. The demo (`hullproof-demo`, commit 3e7c205), read only

The demo is a Next.js app router project (`next` 13.4.0 in package.json) with 32 files under `src/`. Hand count: 27 entry points.

HTTP handlers (19):

| # | Method and path | File and line |
|---|---|---|
| 1 | GET /api/admin/users | `src/app/api/admin/users/route.ts:9` |
| 2 | POST /api/admin/users | `src/app/api/admin/users/route.ts:17` |
| 3 | DELETE /api/admin/users | `src/app/api/admin/users/route.ts:25` |
| 4 | POST /api/ai/assistant | `src/app/api/ai/assistant/route.ts:24` |
| 5 | POST /api/auth/login | `src/app/api/auth/login/route.ts:13` |
| 6 | POST /api/auth/logout | `src/app/api/auth/logout/route.ts:6` |
| 7 | POST /api/auth/signup | `src/app/api/auth/signup/route.ts:10` |
| 8 | GET /api/files/[id] | `src/app/api/files/[id]/route.ts:5` |
| 9 | POST /api/files | `src/app/api/files/route.ts:5` |
| 10 | GET /api/me | `src/app/api/me/route.ts:4` |
| 11 | GET /api/notes/[id] | `src/app/api/notes/[id]/route.ts:10` |
| 12 | PATCH /api/notes/[id] | `src/app/api/notes/[id]/route.ts:18` |
| 13 | DELETE /api/notes/[id] | `src/app/api/notes/[id]/route.ts:29` |
| 14 | GET /api/notes/export | `src/app/api/notes/export/route.ts:5` |
| 15 | POST /api/notes/import-url | `src/app/api/notes/import-url/route.ts:8` |
| 16 | GET /api/notes | `src/app/api/notes/route.ts:8` |
| 17 | POST /api/notes | `src/app/api/notes/route.ts:18` |
| 18 | GET /api/search | `src/app/api/search/route.ts:5` |
| 19 | POST /api/webhooks/payfake | `src/app/api/webhooks/payfake/route.ts:13` |

Server action (1):

| # | Name | File and line |
|---|---|---|
| 20 | updateProfile | `src/app/actions/profile.ts:15` |

Page routes (4), all client components except the home page:

| # | Path | File and line |
|---|---|---|
| 21 | / | `src/app/page.tsx:3` |
| 22 | /login | `src/app/login/page.tsx:5` |
| 23 | /dashboard | `src/app/dashboard/page.tsx:9` |
| 24 | /admin | `src/app/admin/page.tsx:8` |

Model tools (3), the functions in the `tools` object that the assistant route runs when the model names them:

| # | Tool | File and line |
|---|---|---|
| 25 | read_note | `src/lib/ai/tools.ts:10` |
| 26 | archive_note | `src/lib/ai/tools.ts:13` |
| 27 | email_summary | `src/lib/ai/tools.ts:17` |

Not counted: `src/app/layout.tsx` (a layout, not served on its own), and `src/middleware.ts:4`, which is a gate for `/admin/:path*` and `/api/:path*` (recorded as a gate in the map; it checks only that a cookie named `session` exists).

Not in the demo: background jobs, schedules, message consumers, GraphQL or RPC resolvers, mobile deep links.

Hand count of protections, for the 19 HTTP handlers and the server action (reading each handler body), used only to check the map's protection facts by hand:

| Handler | Session read | Role check | Owner filter on its data reads and writes | Signature check | Rate limit | Input schema |
|---|---|---|---|---|---|---|
| admin/users GET, POST, DELETE | yes (`currentUser`) | no | not applicable | no | no | POST and DELETE |
| ai/assistant POST | yes | no | yes (the note read) | no | a per user daily budget in code, no shared limiter | yes |
| auth/login POST | no (public by design) | no | not applicable | no | no | yes |
| auth/logout POST | no (reads the cookie) | no | not applicable | no | no | no |
| auth/signup POST | no (public by design) | no | not applicable | no | no | yes |
| files/[id] GET | yes | no | yes | no | no | no |
| files POST | yes | no | not applicable | no | no | no (the file is not checked) |
| me GET | yes | no | not applicable | no | no | no |
| notes/[id] GET | yes | no | no | no | no | no |
| notes/[id] PATCH | yes | no | yes | no | no | yes |
| notes/[id] DELETE | yes | no | yes | no | no | no |
| notes/export GET | no | no | no | no | no | no |
| notes/import-url POST | yes | no | not applicable | no | no | yes |
| notes GET | yes | no | yes | no | no | no (limit unbounded) |
| notes POST | yes | no | not applicable | no | no | yes |
| search GET | yes | no | yes (string built, owner term present) | no | no | no |
| webhooks/payfake POST | no | no | not applicable | checked, result not enforced | no | yes |
| action updateProfile | yes | no | yes (own id) | no | no | yes |

## 3. Juice Shop and BenchmarkPython

Both targets are read only copies in `bench-targets/`. Nothing from them is copied into this repository.

How the sample was drawn, the same way for both targets:

1. The candidate lines are found with a deliberately broad `grep`, so the candidates do not depend on what the extractors can read. Juice Shop: every line of a `.ts` or `.js` file outside `node_modules`, `frontend`, `test`, `dist`, `build` and `data/static/codefixes` that calls `app`, `router` or `server` with `get`, `post`, `put`, `patch`, `delete`, `all`, `options`, `head`, `use` or `route`. BenchmarkPython: every line of a `.py` file that contains `.route(`, `.get(`, `.post(`, `.put(`, `.patch(`, `.delete(`, `.add_url_rule(`, `.add_resource(` or `@app.`.
2. `node bench/sample.ts --seed 20261011` shuffles the candidates (sorted first, so the order of the files does not matter) and prints them in the order drawn.
3. Going down the drawn order, each line is labelled by reading it: a route (an `app.<method>(` call with a literal path, or an `@app.route(` decorator) or not a route. The draw stops at the 25th route.
4. `node bench/compare-entrypoints.ts` then checks that the map has an entry point at the file and line of each of the 25.

The extractors were written while looking at the demo, Juice Shop and BenchmarkPython route files, so this is a recall check on code the extractors were shaped by, not a blind test. A blind test needs a target nobody looked at.

### 3.1 Juice Shop (commit 0e6d909)

Drawn order: 180 candidates, the 25th route was the 38th line drawn. Lines drawn that were not routes (all `app.use(...)`, which mount middleware or static folders and are gates in the map, not entry points): `server.ts:402`, `server.ts:233`, `server.ts:373`, `server.ts:301`, `server.ts:296`, `server.ts:697`, `server.ts:300`, `server.ts:378`, `server.ts:701`, `server.ts:417`, `server.ts:238`, `server.ts:326`, `server.ts:308`.

| # | Method and path | File and line |
|---|---|---|
| 1 | POST /rest/deluxe-membership | `server.ts:648` |
| 2 | POST /api/SecurityQuestions | `server.ts:411` |
| 3 | GET /rest/user/authentication-details | `server.ts:620` |
| 4 | PUT /api/Feedbacks/:id | `server.ts:452` |
| 5 | PATCH /rest/products/reviews | `server.ts:653` |
| 6 | GET /rest/web3/nftMintListen | `server.ts:662` |
| 7 | DELETE /api/Products/:id | `server.ts:390` |
| 8 | POST /rest/user/data-export | `server.ts:640` |
| 9 | PUT /rest/continue-code-findIt/apply/:continueCode | `server.ts:631` |
| 10 | GET /snippets/:challenge | `server.ts:689` |
| 11 | GET /rest/memories | `server.ts:649` |
| 12 | GET /api/Cards | `server.ts:458` |
| 13 | GET /rest/country-mapping | `server.ts:637` |
| 14 | POST /rest/user/data-export | `server.ts:639` |
| 15 | POST /api/Feedbacks | `server.ts:423` |
| 16 | GET /video | `server.ts:682` |
| 17 | GET /api/Cards/:id | `server.ts:461` |
| 18 | POST /profile | `server.ts:686` |
| 19 | GET /snippets/fixes/:key | `server.ts:691` |
| 20 | GET /api/Recycles | `server.ts:404` |
| 21 | POST /rest/web3/walletExploitAddress | `server.ts:664` |
| 22 | DELETE /api/Addresss/:id | `server.ts:470` |
| 23 | GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility | `server.ts:672` |
| 24 | POST /rest/2fa/setup | `server.ts:484` |
| 25 | GET /rest/repeat-notification | `server.ts:627` |

Candidates in all: 180. Registration lines that are routes by the same reading: 117 (112 lines that start with `app.<method>(` or `router.<method>(` in `server.ts` and `routes/dataErasure.ts`, and 5 chained `.get(`, `.put(` and `.delete(` lines after `app.route(`). Not counted: the 40 `app.use('/path', ...)` lines, which mount a middleware or a static folder, and the 14 generated model resources (`finale.resource` in a loop over `autoModels`, `server.ts` lines 502 to 530), which the library turns into list, create, read, update and delete routes at run time, up to 70 routes. Neither group can be read from the registration lines.

Result is in `bench/PHASE2-MEASURED-2026-10-11.md`.

### 3.2 BenchmarkPython (commit f129148)

Drawn order: 3254 candidates, the 25th route was the 37th line drawn. The 12 lines drawn that were not routes were reads of `request.args`, `request.form` or `request.cookies` inside a handler.

| # | File and line |
|---|---|
| 1 | `testcode/BenchmarkTest00425.py:23` |
| 2 | `testcode/BenchmarkTest00684.py:23` |
| 3 | `testcode/BenchmarkTest00890.py:27` |
| 4 | `testcode/BenchmarkTest00780.py:27` |
| 5 | `testcode/BenchmarkTest00277.py:27` |
| 6 | `testcode/BenchmarkTest00796.py:23` |
| 7 | `testcode/BenchmarkTest00091.py:27` |
| 8 | `testcode/BenchmarkTest00576.py:27` |
| 9 | `testcode/BenchmarkTest00680.py:27` |
| 10 | `testcode/BenchmarkTest00297.py:23` |
| 11 | `testcode/BenchmarkTest00312.py:23` |
| 12 | `testcode/BenchmarkTest01142.py:23` |
| 13 | `testcode/BenchmarkTest01154.py:23` |
| 14 | `testcode/BenchmarkTest00457.py:27` |
| 15 | `testcode/BenchmarkTest01051.py:27` |
| 16 | `testcode/BenchmarkTest00571.py:23` |
| 17 | `testcode/BenchmarkTest00872.py:27` |
| 18 | `testcode/BenchmarkTest00478.py:27` |
| 19 | `testcode/BenchmarkTest01126.py:27` |
| 20 | `testcode/BenchmarkTest00871.py:27` |
| 21 | `testcode/BenchmarkTest00175.py:23` |
| 22 | `testcode/BenchmarkTest00391.py:23` |
| 23 | `testcode/BenchmarkTest00226.py:27` |
| 24 | `testcode/BenchmarkTest01127.py:23` |
| 25 | `testcode/BenchmarkTest00153.py:23` |

Routes by the same reading: 2463 `@app.route(` decorators, 2460 in `testcode/` (1230 test files with a GET and a POST each) and 3 in `app.py` (lines 36, 43 and 47).

Result is in `bench/PHASE2-MEASURED-2026-10-11.md`.
