# Phase 1 engine on targets the checks were not written for, 2026-10-10

Section 9 (added later the same day) measures BenchmarkPython and Juice Shop again after test code handling and the taint rules were added, with a before and after table. Sections 1 to 8 are the earlier measurement.

The demo score in `bench/PHASE1-DEMO-SCORE.md` is an upper estimate, because the checks were written while reading the demo and its answer key. This file measures the same engine on four public targets in `../bench-targets/`: OWASP BenchmarkPython, OWASP Juice Shop, TerraGoat and the OpenSSF CVE Benchmark.

## 1. How it was run

| Item | Value |
|---|---|
| Engine | commit f1feb12 (branch dev), version 0.4.0-dev |
| Tools | Semgrep 1.176.0, Gitleaks 8.30.1, Trivy 0.75.0; OSV Scanner 2.6.0 installed but skipped (network not allowed) |
| Machine | macOS (Darwin 25.6.0), Node 22.23.2 |
| Options | defaults: Pro edition, stage LAUNCH (no target has `docs/security/STAGE.md`), network off, the Pro kit with the uncommitted `deterministic_only` change from the maintainers' working copy |
| Rule sets | "core": the 17 open core Semgrep files only. "pro": core plus the Pro edition's additional rules (not published) (28 files in all) |
| Runs | `scan`, `report`, `gate --date 2026-10-10`, three times per target and rule set, 24 runs in all |
| Output | a scratch folder under the session scratchpad. Nothing was written into a target, and `git status` in every target was clean after the runs. No target code was copied into this repository. |

Targets: BenchmarkPython f129148, juice-shop 0e6d909, terragoat 729f8da, ossf-cve-benchmark 91c59fd.

## 2. Stability

Every file in each scan folder except the timing files (`run.json`, `scan/run.json`), 19 files per run, plus the gate output, was hashed per run.

| Target | Rule set | Scan folder sha256 (first 16), all 3 runs | Gate output sha256 (first 16) | Byte identical | Scan exit | Gate |
|---|---|---|---|---|---|---|
| BenchmarkPython | core | ba3c71dd16ad339e | 8ae8e3bef505d6cf | yes | 0 | NOT READY, exit 1 |
| BenchmarkPython | pro | 5b37c17ea9c4fb22 | 9c2c67af4539681b | yes | 0 | NOT READY, exit 1 |
| TerraGoat | core | 24f2ebd76e8265a7 | 5f1fa52acd5a478c | yes | 0 | NOT READY, exit 1 |
| TerraGoat | pro | 668ffbc62243f183 | fbf7ee2a096bae7f | yes | 0 | NOT READY, exit 1 |
| OpenSSF CVE Benchmark | core | 42b3957f72745a0f | 4dc77ccac8ad38b7 | yes | 0 | NOT READY, exit 1 |
| OpenSSF CVE Benchmark | pro | 6d6eccdb39912ff3 | 4dc77ccac8ad38b7 | yes | 0 | NOT READY, exit 1 |
| Juice Shop | core | b978939b1582c1cb | 70f487fa6108fd18 | yes | 0 | NOT READY, exit 1 |
| Juice Shop | pro | c2d2bde0162bb483 | 59bc9e58bab8792c | yes | 0 | NOT READY, exit 1 |

All 24 runs were byte identical within their row. Run times: BenchmarkPython 11 to 14 seconds, TerraGoat 9 to 11, CVE Benchmark 7 to 11, Juice Shop 49 to 54 (core) and 77 to 98 (pro).

A bug found by this measurement and fixed before these runs (commit f1feb12): on Juice Shop with the Pro edition's additional rules (not published), the indented findings block was 207103 characters, over the kit validator's 200000 limit (rule F3), so `scan` and `gate` exited 2. The engine now writes the same sorted JSON on one line once the indented block passes the kit's 150000 warning size. An earlier batch of runs on commit a5d0534 showed the failure, three times identically.

## 3. BenchmarkPython: precision and recall

Ground truth: `expectedresults-0.1.csv`, 1230 test cases in 14 categories, each marked as a real vulnerability or not. A test case counts as flagged for a category when an engine finding of the mapped rule or check names a file whose path holds that test case name (`testcode/BenchmarkTestNNNNN.py`). Scoring follows the Benchmark's own method: for each category only that category's test cases are counted.

### 3.1 Category mapping

| Benchmark category | Engine rule or check that runs on Python | Status |
|---|---|---|
| sqli (CWE-89) | Semgrep `hullproof-raw-sql-concat`, `hullproof-sql-string-built-in-variable` (generic language) | covered |
| xss (CWE-79) | Semgrep: the Pro edition's additional rules (not published) (core); the Pro edition's additional rules (not published) (the Pro edition's additional rules (not published)) | covered |
| securecookie (CWE-614) | check the Pro edition's additional rules (not published), counted when its note names the missing Secure flag | covered |
| cmdi, codeinj, redirect, weakrand | the engine has rules for these in JavaScript and TypeScript only | not covered for Python |
| pathtraver, hash, ldapi, xpathi, deserialization, trustbound, xxe | no rule or check | not covered |

The not covered categories hold 1086 of the 1230 test cases (392 of them real vulnerabilities). They are not misses of anything the engine claims.

### 3.2 Results (identical for core and pro)

| Category | Cases (real / not real) | TP | FP | FN | TN | Precision | Recall | False positive rate |
|---|---|---|---|---|---|---|---|---|
| sqli | 5 / 11 | 0 | 0 | 5 | 11 | no flags | 0.00 | 0.00 |
| xss | 31 / 58 | 0 | 0 | 31 | 58 | no flags | 0.00 | 0.00 |
| securecookie | 24 / 15 | 24 | 0 | 0 | 15 | 1.00 | 1.00 | 0.00 |

Across the three covered categories: 24 true positives, 0 false positives, 36 false negatives; precision 1.00, recall 0.40 (24 of 60 real cases).

What the misses look like (read from the code): the SQL test cases build the query with a Python f string and pass it to `cursor.execute`, a shape the rules do not match. The XSS test cases concatenate request data into a response string returned by Flask, with no template, and no Python rule covers that. Semgrep scanned 1 file in the core run and 2486 in the pro run, because the core rule set's Python capable rules are limited by their own paths; neither run produced a Python hit.

Other engine output on this target: the cookie check also flagged a missing HttpOnly flag on 81 harness cookies in other categories' test cases (real, CWE-1004, but not what those test cases measure); the Pro edition's additional rules (not published) failed on `app.py`; and with the Pro edition's additional rules (not published) 4 Semgrep hits in `templates/js/testsuiteutils.js`, the harness's own JavaScript.

## 4. Juice Shop

### 4.1 Counts

| | core | pro |
|---|---|---|
| Semgrep hits (files scanned / tracked) | 36 (648 / 1300) | 141 (834 / 1300) |
| Gitleaks hits | 68 | 68 |
| Trivy hits (mapped) | 87 (1) | 87 (1) |
| Fail records: BLOCKER, CRITICAL, HIGH | 67: 58, 5, 4 | 117: 64, 44, 9 |
| Observations | 48 | 48 |
| Requirement rows FAIL | 14 | 19 |

Fail records per requirement (a record can name several requirements):

| Requirement | Severity, edition | core | pro |
|---|---|---|---|
| SEC-SECRETS-004 | BLOCKER, free | 26 | 32 |
| SEC-API-017 | BLOCKER, free | 25 | 25 |
| SEC-API-021 | BLOCKER, free | 6 | 6 |
| SEC-AUTHZ-003 | BLOCKER, free | 1 | 1 |
| SEC-MOBILE-002 | CRITICAL, free | 0 | 25 |
| SEC-WEB-031 | CRITICAL, free | 3 | 17 |
| SEC-AUTH-001 | CRITICAL, free | 2 | 2 |
| SEC-DATA-001 | CRITICAL, free | 2 | 2 |
| SEC-LOG-001 | CRITICAL, free | 2 | 2 |
| SEC-API-034, SEC-API-035 | CRITICAL, free | 1 each | 1 each |
| Pro requirement | HIGH, pro | 0 | 25 |
| Pro requirement | HIGH, pro | 0 | 19 |
| Pro requirement | HIGH, pro | 0 | 17 |
| Pro requirement | HIGH, pro | 0 | 6 |
| Pro requirement | HIGH, pro | 2 | 2 |
| Three Pro requirements | HIGH, pro | 1 each | 1 each |

Observations: 47 Trivy hits with no mapped requirement and one MEDIUM requirement (a GROWTH requirement outside the LAUNCH stage).

### 4.2 Hand check of 20 records (pro run)

Seed 20261010. Method: the fail and observation records of `report.findings.md`, in file order, shuffled with a Fisher and Yates shuffle driven by the mulberry32 generator with that seed; the first 20 were read in the code. TP means the code at the named place has the security weakness the record names. FP means it does not, or the matched condition is not a security weakness there.

| # | Kind, severity | Rule or check | Where | Verdict | Reason |
|---|---|---|---|---|---|
| 12 | observation | trivy AWS-0052 | data/static/codefixes/iacLeakedKeyChallenge_2.tf:121 | TP | load balancer does not drop invalid headers; the file is a challenge code snippet |
| 21 | observation | trivy AWS-0053 | data/static/codefixes/iacLeakedKeyChallenge_3_correct.tf:123 | FP | a public load balancer is the intended design of a public shop |
| 30 | observation | trivy AWS-0053 | infrastructure/terraform/networking.tf:124 | FP | same |
| 37 | observation | trivy AWS-0052 | terraform/networking.tf:122 | TP | invalid headers not dropped |
| 41 | observation | trivy AWS-0124 | terraform/networking.tf:68 | FP | missing rule description, no security effect |
| 46 | observation | trivy DS-0025 | test/smoke/Dockerfile:3 | FP | `apk add` without `--no-cache` is image size, not security |
| 48 | fail BLOCKER | semgrep hullproof-raw-sql-concat | data/static/codefixes/dbSchemaChallenge_1.ts:5 | TP | request text concatenated into a SQL query (challenge snippet) |
| 60 | fail BLOCKER | semgrep hullproof-raw-sql-concat | data/static/codefixes/unionSqlInjectionChallenge_1.ts:6 | TP | same, template string |
| 73 | fail BLOCKER | semgrep hullproof-eval-or-new-function | routes/captcha.ts:22 | FP | `eval` of an expression the server builds from its own random digits and a fixed operator list |
| 78 | fail BLOCKER | semgrep hullproof-eval-or-new-function | test/cypress/e2e/contact.spec.ts:267 | FP | test code |
| 81 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/about/about.component.ts:117 | TP | user feedback text put into HTML and passed to `bypassSecurityTrustHtml` |
| 99 | fail HIGH | the Pro edition's additional rules (not published) | lib/insecurity.ts:192, routes/updateUserProfile.ts:42 | TP | `res.cookie('token', ...)` with no Secure or HttpOnly |
| 110 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/navbar/navbar.component.spec.ts:229 | FP | test code with a placeholder token |
| 120 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/sidenav/sidenav.component.spec.ts:381 | FP | test code |
| 121 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | same lines as 120 | FP | test code, and a second record for the same lines |
| 130 | fail BLOCKER | semgrep the Pro edition's additional rules (not published) | test/cypress/e2e/totpSetup.spec.ts:7 | FP | test fixture value for a seeded demo user |
| 132 | fail CRITICAL | semgrep hullproof-log-session-token | frontend/src/app/faucet/faucet.component.ts:205 | FP | logs a true or false flag named `session`, not a token |
| 143 | fail BLOCKER | gitleaks private-key | terraform/networking.tf:171 | TP | a private key written into Terraform (the leaked key challenge) |
| 153 | fail BLOCKER | gitleaks generic-api-key | test/api/user.test.ts:240 | FP | test passwords and a test token for seeded demo users |
| 160 | fail HIGH | the Pro edition's additional rules (not published) | .github/workflows/ci.yml:36 | TP | the project has no lockfile (`.npmrc` sets `package-lock=false`) and CI runs `npm install` |

Result: 8 TP, 12 FP (precision on the sample 0.40). Fail records alone: 6 of 14 TP. Six of the 12 false positives are in test files.

## 5. TerraGoat

### 5.1 Counts (identical for core and pro, except Semgrep files scanned 0 against 4)

| | value |
|---|---|
| Trivy hits (mapped to a requirement) | 248 (76) |
| Gitleaks hits | 4 |
| Semgrep hits | 0 |
| Fail records | 4: 3 BLOCKER (SEC-SECRETS-004, Gitleaks), 1 HIGH (actions not pinned) |
| Observations | 171 (165 from Trivy) |

Requirements named by observations: seven cloud requirements (12, 9, 6, 5, 2, 1 and 1 observations), all written only in a Pro standard document and not yet in `security-controls.json`, so they cannot fail a requirement row; two cloud requirements, one HIGH (6) and one MEDIUM (1), which are GROWTH requirements outside the LAUNCH stage; and one MEDIUM requirement (1). So a deliberately broken cloud setup produces 2 FAIL rows today. Once the kit build adds those seven requirements, those hits become fail records.

### 5.2 Hand check of 20 records (pro run, seed 20261010, same method)

| # | Rule | Where | Verdict | Reason |
|---|---|---|---|---|
| 4 | trivy AWS-0080 | terraform/aws/db-app.tf:19 | TP | `storage_encrypted = false` |
| 12 | trivy AWS-0180 | terraform/aws/db-app.tf:22 | TP | `publicly_accessible = true` |
| 17 | trivy AWS-0027 | terraform/aws/ec2.tf:34 | TP | EBS volume with no encryption at all |
| 70 | trivy AZU-0042 | terraform/azure/aks.tf:23 | TP | role based access control disabled |
| 81 | trivy AZU-0072 | terraform/azure/app_service.tf:27 | TP | `https_only = false` |
| 88 | trivy AZU-0031 | terraform/azure/logging.tf:8 | TP | log retention 30 days |
| 90 | trivy AZU-0033 | terraform/azure/logging.tf:1 | TP | log profile captures only the Action category |
| 97 | trivy AZU-0057 | terraform/azure/mssql.tf:1 | TP | storage account with no logging block |
| 112 | trivy AZU-0018 | terraform/azure/sql.tf:31 | TP | threat alert policy with no email address, two alerts disabled |
| 113 | trivy AZU-0019 | terraform/azure/sql.tf:73 | TP | PostgreSQL server with no `log_connections` setting |
| 116 | trivy AZU-0022 | terraform/azure/sql.tf:9 | TP | SQL server left on its default public network access |
| 118 | trivy AZU-0024 | terraform/azure/sql.tf:109 | TP | `log_checkpoints` set to off |
| 119 | trivy AZU-0026 | terraform/azure/sql.tf:9 | TP | no minimum TLS version |
| 120 | trivy AZU-0027 | terraform/azure/sql.tf:9 | TP | no extended audit policy |
| 122 | trivy AZU-0010 | terraform/azure/storage.tf:62 | FP | the rule wants Azure services allowed to bypass the network rules; not allowing it is not a weakness |
| 130 | trivy GCP-0022 | terraform/gcp/big_data.tf:1 | TP | disconnections not logged (the same instance allows 0.0.0.0/0) |
| 143 | trivy GCP-0053 | terraform/gcp/gke.tf:19 | TP | control plane open to 0.0.0.0/0 |
| 156 | trivy GCP-0034 | terraform/gcp/instances.tf:36 | TP | disk with no customer managed key |
| 162 | trivy GCP-0027 | terraform/gcp/networks.tf:22 | TP | firewall allows all TCP ports from 0.0.0.0/0 |
| 163 | trivy GCP-0029 | terraform/gcp/networks.tf:7 | TP | subnetwork without flow logs |

Result: 19 TP, 1 FP. All 20 sampled records are observations, because of the controls gap above. TerraGoat is broken on purpose, so a high TP share is expected and says little about precision on a real project.

## 6. OpenSSF CVE Benchmark

### 6.1 The repository itself (identical for core and pro)

The benchmark repository holds the harness and the CVE metadata (223 files in `CVEs/`), not the vulnerable code. On it the engine wrote 3 fail records and 1 observation: SEC-API-020 (BLOCKER, Semgrep `hullproof-subprocess-arg-no-separator`), SEC-LOG-001 (CRITICAL, `check.log.no-credential-in-logs`), a HIGH requirement (actions pinned by tag), and the observation of a MEDIUM requirement (no `permissions` block).

Hand check: only 4 records exist, so all 4 were checked instead of 20.

| # | Rule or check | Where | Verdict | Reason |
|---|---|---|---|---|
| 0 | the Pro edition's additional rules (not published) (observation) | .github/workflows/Checks.yml:6 and 2 more | TP | no `permissions` block in the workflows |
| 1 | semgrep hullproof-subprocess-arg-no-separator | test/integration-tests/slow/multiple-tools-multiple-cves.test.ts:68 | FP | test code calling `execFileSync` with fixed arguments |
| 2 | check.log.no-credential-in-logs | src/repositories.ts:266 | TP | `console.log` prints the GitHub token |
| 3 | the Pro edition's additional rules (not published) | .github/workflows/Checks.yml:10 | TP | `actions/setup-node@v1`, `actions/checkout@v2` |

### 6.2 Vulnerable commit against fixed commit: not run here (done later in `bench/CVE-SUBSET-2026-10-10.md`)

Each CVE file names an upstream repository and a vulnerable and a fixed commit. 127 of the 223 CVEs have a type the engine has a JavaScript or TypeScript rule for: XSS CWE-79 (83), command injection CWE-78 (48), code injection CWE-94 (37), open redirect CWE-601 (7), SQL injection CWE-89 (4), SSRF CWE-918 (3), weak random CWE-338 (2); a CVE can have several. Checking them needs a clone of 107 upstream repositories at two commits each. That is a download of third party code, and each download of third party code needs the maintainers' approval first, so it was not done. It needs that approval, then the benchmark's own `bin/cli download-commits` into a scratch folder and two scans per CVE.

## 7. Conclusions

1. The engine is fully deterministic on all four targets: 24 of 24 runs gave byte identical scan folders and gate outputs within each target and rule set.
2. Where the engine has a rule or check for the language, it is precise but narrow. On BenchmarkPython's covered categories it flagged 24 cases with no false positive, and missed all 36 SQL injection and XSS cases, because its Python rules do not match f string SQL or HTML built by string concatenation.
3. Most of BenchmarkPython (1086 of 1230 cases) is in categories the engine has no Python rule for. The engine says nothing about them, and a short report there means "not checked", not "clean".
4. On Juice Shop, 8 of 20 sampled records were true. Test files cause half of the false positives (6 of 12). Leaving test and spec files out of the code rules, or marking hits there as observations, is the largest single precision gain available. A second gain is merging records of two rules that point at the same lines (records 120 and 121).
5. On TerraGoat the Trivy hits are almost all true (19 of 20), but only 2 requirement rows fail, because the seven cloud requirements for these checks are not in the controls file yet and most other cloud requirements are GROWTH stage.
6. the Pro edition's additional rules (not published) changes nothing on BenchmarkPython, TerraGoat or the CVE Benchmark repository, and adds 50 fail records on Juice Shop (mostly browser token storage and HTML injection).

## 8. Limits

1. Hand checks are one reader's judgement from reading the code, with a written reason per row; nothing was run against a live app.
2. A sample of 20 gives a rough share, not a precise rate. The CVE Benchmark sample is 4, all its records.
3. BenchmarkPython counts by file name. A finding in a shared helper is not counted against any test case.
4. The targets were on this machine while the scanner adapters were built (scanner run notes kept by the maintainers), and the cookie check reads Flask `set_cookie` arguments. The checks were not written against BenchmarkPython's answer key, but the targets are not fully unseen.
5. OSV Scanner did not run (network off), so no dependency advisory is in any number here.
6. The stage was LAUNCH. A GROWTH or SCALE run puts more requirements in scope and turns some observations into fail records.
7. The kit used carries uncommitted changes in the maintainers' working copy (`deterministic_only`, findings schema 1.1.0). The numbers depend on those changes being committed as they are.

## 9. Coverage update: test code handling and taint rules (engine commit a11bb26)

Sections 1 to 8 are the measurement before this change and stay as they were. This section measures the same engine after two changes, on BenchmarkPython and Juice Shop only:

1. Test code handling (commit 883f3e9). A finding in a test, fixture, spec, mock or example path, found by folder and file name conventions per language (`src/report/test-code.ts`), is kept in the scanner and check output, marked as test code in the findings record (an observation whose title starts with `Test code:`), listed in its own section of `report.md`, and never fails a requirement or reaches the gate. Two requirements about test material that ships still fail from a test path.
2. Taint rules (commit a11bb26). 25 Semgrep taint mode rules in `rules/semgrep/taint-*.yaml` for SQL injection (CWE-89), XSS (CWE-79), command injection (CWE-78), path traversal (CWE-22) and SSRF (CWE-918) in Python (Flask, Django, FastAPI), JavaScript and TypeScript (Express, Koa, Next.js, Node), Java (servlets, Spring MVC), PHP and Go, mapped to the requirement for each class (those outside the Free edition are not named here). They are open core rules under Apache-2.0.

How the rules were written. Each rule was written from the CWE definition and the framework's documented request and sink APIs, with fixtures written for it (`test/fixtures/rules/`, checked by `semgrep --test` in `test/rules.test.ts`). No Semgrep registry rule was copied or used as a base. BenchmarkPython's expected results file and its test case names and code were not read while writing or changing a rule. The numbers below are the first measurement of the rules as written; no rule was changed after it.

Runs: same machine, tools and options as section 1, engine commit a11bb26, three runs per target and rule set (12 runs), output in a scratch folder, no target changed.

### 9.1 Stability

| Target | Rule set | Scan folder sha256 (first 16), all 3 runs | Gate output sha256 (first 16) | Byte identical | Scan exit | Gate |
|---|---|---|---|---|---|---|
| BenchmarkPython | core | 12f6ebd7c375e308 | 0b2b419e1d071b55 | yes | 0 | NOT READY, exit 1 |
| BenchmarkPython | pro | ebd5e153d275c5a0 | 8ea2dec813bd5115 | yes | 0 | NOT READY, exit 1 |
| Juice Shop | core | 68bcf209d434a722 | dc30c512cab28fec | yes | 0 | NOT READY, exit 1 |
| Juice Shop | pro | a4dab084c8da744e | 7f6e4fe102dabde1 | yes | 0 | NOT READY, exit 1 |

All 12 runs were byte identical within their row. Run times: BenchmarkPython 13 to 16 seconds, Juice Shop 51 to 52 (core) and 84 to 95 (pro).

A bug found by this measurement and fixed before these runs (in commit a11bb26): with the taint rules, BenchmarkPython produced 472 records, a findings block of 501327 characters even on one line, so `scan` exited 2 on the kit validator's 200000 limit. When the block passes the 150000 warning size on one line, the engine now writes one record per rule for a rule that matched more than 20 files (all its hits stay in `scan/semgrep.json`, and the record says how many files). On BenchmarkPython this applies to the XSS and path traversal rules. Juice Shop stays under the limit and keeps one record per rule and file.

### 9.2 BenchmarkPython: before and after

Scoring as in section 3: a test case counts as flagged for a category when a mapped rule names its file, and only that category's cases are counted. The taint rules map to sqli, xss, cmdi and pathtraver. BenchmarkPython has no SSRF category. Core and pro gave the same numbers.

| Category | Cases (real / not real) | Before: TP, FP, FN | Before: precision, recall | After: TP, FP, FN, TN | After: precision | After: recall | After: false positive rate | After: recall minus false positive rate |
|---|---|---|---|---|---|---|---|---|
| sqli (CWE-89) | 5 / 11 | 0, 0, 5 | no flags, 0.00 | 2, 0, 3, 11 | 1.00 | 0.40 | 0.00 | 0.40 |
| xss (CWE-79) | 31 / 58 | 0, 0, 31 | no flags, 0.00 | 14, 23, 17, 35 | 0.38 | 0.45 | 0.40 | 0.05 |
| cmdi (CWE-78) | 13 / 7 | not covered | | 5, 2, 8, 5 | 0.71 | 0.38 | 0.29 | 0.10 |
| pathtraver (CWE-22) | 65 / 103 | not covered | | 23, 30, 42, 73 | 0.43 | 0.35 | 0.29 | 0.06 |
| securecookie (CWE-614) | 24 / 15 | 24, 0, 0 | 1.00, 1.00 | 24, 0, 0, 15 | 1.00 | 1.00 | 0.00 | 1.00 |

| Totals | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| Before, 3 covered categories | 24 | 0 | 36 | 1.00 | 0.40 |
| After, the same 3 categories | 40 | 23 | 20 | 0.63 | 0.67 |
| After, 5 covered categories | 68 | 55 | 70 | 0.55 | 0.49 |

What this says:

1. Recall rose where the engine had none (SQL and XSS) and two categories are newly covered, at a cost in precision. The XSS rule is close to chance on its own category: it flags 45 percent of the real cases and 40 percent of the safe ones. Path traversal and command injection separate real from safe cases only a little better.
2. The XSS rule treats any string a Flask view returns as HTML. Outside its own category it also flags 371 test cases of other categories, which the Benchmark's scoring does not count but a user would see. Whether those responses are exploitable was not checked.
3. Still not covered: codeinj, redirect, weakrand, hash, ldapi, xpathi, deserialization, trustbound and xxe, 898 of the 1230 cases (314 of them real).
4. The misses were not studied case by case, because reading the missed test cases to change the rules would tune them to this benchmark.

### 9.3 Juice Shop: counts before and after

| | core before | core after | pro before | pro after |
|---|---|---|---|---|
| Semgrep hits (files scanned / tracked) | 36 (648 / 1300) | 54 (651 / 1300) | 141 (834 / 1300) | 159 (834 / 1300) |
| Taint rule hits | none | 18 | none | 18 |
| Fail records: BLOCKER, CRITICAL, HIGH | 67: 58, 5, 4 | 59: 42, 8, 9 | 117: 64, 44, 9 | 79: 43, 24, 12 |
| Observations (of them test code) | 48 (none) | 70 (26) | 48 (none) | 100 (56) |
| Requirement rows FAIL | 14 | 16 | 19 | 20 |

The taint rule hits: SQL injection 6, path traversal 6, XSS 5, SSRF 1. On the pro run, fail records fell from 117 to 79 even with the taint records added, and 56 records are now test code observations. Test code handling removed no FAIL row, because every requirement it touched also fails from shipped code. The FAIL rows added are the path traversal requirement in both runs, and the XSS requirement in the core run (the XSS taint rule; the Pro edition's additional rules (not published) already failed it before).

### 9.4 Juice Shop hand check, two seeds, before and after

Same method as section 4.2 (pro run, records of `report.findings.md` in file order, Fisher and Yates shuffle with mulberry32, first 20, read in the code), with seed 20261010 and a second seed 20261011. "Before" is the run of section 4 (engine f1feb12); "after" is engine a11bb26. A test code record is judged by the same rule as any other: a placeholder token in a spec file is FP, even though the record now says it is test code and keeps it out of the gate.

| Sample | Records sampled | TP | FP | Share TP | Fail records: TP of sampled | Test code records in the sample |
|---|---|---|---|---|---|---|
| Before, seed 20261010 (section 4.2) | 20 | 8 | 12 | 0.40 | 6 of 14 | not marked then; 6 of the 12 FP were in test files |
| Before, seed 20261011 | 20 | 8 | 12 | 0.40 | 7 of 17 | not marked then; 10 of the 12 FP were in test files |
| After, seed 20261010 | 20 | 13 | 7 | 0.65 | 10 of 11 | 6, all FP, none in the gate |
| After, seed 20261011 | 20 | 7 | 13 | 0.35 | 6 of 10 | 8, all FP, none in the gate |

Leaving out the test code records, which never reach the gate: after, seed 20261010, 13 of 14 records are TP; seed 20261011, 7 of 12. The share of fail records that are TP, the part that reaches the gate, went from 13 of 31 (both seeds before) to 16 of 21 (both seeds after).

Before, seed 20261011:

| # | Kind, severity | Rule or check | Where | Verdict | Reason |
|---|---|---|---|---|---|
| 11 | observation | trivy AWS-0037 | data/static/codefixes/iacLeakedKeyChallenge_2.tf:250 | FP | `encrypted = var.efs_encrypted`, and the variable defaults to true in the real Terraform; the snippet file has no variables file |
| 15 | observation | trivy AWS-0104 | data/static/codefixes/iacLeakedKeyChallenge_2.tf:85 | TP | egress to 0.0.0.0/0 on all ports |
| 44 | observation | trivy DS-0001 | test/smoke/Dockerfile:1 | FP | `FROM alpine` with no tag in a smoke test image |
| 49 | fail BLOCKER | semgrep hullproof-sql-built-string-reaches-query | data/static/codefixes/dbSchemaChallenge_1.ts:5 | TP | request text concatenated into SQL (challenge snippet) |
| 59 | fail BLOCKER | semgrep hullproof-sql-string-built-in-variable | data/static/codefixes/loginJimChallenge_4.ts:18 | TP | request body in a SQL template string (challenge snippet) |
| 70 | fail BLOCKER | semgrep hullproof-sql-built-string-reaches-query | routes/search.ts:23 | TP | search text in a SQL template string |
| 72 | fail BLOCKER | semgrep hullproof-sql-string-built-in-variable | test/api/login.test.ts:216 | FP | test code sending an injection payload |
| 84 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/track-result/track-result.component.ts:49 | TP | order id echoed by the server put into HTML and passed to `bypassSecurityTrustHtml` |
| 95 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | test/cypress/e2e/restApi.spec.ts:62 | FP | test code |
| 99 | fail HIGH | the Pro edition's additional rules (not published) | lib/insecurity.ts:192, routes/updateUserProfile.ts:42 | TP | token cookie with no Secure or HttpOnly |
| 103 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/app.guard.spec.ts:32 | FP | test code with a placeholder token |
| 106 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:66 | FP | test code |
| 111 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/oauth/oauth.component.ts:52 | TP | auth token stored in localStorage |
| 114 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/payment/payment.component.ts:233 | TP | auth token stored in localStorage |
| 130 | fail BLOCKER | semgrep the Pro edition's additional rules (not published) | test/cypress/e2e/totpSetup.spec.ts:7 | FP | test fixture value for a seeded demo user |
| 138 | fail BLOCKER | gitleaks jwt | frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:72 | FP | test JWT with a fake payload |
| 146 | fail BLOCKER | gitleaks generic-api-key | test/api/chat.test.ts:261 | FP | demo user password in a test |
| 154 | fail BLOCKER | gitleaks jwt | test/api/user.test.ts:280 | FP | expired test token |
| 157 | fail BLOCKER | gitleaks generic-api-key | test/cypress/e2e/totpSetup.spec.ts:7 | FP | same value as 130 |
| 164 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/hacking-instructor/index.ts:126 | FP | `innerHTML` of tutorial hint text that is fixed in the app's own code |

After, seed 20261010:

| # | Kind, severity | Rule or check | Where | Verdict | Reason |
|---|---|---|---|---|---|
| 6 | observation | trivy AWS-0054 | data/static/codefixes/iacLeakedKeyChallenge_1.tf:156 | TP | HTTP listener on port 80 forwards plain HTTP, no redirect |
| 47 | observation, test code | semgrep the Pro edition's additional rules (not published) | frontend/src/app/sidenav/sidenav.component.spec.ts:381 | FP | placeholder token in a spec |
| 52 | observation | trivy AWS-0054 | infrastructure/terraform/networking.tf:157 | TP | same listener |
| 60 | observation | trivy AWS-0054 | terraform/networking.tf:157 | TP | same listener |
| 70 | observation, test code | gitleaks | test/api/checkKeys.test.ts:46 | FP | test value for the wallet key check |
| 72 | observation, test code | gitleaks | test/api/data-export.test.ts:53 | FP | demo user password in a test |
| 74 | observation, test code | gitleaks | test/api/feedback.test.ts:117 | FP | same |
| 83 | observation, test code | gitleaks | test/api/user.test.ts:280 | FP | expired test token |
| 84 | observation, test code | semgrep hullproof-eval-or-new-function | test/cypress/e2e/contact.spec.ts:267 | FP | test code |
| 100 | fail BLOCKER | semgrep hullproof-raw-sql-concat | data/static/codefixes/dbSchemaChallenge_1.ts:5 | TP | as before |
| 105 | fail BLOCKER | semgrep hullproof-sql-string-built-in-variable | data/static/codefixes/dbSchemaChallenge_3.ts:11 | TP | search text in a SQL template string (challenge snippet) |
| 107 | fail BLOCKER | semgrep hullproof-sql-string-built-in-variable | data/static/codefixes/loginAdminChallenge_1.ts:18 | TP | request body in SQL (challenge snippet) |
| 114 | fail BLOCKER | semgrep hullproof-raw-sql-concat | data/static/codefixes/unionSqlInjectionChallenge_1.ts:6 | TP | as before |
| 123 | fail BLOCKER | semgrep hullproof-sql-built-string-reaches-query | routes/login.ts:34 | TP | login SQL built from the request body |
| 124 | fail BLOCKER | semgrep hullproof-sql-string-built-in-variable | routes/login.ts:34 | TP | same line, second record |
| 125 | fail BLOCKER | semgrep hullproof-taint-js-sql-injection | routes/login.ts:34 | TP | same line, third record |
| 129 | fail BLOCKER | semgrep hullproof-taint-js-sql-injection | routes/search.ts:23 | TP | search SQL built from the query string |
| 155 | fail HIGH | the Pro edition's additional rules (not published) | lib/insecurity.ts:192, routes/updateUserProfile.ts:42 | TP | as before |
| 167 | fail CRITICAL | semgrep hullproof-log-session-token | frontend/src/app/web3-sandbox/web3-sandbox.component.ts:332 | FP | logs a true or false flag named `session` |
| 174 | fail HIGH | the Pro edition's additional rules (not published) | .github/workflows/ci.yml:36 | TP | as before |

After, seed 20261011:

| # | Kind, severity | Rule or check | Where | Verdict | Reason |
|---|---|---|---|---|---|
| 17 | observation | trivy AWS-0164 | data/static/codefixes/iacLeakedKeyChallenge_2.tf:22 | FP | public IPs on the public subnet are the intended design |
| 28 | observation, test code | semgrep the Pro edition's additional rules (not published) | frontend/src/app/Services/basket.service.spec.ts:121 | FP | spec |
| 31 | observation, test code | semgrep the Pro edition's additional rules (not published) | frontend/src/app/app.guard.spec.ts:32 | FP | spec |
| 32 | observation, test code | gitleaks | frontend/src/app/app.guard.spec.ts:46 | FP | spec |
| 49 | observation | trivy AWS-0017 | infrastructure/terraform/main.tf:126 | TP | log group with no customer managed key (a hardening gap, judged as GCP-0034 was in section 5.2) |
| 66 | observation, test code | semgrep the Pro edition's additional rules (not published) | test/api/2fa.test.ts:42 | FP | test value |
| 73 | observation, test code | gitleaks | test/api/erasure-request.test.ts:36 | FP | demo user password in a test |
| 75 | observation, test code | gitleaks | test/api/login.test.ts:147 | FP | same |
| 91 | observation, test code | semgrep the Pro edition's additional rules (not published) | test/cypress/e2e/totpSetup.spec.ts:7 | FP | test fixture value |
| 99 | observation, test code | trivy DS-0026 | test/smoke/Dockerfile:1 | FP | no health check in a smoke test image |
| 104 | fail BLOCKER | semgrep hullproof-sql-built-string-reaches-query | data/static/codefixes/dbSchemaChallenge_3.ts:11 | TP | challenge snippet SQL |
| 127 | fail BLOCKER | semgrep hullproof-sql-built-string-reaches-query | routes/search.ts:23 | TP | search SQL |
| 135 | fail CRITICAL | semgrep hullproof-ssrf-request-data-to-url | routes/profileImageUrlUpload.ts:24 | TP | `fetch(url)` with the URL from the request body |
| 148 | fail HIGH | semgrep hullproof-taint-js-path-traversal | routes/profileImageFileUpload.ts:42 | FP | the path holds the user id and a detected file type; the rule followed the token cookie into a session lookup |
| 149 | fail HIGH | semgrep hullproof-taint-js-path-traversal | routes/profileImageUrlUpload.ts:29 | FP | the extension is limited to a fixed list, else `jpg` |
| 152 | fail HIGH | semgrep hullproof-taint-js-path-traversal | server.ts:276 | FP | the path is resolved and checked to start with the `infrastructure` folder before the read |
| 161 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/app/payment/payment.component.ts:233 | TP | as before |
| 173 | fail BLOCKER | gitleaks private-key | terraform/networking.tf:171 | TP | as before |
| 175 | fail HIGH | the Pro edition's additional rules (not published) | frontend/package.json:1, package.json:1 | TP | no lockfile is committed |
| 177 | fail CRITICAL | semgrep the Pro edition's additional rules (not published) | frontend/src/assets/private/three.js:11375 | FP | vendored library writing a progress number into `innerHTML` |

What the samples say:

1. Test code handling did what section 7 item 4 expected. In the before samples 16 of 24 false positives were in test files and most were BLOCKER or CRITICAL fail records; after, every sampled test file record is an observation that never reaches the gate, and fail records went from 13 of 31 TP to 16 of 21.
2. The JavaScript taint rules found the two real SQL injections in shipped Juice Shop code (login and search) and the SSRF in the profile image upload, which a kit rule already found on the same line. Their path traversal rule gave 3 false positives in seed 20261011: it follows taint through a session lookup keyed by the token cookie, does not see a value limited to a fixed list by a ternary, and does not recognise `startsWith` on a resolved path as a guard (it recognises guard functions by name only).
3. One line can still give several records (records 123, 124 and 125 are three rules on `routes/login.ts:34`). Merging records of different rules on the same lines is still open.
4. The share of TP over all 20 records swings between seeds (0.65 and 0.35 after), which shows how rough a sample of 20 is.

### 9.5 Secrets in test files, rule tiers and the recorded kit (engine commit 6d82af4)

Three changes after 9.1 to 9.4: secret findings (any Gitleaks hit, any rule mapped to a SEC-SECRETS requirement) are never treated as test code, so they hold the gate from any path; every Semgrep rule has a confidence tier in `rules/tiers.json` (or the tier file of a rule pack) (threshold 0.80 precision on at least 3 judged hits, explained in `README.md`), and a lead rule's hits are listed as leads that never hold the gate; and `scan` records the kit it used in `kit.local.json`, which `report` and `gate` read when neither `--kit` nor `HULLPROOF_KIT` is given. These runs gave neither, and both commands found the kit.

| Target, pro | Scan folder sha256 (first 16), all 3 runs | Gate output sha256 (first 16) | Byte identical | Exits (scan, report, gate) |
|---|---|---|---|---|
| Demo (hullproof-demo 3e7c205) | 02146e43a3318c3c | a49225749d98a4c4 | yes | 0, 0, 1 |
| Juice Shop | 469a9a5605faa78f | 59bc9e58bab8792c | yes | 0, 0, 1 |

The scan folder hash leaves out `run.json` and `kit.local.json`, which hold timings and a machine path.

Demo: unchanged. The findings record still scores 21 found, 1 partial and 8 missed (13 of 15 free flaws), the gate output has the same sha256 as in `bench/PHASE1-DEMO-SCORE.md`, and no record became a lead or test code.

Juice Shop, against 9.3 (pro after):

| | 9.3 | Now |
|---|---|---|
| Fail records | 79 | 90 |
| Fail records that became leads | | 14, every taint rule record: SQL injection 6, path traversal 5, XSS 2, SSRF 1 |
| Test code records that are fail records again (secrets) | | 25 |
| Test code observations | 56 | 31 |
| Lead observations | 0 | 14 |
| Requirement rows FAIL | 20 | 19 (the path traversal requirement is now failed only by leads) |

Every taint rule is a lead today: the XSS and path traversal rules because they measured below 0.80 (0.38 and 0.43 on BenchmarkPython, 0.00 on 3 judged Juice Shop records), and the SQL injection rules because 2 judged hits are fewer than the 3 a measurement needs to change a default. So the two real SQL injections the JavaScript taint rule found in `routes/login.ts` and `routes/search.ts` are now leads, while kit rules still fail the same lines. In the hand check of 9.4, 9 sampled test code records are secrets (seed 20261010: 70, 72, 74, 83; seed 20261011: 32, 66, 73, 75, 91), all judged FP, and they are now fail records again; 5 sampled taint records are now leads (125 and 129 TP; 148, 149 and 152 FP). Applied to the two after samples, the sampled fail records become 14 TP of 25, against 16 of 21 in 9.4 and 13 of 31 before any of these changes. Holding secrets in test files costs precision on Juice Shop, whose test secrets are demo values; that is the intended trade, since the engine cannot tell a demo value from a live key.
