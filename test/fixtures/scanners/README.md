# Scanner adapter fixtures

`app/` is a small synthetic project with planted flaws for the scanner adapter tests: a SQL string built by concatenation
(Semgrep), Terraform for AWS, Azure and Google Cloud with public storage, open admin ports, public databases, wildcard
roles, unencrypted volumes and a single Region trail (Trivy), and a Dockerfile that runs as root with a token in `ENV`.
The secret for the Gitleaks test is not stored here: the test writes it into a temporary copy, so this repository never
holds a secret shaped value.

`osv-output.json` is a hand written OSV Scanner JSON report. Its field names follow the OSV Scanner 2.6.0 source (`pkg/models/results.go`: results, source, packages, vulnerabilities, groups with ids, aliases and max_severity) and the OSV schema; it was not printed by OSV Scanner, because no network run was allowed. Its advisory ids
(`TEST-...`) and packages are invented for the parser and policy tests and do not exist in any advisory database.
