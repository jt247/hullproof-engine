# Security policy

## Scope

This policy covers the Hullproof Engine in this repository: the command line program, the discovery and mapping code, the executable checks, the Semgrep rules and the scripts that ship with it. Examples of reports in scope: a way to make the engine run code from a repository it scans, a way to make it write outside its output folder, a way to make it send data over the network when `--allow-network` was not given, or a rule or check that fails open in a way its documentation says it does not.

A vulnerability in a project you scan with the engine is not in scope. That is for the project's owner to fix. A vulnerability in Semgrep, Gitleaks, OSV Scanner or Trivy is for those projects.

## How to report

Use GitHub private vulnerability reporting. Open the Security tab of https://github.com/jt247/hullproof-engine, choose Report a vulnerability and fill in the form. The report goes privately to the maintainers.

If the Report a vulnerability button is not there, send the report by email to joshua@joshuatheophilus.com with the subject "Hullproof Engine security report".

Please do not open a public issue or pull request for a vulnerability. Send only what is needed to reproduce the problem. Do not send secrets or customer data.

Please include:

1. The file or command that is affected.
2. The engine version, from `node src/cli.ts version`.
3. Steps to reproduce, with the exact command or input.
4. What you expected and what happened.
5. The impact as you see it.
6. Whether you want to be credited, and under what name.

## What happens next

We aim to acknowledge a report within 7 days. That is a target for the first reply and not a promise of a fix date. We will tell you whether we can reproduce the problem and what we plan to do. We credit reporters who want credit in the release notes for the fix. We do not offer a bounty.

## Supported versions

Only the latest release is supported. A fix goes into a new release and not into older ones.
