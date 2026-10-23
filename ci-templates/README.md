# CI templates

Each file runs `hullproof ci` in one CI system. The command runs no model and no container, needs no secret, and writes `findings.json`, `report.md`, `results.sarif` and `pr-comment.md`. It exits 1 when a finding at or above `--fail-on` failed (default `blocker`), so the job fails and the release is held.

| File | CI system | What was checked |
|---|---|---|
| `github-actions.yml` | GitHub Actions | YAML syntax and expected keys. The same workflow shape ran on a private test repository: a pull request with a planted blocker failed the check, a clean pull request passed, and a summary comment was added and then updated in place |
| `gitlab-ci.yml` | GitLab CI | YAML syntax and expected keys |
| `circleci-config.yml` | CircleCI | YAML syntax and expected keys |
| `bitbucket-pipelines.yml` | Bitbucket Pipelines | YAML syntax and expected keys |
| `azure-pipelines.yml` | Azure Pipelines | YAML syntax and expected keys |

The image line in each file holds a placeholder for the digest of the Hullproof image. Replace it with the digest from the release notes before you use the file. The image holds the engine and the scanners at pinned versions, so the same commit gives the same four files in CI as on your machine.

Fork pull requests: none of these jobs needs a secret, so a fork can run them. Keep it that way. If you add a provider key for the model hunt (Pro edition), do not expose it to builds of forks.
