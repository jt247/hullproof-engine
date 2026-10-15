// The CI templates are checked for YAML syntax and for the keys each CI system expects, with PyYAML (python3 -c "import yaml").
// Nothing here runs a template on its CI system, and the README says so.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = fileURLToPath(new URL('../ci-templates/', import.meta.url));
const hasYaml = spawnSync('python3', ['-c', 'import yaml'], { encoding: 'utf8' }).status === 0;
const SKIP = hasYaml ? false : 'python3 with PyYAML is not available';

function load(name: string): Record<string, any> {
  const r = spawnSync('python3', ['-c', 'import sys,json,yaml;print(json.dumps(yaml.safe_load(open(sys.argv[1])),default=str))', join(DIR, name)], { encoding: 'utf8' });
  assert.equal(r.status, 0, `${name}: ${r.stderr}`);
  return JSON.parse(r.stdout);
}
const names = readdirSync(DIR).filter((n) => n.endsWith('.yml'));

test('five templates exist and every one parses as YAML', { skip: SKIP }, () => {
  assert.deepEqual(names.sort(), ['azure-pipelines.yml', 'bitbucket-pipelines.yml', 'circleci-config.yml', 'github-actions.yml', 'gitlab-ci.yml']);
  for (const n of names) assert.ok(load(n) && typeof load(n) === 'object', n);
});

test('GitLab CI: a job with an image, a script that runs hullproof ci, and artifacts', { skip: SKIP }, () => {
  const d = load('gitlab-ci.yml');
  assert.deepEqual(d.stages, ['security']);
  const j = d.hullproof;
  assert.equal(j.stage, 'security');
  assert.deepEqual(j.image.entrypoint, ['']);
  assert.ok(j.script.some((s: string) => s.startsWith('hullproof ci ')));
  assert.equal(j.artifacts.when, 'always');
  assert.ok(Array.isArray(j.rules) && j.rules.length === 2);
});

test('CircleCI: version 2.1, a job with docker and checkout, and a workflow that runs it', { skip: SKIP }, () => {
  const d = load('circleci-config.yml');
  assert.equal(d.version, 2.1);
  const steps = d.jobs.hullproof.steps;
  assert.equal(steps[0], 'checkout');
  assert.ok(steps.some((s: any) => s.run?.command.startsWith('hullproof ci ')));
  assert.ok(steps.some((s: any) => s.store_artifacts));
  assert.deepEqual(d.workflows.security.jobs, ['hullproof']);
});

test('Bitbucket Pipelines: an image, a step with a script, and pull request and branch pipelines that use it', { skip: SKIP }, () => {
  const d = load('bitbucket-pipelines.yml');
  assert.ok(d.image.name.includes('@sha256:'));
  const step = d.definitions.steps[0].step;
  assert.ok(step.script.some((s: string) => s.startsWith('hullproof ci ')));
  assert.equal(d.pipelines['pull-requests']['**'][0].step.name, 'Hullproof');
  assert.equal(d.pipelines.branches.main[0].step.name, 'Hullproof');
});

test('Azure Pipelines: a container resource, a job that uses it, a script and an artifact task', { skip: SKIP }, () => {
  const d = load('azure-pipelines.yml');
  assert.equal(d.resources.containers[0].container, 'hullproof');
  const job = d.jobs[0];
  assert.equal(job.container, 'hullproof');
  assert.ok(job.steps.some((s: any) => typeof s.script === 'string' && s.script.includes('hullproof ci ')));
  assert.ok(job.steps.some((s: any) => s.task === 'PublishBuildArtifacts@1'));
  assert.equal(job.steps.find((s: any) => s.checkout)?.persistCredentials, false);
});

test('GitHub Actions: least privilege, pull_request, actions pinned by full commit SHA, no pull_request_target', { skip: SKIP }, () => {
  const d = load('github-actions.yml');
  const on = d.on ?? d.true;
  assert.ok('pull_request' in on && !('pull_request_target' in on));
  assert.deepEqual(d.permissions, { contents: 'read' });
  const uses = d.jobs.hullproof.steps.map((s: any) => s.uses).filter(Boolean) as string[];
  assert.equal(uses.length, 3);
  for (const u of uses) assert.match(u, /@([0-9a-f]{40}|COMMIT_SHA)$/, u);
});

test('no template holds a secret, a token or a provider key, and none uses a mutable tag for its image', () => {
  for (const n of names) {
    const t = readFileSync(join(DIR, n), 'utf8');
    assert.doesNotMatch(t, /(api[_-]?key|token|secret|password)\s*[:=]\s*\S{8,}/i, n);
    assert.doesNotMatch(t, /image:[^\n]*:latest/, n);
    if (n !== 'github-actions.yml') assert.match(t, /@sha256:/, n);
    assert.doesNotMatch(t, new RegExp('[\\u2013\\u2014]'), n);
  }
});
