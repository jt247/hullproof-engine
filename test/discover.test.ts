// Stack discovery on small fixture projects, one per stack family, plus determinism, skipping and schema conformance.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../src/discover/discover.ts';
import { loadDetectors } from '../src/discover/detectors.ts';
import type { Stack, StackCategory } from '../src/types/index.ts';
import { STACK_CATEGORIES } from '../src/types/index.ts';
import { stableJson } from '../src/util.ts';
import { validate } from './helpers/schema.ts';

const FIX = fileURLToPath(new URL('./fixtures/stacks/', import.meta.url));
const SCHEMA = JSON.parse(readFileSync(fileURLToPath(new URL('../schemas/stack.schema.json', import.meta.url)), 'utf8'));
const detectors = loadDetectors();

const ids = (s: Stack, c: StackCategory): string[] => s[c].map((i) => i.id);
const item = (s: Stack, c: StackCategory, id: string) => s[c].find((i) => i.id === id);

function run(name: string): Stack {
  const s = discover(join(FIX, name), { detectors });
  assert.deepEqual(validate(SCHEMA, JSON.parse(stableJson(s))), [], `${name}: stack.json matches schemas/stack.schema.json`);
  for (const c of STACK_CATEGORIES) {
    for (const it of s[c]) {
      for (const e of it.evidence) {
        assert.ok(existsSync(join(FIX, name, e.file)), `${name}: evidence file ${e.file} exists`);
        assert.ok((e.line === undefined) !== (e.key === undefined), `${name}: ${it.id} evidence has exactly one of line or key`);
      }
    }
  }
  return s;
}

function expect(s: Stack, want: Partial<Record<StackCategory, string[]>>, absent: Partial<Record<StackCategory, string[]>> = {}): void {
  for (const [c, list] of Object.entries(want) as [StackCategory, string[]][]) {
    for (const id of list) assert.ok(ids(s, c).includes(id), `expected ${c}: ${id}, got ${ids(s, c).join(', ')}`);
  }
  for (const [c, list] of Object.entries(absent) as [StackCategory, string[]][]) {
    for (const id of list) assert.ok(!ids(s, c).includes(id), `did not expect ${c}: ${id}`);
  }
}

test('Next.js with Supabase, Vercel, Stripe, OpenAI, Clerk, pnpm and GitHub Actions', () => {
  const s = run('next-supabase');
  expect(s, {
    languages: ['typescript', 'sql'], runtimes: ['node'], frameworks: ['nextjs', 'react'], package_managers: ['pnpm'],
    data_stores: ['supabase'], auth: ['clerk', 'supabase-auth'], payments: ['stripe'], ai: ['openai-sdk'],
    hosting: ['vercel', 'supabase'], ci: ['github-actions'],
  }, { package_managers: ['npm', 'yarn'], frameworks: ['express'] });
  const next = item(s, 'frameworks', 'nextjs')!;
  assert.deepEqual(next.versions, ['next@15.0.0']);
  assert.equal(next.confidence, 'high');
  assert.deepEqual(next.evidence[0], { file: 'package.json', key: 'dependencies.next', rule: 'frameworks.nextjs.dep.npm', confidence: 'high' });
  assert.deepEqual(item(s, 'package_managers', 'pnpm')!.lockfiles, ['pnpm-lock.yaml']);
  assert.equal(item(s, 'hosting', 'vercel')!.kind, 'platform');
  const openaiImport = item(s, 'ai', 'openai-sdk')!.evidence.find((e) => e.rule === 'ai.openai-sdk.import.js');
  assert.deepEqual(openaiImport, { file: 'src/app/api/chat/route.ts', line: 1, rule: 'ai.openai-sdk.import.js', confidence: 'medium' });
});

test('Django with Postgres on AWS (serverless), Anthropic, GitLab CI and Docker', () => {
  const s = run('django-aws');
  expect(s, {
    languages: ['python'], runtimes: ['python'], frameworks: ['django'], package_managers: ['pip'], data_stores: ['postgres', 'dynamodb'],
    auth: ['django-auth'], ai: ['anthropic-sdk'], hosting: ['aws'], iac: ['serverless-framework'], containers: ['dockerfile'], ci: ['gitlab-ci'],
  });
  assert.deepEqual(item(s, 'iac', 'serverless-framework')!.clouds, ['aws']);
  assert.deepEqual(item(s, 'frameworks', 'django')!.versions, ['django@==5.0.6']);
  const dep = item(s, 'frameworks', 'django')!.evidence.find((e) => e.rule === 'frameworks.django.dep.pypi');
  assert.deepEqual(dep, { file: 'requirements.txt', line: 2, rule: 'frameworks.django.dep.pypi', confidence: 'high' });
});

test('FastAPI with Poetry on Google Cloud, Redis and Cloud Build', () => {
  const s = run('fastapi-gcp');
  expect(s, {
    frameworks: ['fastapi', 'sqlalchemy'], package_managers: ['poetry'], data_stores: ['redis'],
    hosting: ['google-cloud'], ci: ['google-cloud-build'],
  }, { package_managers: ['pip'] });
  assert.deepEqual(item(s, 'package_managers', 'poetry')!.lockfiles, ['poetry.lock']);
  assert.deepEqual(item(s, 'frameworks', 'sqlalchemy')!.versions, ['sqlalchemy@2.0.30']);
});

test('Go with Gin and pgx on Azure, Bicep and Azure Pipelines', () => {
  const s = run('go-azure');
  expect(s, {
    languages: ['go'], frameworks: ['gin'], package_managers: ['go-modules'], data_stores: ['postgres'],
    hosting: ['azure'], iac: ['bicep'], ci: ['azure-pipelines'], containers: ['dockerfile'],
  });
  assert.deepEqual(item(s, 'iac', 'bicep')!.clouds, ['azure']);
  assert.ok(item(s, 'frameworks', 'gin')!.evidence.some((e) => e.rule === 'frameworks.gin.import.go' && e.file === 'cmd/api/main.go'));
});

test('Rails with Postgres, Devise and Stripe on Heroku, CircleCI', () => {
  const s = run('rails-heroku');
  expect(s, {
    languages: ['ruby'], frameworks: ['rails'], package_managers: ['bundler'], data_stores: ['postgres'],
    auth: ['devise'], payments: ['stripe'], hosting: ['heroku'], ci: ['circleci'],
  });
});

test('Laravel with MySQL and Redis in Docker Compose, Bitbucket Pipelines', () => {
  const s = run('laravel-compose');
  expect(s, {
    frameworks: ['laravel'], package_managers: ['composer'], data_stores: ['mysql', 'redis'], auth: ['laravel-auth'],
    iac: ['docker-compose'], containers: ['docker-compose'], ci: ['bitbucket-pipelines'],
  });
  assert.equal(item(s, 'data_stores', 'mysql')!.evidence[0].line, 3);
});

test('Spring Boot with Spring Security and Postgres, Kubernetes, Helm, Kustomize and Jenkins', () => {
  const s = run('spring-k8s');
  expect(s, {
    languages: ['java'], frameworks: ['spring-boot', 'spring'], package_managers: ['maven'], data_stores: ['postgres'],
    auth: ['spring-security'], iac: ['kubernetes', 'helm', 'kustomize'], ci: ['jenkins'],
  });
});

test('Expo and React Native with Firebase and RevenueCat, yarn and EAS', () => {
  const s = run('expo-firebase');
  expect(s, {
    mobile: ['expo', 'react-native'], data_stores: ['firestore'], auth: ['firebase-auth'], payments: ['revenuecat'],
    hosting: ['firebase'], package_managers: ['yarn'], ci: ['expo-eas'],
  });
  assert.equal(item(s, 'mobile', 'expo')!.confidence, 'high');
});

test('Flutter with Supabase and RevenueCat, native Android and iOS folders, Codemagic', () => {
  const s = run('flutter-supabase');
  expect(s, {
    languages: ['dart'], mobile: ['flutter', 'android', 'ios'], data_stores: ['supabase'], payments: ['revenuecat'],
    package_managers: ['pub'], ci: ['codemagic'],
  });
});

test('IaC across clouds: Terraform, CloudFormation, SAM, CDK, Pulumi, ARM and Kubernetes', () => {
  const s = run('iac-clouds');
  expect(s, {
    iac: ['terraform', 'cloudformation', 'sam', 'cdk', 'pulumi', 'arm', 'kubernetes'],
    hosting: ['aws', 'azure', 'google-cloud', 'cloudflare'],
  });
  assert.deepEqual(item(s, 'iac', 'terraform')!.clouds, ['aws', 'azure', 'cloudflare', 'google-cloud']);
  assert.equal(item(s, 'hosting', 'aws')!.kind, 'cloud');
  const k8s = item(s, 'iac', 'kubernetes')!;
  assert.deepEqual(k8s.evidence.map((e) => e.file), ['k8s/service.yml'], 'a YAML file with apiVersion but no kind is not Kubernetes');
  const unknownTf = s.unknown.filter((u) => u.note.startsWith('Terraform provider'));
  assert.deepEqual(unknownTf, [{ file: 'terraform/main.tf', note: 'Terraform provider "foobarcloud" has no detector' }], 'unknown providers are listed, utility providers are not');
});

test('Platforms: Fly, Render, Railway, Netlify, Cloudflare Workers and DigitalOcean', () => {
  const s = run('platforms');
  expect(s, { hosting: ['fly', 'render', 'railway', 'netlify', 'cloudflare', 'digitalocean'], frameworks: ['hono'], package_managers: ['npm'] });
  for (const h of s.hosting) assert.ok(h.kind === 'platform' || h.kind === 'cloud');
});

test('Polyglot: Rust Axum, ASP.NET Core, Phoenix and Vapor', () => {
  const s = run('polyglot');
  expect(s, {
    languages: ['rust', 'csharp'], frameworks: ['axum', 'sqlx', 'aspnet-core', 'phoenix', 'vapor'], package_managers: ['cargo', 'nuget', 'hex', 'swift-package-manager'],
    data_stores: ['postgres'], payments: ['stripe'], runtimes: ['rust', 'dotnet', 'elixir'],
  });
});

test('unknown stack: nothing is guessed, unknowns are listed, near misses do not fire', () => {
  const s = run('unknown-stack');
  for (const c of ['frameworks', 'package_managers', 'data_stores', 'auth', 'payments', 'ai', 'hosting', 'iac', 'ci', 'mobile'] as StackCategory[]) {
    assert.deepEqual(s[c], [], `${c} is empty`);
  }
  assert.deepEqual(s.unknown, [
    { file: 'app.json', note: 'configuration file with no detector' },
    { file: 'package.json', note: 'package.json with no lockfile in its folder or the repository root: package manager not determined' },
    { file: 'src/main.qzx', note: 'no detector for the file extension .qzx (1 file)' },
    { file: 'weird.toml', note: 'configuration file with no detector' },
  ]);
});

test('skips dependency, build and gitignored paths and says so', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-skip-'));
  try {
    cpSync(join(FIX, 'next-supabase'), dir, { recursive: true });
    for (const [p, body] of [
      ['node_modules/express/package.json', '{"name":"express"}'],
      ['vendor/lib.php', '<?php'],
      ['dist/bundle.js', "require('express')"],
      ['secret-build/out.js', "require('express')"],
      ['src/notes.local.ts', "import x from 'express';"],
      ['src/keep.local.ts', "import x from 'koa';"],
      ['src/lib/nested/.gitignore', 'ignored-here.ts\n'],
      ['src/lib/nested/ignored-here.ts', "import x from 'fastify';"],
    ]) { mkdirSync(join(dir, p, '..'), { recursive: true }); writeFileSync(join(dir, p), body); }
    symlinkSync(join(dir, 'package.json'), join(dir, 'linked.json'));
    const s = discover(dir, { detectors });
    assert.deepEqual(s.skipped, [
      { path: 'dist/', reason: 'build output' },
      { path: 'linked.json', reason: 'symlink' },
      { path: 'node_modules/', reason: 'dependency folder' },
      { path: 'secret-build/', reason: 'gitignore' },
      { path: 'src/lib/nested/ignored-here.ts', reason: 'gitignore' },
      { path: 'src/notes.local.ts', reason: 'gitignore' },
      { path: 'vendor/', reason: 'dependency folder' },
    ]);
    assert.ok(!ids(s, 'frameworks').includes('express'), 'skipped files are not read');
    assert.ok(!ids(s, 'frameworks').includes('fastify'), 'nested .gitignore applies');
    assert.ok(ids(s, 'frameworks').includes('koa'), 'a negated gitignore pattern keeps the file');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('determinism: two runs on every fixture give the same bytes', () => {
  for (const name of ['next-supabase', 'django-aws', 'iac-clouds', 'polyglot', 'unknown-stack', 'expo-firebase']) {
    const a = stableJson(discover(join(FIX, name), { detectors }));
    const b = stableJson(discover(join(FIX, name), { detectors: loadDetectors() }));
    assert.equal(a, b, name);
  }
});

test('commit is read from .git without running git, and is null outside a repository', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-git-'));
  try {
    writeFileSync(join(dir, 'go.mod'), 'module x\n');
    assert.equal(discover(dir, { detectors }).commit, null);
    const sha = 'a'.repeat(40);
    mkdirSync(join(dir, '.git/refs/heads'), { recursive: true });
    writeFileSync(join(dir, '.git/HEAD'), 'ref: refs/heads/dev\n');
    writeFileSync(join(dir, '.git/packed-refs'), `# pack-refs\n${sha} refs/heads/dev\n`);
    assert.equal(discover(dir, { detectors }).commit, sha);
    const loose = 'b'.repeat(40);
    writeFileSync(join(dir, '.git/refs/heads/dev'), loose + '\n');
    const s = discover(dir, { detectors });
    assert.equal(s.commit, loose, 'a loose ref wins over packed-refs');
    assert.deepEqual(s.skipped, [{ path: '.git/', reason: 'tool folder' }]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
