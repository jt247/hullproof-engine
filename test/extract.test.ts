// Manifest readers, import scan and gitignore rules.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractDeps, extractImports, nameMatches } from '../src/discover/extract.ts';
import { parseGitignore } from '../src/discover/walk.ts';
import { globToRegExp } from '../src/util.ts';

const names = (file: string, text: string): string[] => extractDeps(file, text).map((d) => `${d.name}@${d.version ?? ''}:${d.line ?? d.key}`);

test('pyproject: PEP 621 arrays, optional groups and build requires; other arrays ignored', () => {
  const text = [
    '[project]', 'name = "x"', 'keywords = ["web", "api"]', 'classifiers = [', '  "License :: OSI Approved",', ']',
    'dependencies = [', '  "Flask>=3.0",', '  "requests[socks] ==2.32.0 ; python_version > \'3.8\'",', ']',
    '[project.optional-dependencies]', 'dev = ["pytest"]', '[build-system]', 'requires = ["setuptools>=68"]',
  ].join('\n');
  assert.deepEqual(names('pyproject.toml', text), ['flask@>=3.0:8', 'requests@==2.32.0:9', 'pytest@:12', 'setuptools@>=68:14']);
});

test('requirements, go.mod, Cargo, Gemfile, pom, gradle, pubspec, csproj, Podfile, mix and Package.swift', () => {
  assert.deepEqual(names('requirements-dev.txt', '-r base.txt\nflask==3.0  # web\ngit+https://x/y.git\n'), ['flask@==3.0:2']);
  assert.deepEqual(names('go.mod', 'module m\nrequire github.com/a/b v1.0.0\nrequire (\n\tgithub.com/c/d v2.0.0 // indirect\n)\n'), ['github.com/a/b@v1.0.0:2', 'github.com/c/d@v2.0.0:4']);
  assert.deepEqual(names('Cargo.toml', '[package]\nname = "x"\n[dependencies]\naxum = "0.7"\nserde = { version = "1", features = [] }\n[dev-dependencies]\ntokio = "1"\n'), ['axum@0.7:4', 'serde@1:5', 'tokio@1:7']);
  assert.deepEqual(names('Gemfile', "gem 'rails', '~> 7.1'\n  gem \"pg\"\n"), ['rails@~> 7.1:1', 'pg@:2']);
  assert.deepEqual(names('pom.xml', '<project>\n<dependency>\n<groupId>org.a</groupId>\n<artifactId>b</artifactId>\n<version>1</version>\n</dependency>\n</project>'), ['org.a:b@1:4']);
  assert.deepEqual(names('app/build.gradle.kts', 'dependencies {\n  implementation("io.ktor:ktor-server-core:2.3.0")\n}\n'), ['io.ktor:ktor-server-core@2.3.0:2']);
  assert.deepEqual(names('pubspec.yaml', 'name: x\ndependencies:\n  flutter:\n    sdk: flutter\n  http: ^1.2.0\nflutter:\n  uses-material-design: true\n'), ['flutter@:3', 'http@^1.2.0:5']);
  assert.deepEqual(names('Api.csproj', '<PackageReference Include="Npgsql" Version="8.0.3" />'), ['Npgsql@8.0.3:1']);
  assert.deepEqual(names('Podfile', "platform :ios, '15.0'\npod 'Firebase/Auth', '10.0'\n"), ['Firebase/Auth@10.0:2']);
  assert.deepEqual(names('mix.exs', '[{:phoenix, "~> 1.7"}]'), ['phoenix@~> 1.7:1']);
  assert.deepEqual(names('Package.swift', '.package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),'), ['github.com/vapor/vapor@4.0.0:1']);
  assert.deepEqual(names('infra/main.tf', 'provider "aws" {}\nresource "google_storage_bucket" "b" {}\nmodule "m" { source = "./x" }\n'), ['aws@:1', 'google@:2']);
  assert.deepEqual(names('package.json', '{"dependencies":{"a":"1"},"devDependencies":{"b":"2"}}'), ['a@1:dependencies.a', 'b@2:devDependencies.b']);
  assert.deepEqual(names('package.json', 'not json'), []);
});

test('imports: first line per module, relative and alias imports dropped, Go import blocks', () => {
  const js = "import a from 'express';\nimport b from './local';\nconst c = require('@aws-sdk/client-s3');\nimport d from '@/alias';\nimport e from 'express';\nexport { f } from 'stripe';\n";
  assert.deepEqual(extractImports('src/x.ts', js).map((i) => `${i.module}:${i.line}`), ['express:1', '@aws-sdk/client-s3:3', 'stripe:6']);
  const go = 'package main\nimport (\n\t"fmt"\n\tg "github.com/gin-gonic/gin"\n)\nimport "os"\n';
  assert.deepEqual(extractImports('main.go', go).map((i) => `${i.module}:${i.line}`), ['fmt:3', 'github.com/gin-gonic/gin:4', 'os:6']);
  assert.deepEqual(extractImports('a.py', 'from django.contrib.auth import x\nimport boto3\nfrom . import y\n').map((i) => i.module), ['django.contrib.auth', 'boto3']);
  assert.deepEqual(extractImports('README.md', "import x from 'express'"), []);
});

test('name matching: exact, separator prefix and star prefix', () => {
  assert.ok(nameMatches('firebase/auth', 'firebase', '/'));
  assert.ok(!nameMatches('firebase-admin', 'firebase', '/'));
  assert.ok(nameMatches('@aws-sdk/client-s3', '@aws-sdk/*', '/'));
  assert.ok(nameMatches('org.springframework:spring-core', 'org.springframework', ':'));
  assert.ok(!nameMatches('org.springframework.boot:x', 'org.springframework', ':'));
  assert.ok(!nameMatches('flask-login', 'flask', ''));
});

test('globs and gitignore patterns', () => {
  assert.ok(globToRegExp('*.tf').test('a/b/main.tf'));
  assert.ok(!globToRegExp('.github/workflows/*.yml').test('x/.github/workflows/a.yml'));
  assert.ok(globToRegExp('**/supabase/config.toml').test('supabase/config.toml'));
  assert.ok(globToRegExp('**/supabase/config.toml').test('apps/web/supabase/config.toml'));
  assert.ok(globToRegExp('docker-compose.*.yml').test('docker-compose.test.yml'));
  const [anchored, anywhere, dirOnly, neg] = parseGitignore('/build-only\n*.log\ncache/\n!keep.log\n# comment\n\n', '');
  assert.ok(anchored.re.test('build-only') && !anchored.re.test('sub/build-only'));
  assert.ok(anywhere.re.test('a/b/c.log'));
  assert.ok(dirOnly.dirOnly && dirOnly.re.test('x/cache'));
  assert.ok(neg.negate && neg.re.test('keep.log'));
});
