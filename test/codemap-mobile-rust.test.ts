// The code map for native mobile apps (Android manifests, Info.plist, entitlements) and Rust (Cargo.toml, axum and actix routes), on small
// inline projects, plus the checks that read those facts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../src/discover/discover.ts';
import { makeContext } from '../src/checks/context.ts';
import { loadChecks, runChecks } from '../src/checks/run.ts';
import { PRO_MAP_CHECKS } from '../src/checks/pro-map.ts';
import { getMap } from '../src/checks/map/shared.ts';
import { readManifest, readPlistFile, readNetworkSecurity, isSecretValue } from '../src/map/mobile.ts';
import { readCargo } from '../src/map/rust.ts';
import { stableJson } from '../src/util.ts';
import type { CodeMap, EntryPoint } from '../src/types/index.ts';
import { validate } from './helpers/schema.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const schema = JSON.parse(readFileSync(join(ROOT, 'schemas/codemap.schema.json'), 'utf8'));
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-mob-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  return dir;
}
const mapOf = (dir: string): CodeMap => getMap(makeContext(dir, discover(dir)));
const find = (m: CodeMap, method: string | null, path: string | null, name?: string): EntryPoint => {
  const e = m.entry_points.find((x) => x.method === method && x.path === path && (name === undefined || x.name === name));
  assert.ok(e, `${method} ${path} ${name ?? ''} in ${m.entry_points.map((x) => `${x.kind} ${x.method} ${x.path} ${x.name}`).join(' | ')}`);
  return e;
};
const AUTHZ = new Set(['session_read', 'role_check', 'owner_filter', 'signature_verify']);
const kinds = (e: EntryPoint): string[] => [...new Set(e.protections.filter((p) => p.confidence !== 'low' && p.enforced !== false && AUTHZ.has(p.kind)).map((p) => p.kind))].sort();
const MANIFEST = (app: string, body: string, sdk = ''): string => `<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.app">\n${sdk}  <application ${app}>\n${body}\n  </application>\n</manifest>\n`;

test('Android: the manifest is read into components, flags, permissions and the target SDK', () => {
  const x = readManifest('AndroidManifest.xml', MANIFEST('android:allowBackup="true" android:debuggable="true" android:usesCleartextTraffic="false" android:networkSecurityConfig="@xml/nsc"', `
    <activity android:name=".Main" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
    <service android:name="com.other.Sync" android:exported="false"/>
    <receiver android:name="Boot" android:permission="com.acme.PERM"><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter></receiver>`, '  <uses-permission android:name="android.permission.CAMERA"/>\n  <uses-sdk android:targetSdkVersion="30"/>\n'), null).manifest;
  assert.equal(x.package, 'com.acme.app');
  assert.deepEqual([x.debuggable, x.allow_backup, x.uses_cleartext_traffic, x.target_sdk, x.network_security_config], [true, true, false, 30, '@xml/nsc']);
  assert.deepEqual(x.permissions, ['android.permission.CAMERA']);
  const by = Object.fromEntries(x.components.map((c) => [c.name, c]));
  assert.equal(by['com.acme.app.Main'].launcher, true);
  assert.equal(by['com.other.Sync'].exported, false);
  assert.equal(by['com.acme.app.Boot'].exported, true, 'an intent filter without an exported flag exports a component below target SDK 31');
  assert.equal(by['com.acme.app.Boot'].exported_explicit, false);
  assert.equal(by['com.acme.app.Boot'].permission, 'com.acme.PERM');
  const on31 = readManifest('AndroidManifest.xml', MANIFEST('', '<receiver android:name=".R"><intent-filter><action android:name="x"/></intent-filter></receiver>', '  <uses-sdk android:targetSdkVersion="33"/>\n'), null).manifest;
  assert.equal(on31.components[0].exported, false, 'from target SDK 31 an unflagged component is not exported');
  const gradle = readManifest('AndroidManifest.xml', MANIFEST('', '<receiver android:name=".R"><intent-filter><action android:name="x"/></intent-filter></receiver>'), 34).manifest;
  assert.equal(gradle.target_sdk, 34);
});

test('Android: exported components are entry points, deep links are named by their URL, launchers and private components are left out', () => {
  const dir = project({
    'app/src/main/AndroidManifest.xml': MANIFEST('', `
    <activity android:name=".Main" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
    <activity android:name=".Link" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><category android:name="android.intent.category.DEFAULT"/>
      <data android:scheme="https" android:host="a.test" android:pathPrefix="/x"/></intent-filter>
      <intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="app" android:host="open"/></intent-filter></activity>
    <receiver android:name=".Open" android:exported="true"/>
    <receiver android:name=".Guarded" android:exported="true" android:permission="com.acme.P"/>
    <service android:name=".Private" android:exported="false"/>
    <provider android:name=".Prov" android:authorities="a" android:exported="true" android:readPermission="com.acme.R"/>`),
    'app/build.gradle.kts': 'android { defaultConfig { targetSdk = 34 } }\n',
    'app/src/main/java/com/acme/app/Main.kt': 'package com.acme.app\nclass Main\n',
  });
  const m = mapOf(dir);
  const sig = m.entry_points.map((e) => `${e.kind} ${e.name}`).sort();
  assert.deepEqual(sig, ['deep_link app://open', 'deep_link https://a.test/x', 'ipc com.acme.app.Guarded', 'ipc com.acme.app.Open', 'ipc com.acme.app.Prov']);
  assert.deepEqual(kinds(find(m, null, null, 'com.acme.app.Guarded')), ['role_check']);
  assert.deepEqual(kinds(find(m, null, null, 'com.acme.app.Open')), []);
  assert.deepEqual(kinds(find(m, null, null, 'com.acme.app.Prov')), ['role_check']);
  assert.deepEqual(m.coverage.map((c) => [c.language, c.status, c.extractor]), [['kotlin', 'partial', 'android']]);
  assert.match(m.coverage[0].note, /source files are not read/);
});

test('Android: the network security configuration and the secrets written into config files', () => {
  const n = readNetworkSecurity('res/xml/network_security_config.xml', '<network-security-config><base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="user"/></trust-anchors></base-config><domain-config cleartextTrafficPermitted="true"><domain>old.acme.test</domain></domain-config><domain-config><domain>x.test</domain><pin-set><pin digest="SHA-256">AAA=</pin></pin-set></domain-config></network-security-config>');
  assert.deepEqual([n.cleartext_base, n.cleartext_domains, n.trusts_user_certs, n.pinned_domains], [false, ['old.acme.test'], true, 1]);
  assert.ok(isSecretValue('com.acme.STRIPE_SECRET_KEY', 'a-long-literal-value'));
  assert.ok(!isSecretValue('com.google.android.geo.API_KEY', 'AIzaSomethingLong0000'), 'a maps key is public by design');
  assert.ok(!isSecretValue('api_secret', '@string/x') && !isSecretValue('api_secret', 'YOUR_SECRET_HERE') && !isSecretValue('api_secret', 'short'), 'a reference, a placeholder and a short value are not secrets');
  const m = mapOf(project({
    'app/src/main/AndroidManifest.xml': MANIFEST('', '<meta-data android:name="client_secret" android:value="abcdefgh12345678"/><meta-data android:name="x_secret" android:value="@string/s"/>'),
    'app/src/main/res/values/strings.xml': '<resources><string name="db_password">hunter2hunter2</string><string name="app_name">App</string></resources>',
  }));
  assert.deepEqual(m.config.secrets.map((s) => `${s.where}:${s.key}`), ['android manifest:client_secret', 'android strings:db_password']);
  assert.ok(!stableJson(m).includes('abcdefgh12345678') && !stableJson(m).includes('hunter2hunter2'), 'the value is never copied into the map');
});

test('iOS: Info.plist and entitlements give App Transport Security, URL schemes, associated domains and secrets', () => {
  const plist = `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>one</string><string>two</string></array></dict></array>\n<key>PrivateKeyPassword</key><string>literal-value-1234</string>\n<key>NSCameraUsageDescription</key><string>Scan</string>\n<key>LSRequiresIPhoneOS</key><true/>\n</dict></plist>`;
  const r = readPlistFile('Info.plist', plist)!;
  assert.deepEqual([r.plist.ats_arbitrary_loads, r.plist.url_schemes, r.plist.usage_descriptions], [true, ['one', 'two'], ['NSCameraUsageDescription']]);
  assert.equal(r.secrets.length, 1);
  const ent = readPlistFile('A.entitlements', '<plist version="1.0"><dict><key>com.apple.developer.associated-domains</key><array><string>applinks:a.test</string><string>webcredentials:a.test</string></array></dict></plist>')!;
  assert.deepEqual(ent.plist.associated_domains, ['a.test']);
  const none = readPlistFile('Info.plist', '<plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict></dict></plist>')!;
  assert.equal(none.plist.ats_arbitrary_loads, null);
  const m = mapOf(project({ 'App/Info.plist': plist, 'App/App.entitlements': '<plist version="1.0"><dict><key>com.apple.developer.associated-domains</key><array><string>applinks:a.test</string></array></dict></plist>', 'App/A.swift': 'import UIKit\n' }));
  assert.deepEqual(m.entry_points.map((e) => `${e.kind} ${e.name}`).sort(), ['deep_link https://a.test/', 'deep_link one://', 'deep_link two://']);
  assert.deepEqual(m.coverage.map((c) => [c.language, c.status, c.extractor]), [['swift', 'partial', 'ios']]);
});

test('Cargo.toml: dependency sources, version forms, multi line tables, the release profile, lints, dev dependencies and the lockfile', () => {
  const t = readCargo('Cargo.toml', `[package]
name = "svc"
edition = "2021"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
lib = { git = "https://example.test/lib", branch = "main" }
local = { path = "../local" }
wide = "*"
multi = { version = "2",
  features = ["a"] }

[dependencies.extra]
version = "3"
git = "https://example.test/extra"

[dev-dependencies]
testdep = "1"

[profile.release]
debug = true
overflow-checks = false

[lints.rust]
unsafe_code = "forbid"
`, false, true);
  const by = Object.fromEntries(t.dependencies.map((d) => [d.name, d]));
  assert.deepEqual([by.axum.source, by.axum.version, by.tokio.version, by.lib.source, by.local.source, by.wide.version, by.multi.version, by.extra.source], ['registry', '0.7', '1', 'git', 'path', '*', '2', 'git']);
  assert.ok(!('testdep' in by), 'dev dependencies are not shipped');
  assert.deepEqual([t.name, t.edition, t.release_debug, t.release_overflow_checks, t.unsafe_code_lint, t.has_lock, t.binary], ['svc', '2021', true, false, 'forbid', false, true]);
  const lock = mapOf(project({ 'Cargo.toml': '[package]\nname = "a"\n', 'Cargo.lock': 'version = 3\n', 'src/main.rs': 'fn main() {}\n' }));
  assert.deepEqual([lock.config.cargo!.manifests[0].has_lock, lock.config.cargo!.manifests[0].binary], [true, true]);
  const ws = mapOf(project({ 'Cargo.lock': 'version = 3\n', 'crates/a/Cargo.toml': '[package]\nname = "a"\n', 'crates/a/src/lib.rs': '' }));
  assert.equal(ws.config.cargo!.manifests[0].has_lock, true, 'a lockfile at the workspace root counts');
});

const AXUM = `use axum::{middleware, routing::{get, post}, Router};
mod auth;
use auth::{require_admin, require_auth, AuthUser};
#[tokio::main]
async fn main() {
    let inner = Router::new().route("/a", get(a)).route_layer(middleware::from_fn(require_auth));
    let admin = Router::new().route("/purge", post(purge)).route_layer(middleware::from_fn(require_admin)).route_layer(middleware::from_fn(require_auth));
    let app = Router::new()
        .route("/open", get(open))
        .merge(inner)
        .nest("/admin", admin)
        .route("/late", get(late));
}
async fn open() {}
async fn a() {}
async fn purge() {}
async fn late(user: AuthUser) {}
`;
const AUTHRS = 'pub struct AuthUser;\npub async fn require_auth(req: Request, next: Next) -> Result<Response, StatusCode> {\n    if req.headers().get("authorization").is_none() { return Err(StatusCode::UNAUTHORIZED); }\n    Ok(next.run(req).await)\n}\npub async fn require_admin(req: Request, next: Next) -> Result<Response, StatusCode> {\n    Err(StatusCode::FORBIDDEN)\n}\n';

test('axum: route, merge, nest, route_layer applied to the routes before it, extractor types, and the routes after a layer', () => {
  const m = mapOf(project({ 'Cargo.toml': '[package]\nname = "a"\n[dependencies]\naxum = "0.7"\n', 'src/main.rs': AXUM, 'src/auth.rs': AUTHRS }));
  assert.deepEqual(m.entry_points.map((e) => `${e.method} ${e.path}`).sort(), ['GET /a', 'GET /late', 'GET /open', 'POST /admin/purge']);
  assert.deepEqual(kinds(find(m, 'GET', '/open')), []);
  assert.deepEqual(kinds(find(m, 'GET', '/a')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'POST', '/admin/purge')), ['role_check', 'session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/late')), ['session_read'], 'the extractor in the signature, not a layer');
  assert.ok(m.entry_points.every((e) => e.framework === 'axum' && e.data.length === 0 && e.outbound.length === 0), 'handler bodies are not read');
  assert.deepEqual(m.coverage.map((c) => [c.language, c.status, c.extractor]), [['rust', 'partial', 'rust']]);
  assert.match(m.coverage[0].note, /Handler bodies are not read/);
});

test('axum: a signature check in the handler, one method router with several methods, and a handler that is not in the project', () => {
  const m = mapOf(project({
    'Cargo.toml': '[package]\nname = "a"\n[dependencies]\naxum = "0.7"\n',
    'src/main.rs': 'fn app() -> Router {\n    Router::new()\n        .route("/webhooks/pay", post(pay))\n        .route("/x", get(read).delete(remove))\n        .route("/ext", get(other::handler))\n}\nasync fn pay(headers: HeaderMap, body: Bytes) -> StatusCode {\n    if !verify_signature(&headers, &body) { return StatusCode::UNAUTHORIZED; }\n    StatusCode::OK\n}\nasync fn read() {}\nasync fn remove() {}\n',
  }));
  assert.equal(find(m, 'POST', '/webhooks/pay').kind, 'webhook');
  assert.deepEqual(kinds(find(m, 'POST', '/webhooks/pay')), ['signature_verify']);
  assert.deepEqual(m.entry_points.filter((e) => e.path === '/x').map((e) => e.method).sort(), ['DELETE', 'GET']);
  assert.equal(find(m, 'GET', '/ext').confidence, 'medium');
});

test('actix web: the attribute macros give routes, and an extractor type protects one', () => {
  const m = mapOf(project({
    'Cargo.toml': '[package]\nname = "a"\n[dependencies]\nactix-web = "4"\n',
    'src/main.rs': '#[get("/ping")]\nasync fn ping() -> impl Responder { "pong" }\n\n#[post("/notes")]\nasync fn create(user: AuthUser, body: Json<N>) -> impl Responder { "ok" }\n',
  }));
  assert.deepEqual(m.entry_points.map((e) => `${e.method} ${e.path} ${e.framework}`).sort(), ['GET /ping actix-web', 'POST /notes actix-web']);
  assert.deepEqual(kinds(find(m, 'POST', '/notes')), ['session_read']);
});

const mapChecks = (dir: string, ids: string[]) => {
  const ctx = makeContext(dir, discover(dir));
  return runChecks(ctx, loadChecks().filter((c) => ids.includes(c.id)));
};
const SECRET_FIXTURE = (secret: boolean): Record<string, string> => ({ 'app/src/main/AndroidManifest.xml': MANIFEST('', secret ? '<meta-data android:name="client_secret" android:value="abcdefgh12345678"/>' : '<meta-data android:name="client_id" android:value="abcdefgh12345678"/>') });

test('check.map.mobile-secret-in-config: fails on a value written under a secret name, never prints the value, passes without one', () => {
  const bad = mapChecks(project(SECRET_FIXTURE(true)), ['check.map.mobile-secret-in-config']);
  assert.equal(bad.results[0].result, 'FAIL');
  assert.match(bad.results[0].evidence[0].note, /client_secret/);
  assert.ok(!JSON.stringify(bad).includes('abcdefgh12345678'));
  const good = mapChecks(project(SECRET_FIXTURE(false)), ['check.map.mobile-secret-in-config']);
  assert.equal(good.results[0].result, 'NOT ASSESSED: NEEDS DYNAMIC TEST');
  assert.equal(mapChecks(project({ 'a.txt': 'x' }), ['check.map.mobile-secret-in-config']).not_run.length, 1);
});

test('the Pro mobile and Rust checks fail on a bad manifest, plist and Cargo.toml and leave a good one alone', { skip: PRO_MAP_CHECKS.length ? false : 'the Pro map checks are not in this edition' }, () => {
  const ids = ['check.map.android-cleartext-traffic', 'check.map.android-debuggable', 'check.map.android-backup-allowed', 'check.map.android-exported-without-permission', 'check.map.ios-ats-arbitrary-loads', 'check.map.cargo-nonregistry-dependency'];
  const bad = project({
    'app/src/main/AndroidManifest.xml': MANIFEST('android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true"', '<receiver android:name=".R" android:exported="true"/><activity android:name=".L" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="a.test"/></intent-filter></activity>'),
    'app/src/debug/AndroidManifest.xml': MANIFEST('android:debuggable="true"', ''),
    'app/src/main/res/xml/network_security_config.xml': '<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>',
    'Notes/Info.plist': '<plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>',
    'Cargo.toml': '[package]\nname = "a"\n[dependencies]\nlib = { git = "https://example.test/lib" }\n',
  });
  const r = mapChecks(bad, ids);
  assert.deepEqual(r.results.map((x) => x.check_id).sort(), ids.slice().sort());
  assert.ok(r.results.every((x) => x.result === 'FAIL'), JSON.stringify(r.results.map((x) => [x.check_id, x.result])));
  const debug = r.results.find((x) => x.check_id === 'check.map.android-debuggable')!;
  assert.equal(debug.evidence.length, 1, 'a debug source set is not judged');
  assert.equal(r.results.find((x) => x.check_id === 'check.map.android-exported-without-permission')!.evidence.length, 1, 'the browsable deep link is by design');
  const good = project({
    'app/src/main/AndroidManifest.xml': MANIFEST('android:allowBackup="false" android:usesCleartextTraffic="false"', '<receiver android:name=".R" android:exported="true" android:permission="com.acme.P"/>'),
    'Notes/Info.plist': '<plist version="1.0"><dict><key>CFBundleName</key><string>n</string></dict></plist>',
    'Cargo.toml': '[package]\nname = "a"\n[dependencies]\nlib = "1"\n',
  });
  assert.ok(mapChecks(good, ids).results.every((x) => x.result !== 'FAIL'));
});

test('mobile and Rust maps are deterministic, free of absolute paths, and match the codemap schema', () => {
  const dir = project({ ...SECRET_FIXTURE(true), 'Cargo.toml': '[package]\nname = "a"\n', 'src/main.rs': AXUM, 'src/auth.rs': AUTHRS, 'N/Info.plist': '<plist version="1.0"><dict><key>CFBundleName</key><string>n</string></dict></plist>' });
  const a = stableJson(mapOf(dir));
  assert.equal(a, stableJson(mapOf(dir)));
  assert.deepEqual(validate(schema, JSON.parse(a)), []);
  assert.ok(!a.includes(dir));
});
