// The code map for Spring (Java) and ASP.NET Core (C#), on small inline projects: the routing forms, the protections each one gets from
// annotations, the Spring Security filter chain, attributes and policies, and the places where the engine says it cannot tell.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../src/discover/discover.ts';
import { makeContext } from '../src/checks/context.ts';
import { getMap } from '../src/checks/map/shared.ts';
import { stableJson } from '../src/util.ts';
import type { CodeMap, EntryPoint } from '../src/types/index.ts';
import { validate } from './helpers/schema.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const schema = JSON.parse(readFileSync(join(ROOT, 'schemas/codemap.schema.json'), 'utf8'));
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-jvm-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  return dir;
}
const mapOf = (dir: string): CodeMap => getMap(makeContext(dir, discover(dir)));
const find = (m: CodeMap, method: string, path: string): EntryPoint => { const e = m.entry_points.find((x) => x.method === method && x.path === path); assert.ok(e, `${method} ${path} in ${m.entry_points.map((x) => `${x.method} ${x.path}`).join(', ')}`); return e; };
const AUTHZ = new Set(['session_read', 'role_check', 'owner_filter', 'signature_verify']);
const kinds = (e: EntryPoint): string[] => [...new Set(e.protections.filter((p) => p.confidence !== 'low' && p.enforced !== false && AUTHZ.has(p.kind)).map((p) => p.kind))].sort();
const POM = '<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>';
const POM_SEC = '<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency><dependency><artifactId>spring-boot-starter-security</artifactId></dependency></dependencies></project>';
const ctl = (body: string, head = '@RestController\n@RequestMapping("/api")'): string => `package app.web;\nimport org.springframework.web.bind.annotation.*;\n${head}\npublic class C {\n${body}\n}\n`;
const J = 'src/main/java/app/web/C.java';
const cfg = (chain: string, extra = ''): string => `package app;\n${extra}@Configuration\n@EnableWebSecurity\npublic class S {\n  @Bean\n  public SecurityFilterChain f(HttpSecurity http) throws Exception {\n    http${chain};\n    return http.build();\n  }\n}\n`;

test('Spring: the mapping annotations, path arrays, RequestMapping with several methods, and a class level prefix', () => {
  const m = mapOf(project({
    'pom.xml': POM,
    [J]: ctl(`
  @GetMapping({"/a", "/b"}) public String ab() { return "x"; }
  @RequestMapping(value = "/c", method = {RequestMethod.GET, RequestMethod.POST}) public String c() { return "x"; }
  @RequestMapping("/d") public String d() { return "x"; }
  @PatchMapping(path = "/e/{id}") public String e(@PathVariable Long id) { return "x"; }
  @DeleteMapping public String root() { return "x"; }`),
  }));
  const sig = m.entry_points.map((e) => `${e.method} ${e.path}`).sort();
  assert.deepEqual(sig, ['ANY /api/d', 'DELETE /api', 'GET /api/a', 'GET /api/b', 'GET /api/c', 'PATCH /api/e/:id', 'POST /api/c']);
  assert.deepEqual(m.coverage.map((c) => [c.language, c.status, c.extractor]), [['java', 'mapped', 'spring']]);
  assert.ok(m.entry_points.every((e) => e.framework === 'spring'));
});

test('Spring: a controller without a mapping annotation, an interface and a class that is not a controller give no entry point', () => {
  const m = mapOf(project({
    'pom.xml': POM,
    'src/A.java': 'package a;\npublic class Helper { @GetMapping("/x") public String x() { return ""; } }\n',
    'src/B.java': 'package a;\n@RestController\npublic class B { public String plain() { return ""; } }\n',
  }));
  assert.equal(m.entry_points.length, 0);
});

test('Spring: method security annotations count as enforced only when method security is switched on', () => {
  const body = '  @GetMapping("/r") @PreAuthorize("hasRole(\'ADMIN\')") public String r() { return "x"; }';
  const off = mapOf(project({ 'pom.xml': POM_SEC, [J]: ctl(body), 'src/S.java': cfg('.authorizeHttpRequests(a -> a.anyRequest().permitAll())') }));
  const eOff = find(off, 'GET', '/api/r');
  assert.ok(!kinds(eOff).includes('role_check'), JSON.stringify(eOff.protections));
  assert.ok(eOff.protections.some((p) => p.kind === 'role_check' && p.enforced === false && /not enabled/.test(p.via)));
  const on = mapOf(project({ 'pom.xml': POM_SEC, [J]: ctl(body), 'src/S.java': cfg('.authorizeHttpRequests(a -> a.anyRequest().permitAll())', '@EnableMethodSecurity\n') }));
  assert.ok(kinds(find(on, 'GET', '/api/r')).includes('role_check'));
  const old = mapOf(project({ 'pom.xml': POM_SEC, [J]: ctl('  @GetMapping("/s") @Secured("ROLE_ADMIN") public String s() { return "x"; }'), 'src/S.java': cfg('.authorizeHttpRequests(a -> a.anyRequest().permitAll())', '@EnableGlobalMethodSecurity(securedEnabled = true)\n') }));
  assert.ok(kinds(find(old, 'GET', '/api/s')).includes('role_check'));
});

test('Spring: the filter chain, first matching rule wins, with methods, wildcards and anyRequest', () => {
  const chain = `.authorizeHttpRequests(auth -> auth
      .requestMatchers("/health", "/api/public/**").permitAll()
      .requestMatchers(HttpMethod.DELETE, "/api/items/*").hasRole("ADMIN")
      .requestMatchers("/api/admin/**").hasAnyRole("ADMIN", "STAFF")
      .anyRequest().authenticated())`;
  const m2 = mapOf(project({
    'pom.xml': POM_SEC,
    [J]: ctl(`
  @GetMapping("/public/x") public String pub() { return "x"; }
  @GetMapping("/items/{id}") public String get(@PathVariable Long id) { return "x"; }
  @DeleteMapping("/items/{id}") public String del(@PathVariable Long id) { return "x"; }
  @GetMapping("/admin/stats") public String stats() { return "x"; }
  @GetMapping("/things") public String things() { return "x"; }`),
    'src/S.java': cfg(chain),
  }));
  assert.deepEqual(kinds(find(m2, 'GET', '/api/public/x')), []);
  assert.deepEqual(kinds(find(m2, 'GET', '/api/items/:id')), ['session_read']);
  assert.deepEqual(kinds(find(m2, 'DELETE', '/api/items/:id')), ['role_check', 'session_read']);
  assert.deepEqual(kinds(find(m2, 'GET', '/api/admin/stats')), ['role_check', 'session_read']);
  assert.deepEqual(kinds(find(m2, 'GET', '/api/things')), ['session_read']);
  assert.ok(m2.gates.length >= 4 && m2.gates.every((g) => g.framework === 'spring'), 'the rules are listed as gates');
});

test('Spring: the older authorizeRequests chain with antMatchers is read the same way', () => {
  const m = mapOf(project({
    'pom.xml': POM_SEC,
    [J]: ctl('  @GetMapping("/admin/x") public String a() { return "x"; }\n  @GetMapping("/open") public String o() { return "x"; }'),
    'src/S.java': cfg('.authorizeRequests().antMatchers("/api/open").permitAll().antMatchers("/api/admin/**").hasRole("ADMIN").anyRequest().authenticated()'),
  }));
  assert.deepEqual(kinds(find(m, 'GET', '/api/admin/x')), ['role_check', 'session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/api/open')), []);
});

test('Spring: with the security starter and no filter chain every request needs a sign in; without the starter nothing protects a route', () => {
  const code = ctl('  @GetMapping("/x") public String x() { return "x"; }');
  assert.deepEqual(kinds(find(mapOf(project({ 'pom.xml': POM_SEC, [J]: code })), 'GET', '/api/x')), ['session_read']);
  assert.deepEqual(kinds(find(mapOf(project({ 'pom.xml': POM, [J]: code })), 'GET', '/api/x')), []);
});

test('Spring: the handler body is read: a request id used in a repository call, the owner in the query, a principal parameter', () => {
  const m = mapOf(project({
    'pom.xml': POM,
    [J]: ctl(`
  @GetMapping("/a/{id}") public Note a(@PathVariable Long id) { return noteRepository.findById(id).orElseThrow(); }
  @GetMapping("/b/{id}") public Note b(@AuthenticationPrincipal UserPrincipal user, @PathVariable Long id) { return noteRepository.findByIdAndOwnerId(id, user.getId()).orElseThrow(); }
  @PostMapping("/c") public void c(@RequestBody Req body) { restTemplate.getForObject(body.getUrl(), String.class); }`),
  }));
  const a = find(m, 'GET', '/api/a/:id');
  assert.ok(a.data.some((d) => d.op === 'read' && d.by_id && !d.owner_scoped && d.target === 'note'), JSON.stringify(a.data));
  const b = find(m, 'GET', '/api/b/:id');
  assert.ok(b.data.some((d) => d.by_id && d.owner_scoped), JSON.stringify(b.data));
  assert.ok(kinds(b).includes('owner_filter') && kinds(b).includes('session_read'));
  const c = find(m, 'POST', '/api/c');
  assert.ok(c.outbound.some((o) => o.kind === 'http' && o.request_derived && !o.guarded));
});

test('Spring: a webhook path gives a webhook entry point, and constructEvent before use is a signature check', () => {
  const m = mapOf(project({
    'pom.xml': POM,
    [J]: ctl(`
  @PostMapping("/webhooks/pay") public String a(@RequestBody String p, @RequestHeader("Stripe-Signature") String sig) throws Exception { Event e = Webhook.constructEvent(p, sig, secret); return "ok"; }
  @PostMapping("/webhooks/other") public String b(@RequestBody String p) { return "ok"; }`),
  }));
  const a = find(m, 'POST', '/api/webhooks/pay');
  assert.equal(a.kind, 'webhook');
  assert.ok(kinds(a).includes('signature_verify'));
  assert.ok(!kinds(find(m, 'POST', '/api/webhooks/other')).includes('signature_verify'));
});

const PROGRAM = (body: string): string => `using Microsoft.AspNetCore.Authorization;\nvar builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\n${body}\napp.Run();\n`;
const CTL = (attrs: string, body: string, ns = 'namespace App;'): string => `using Microsoft.AspNetCore.Mvc;\n${ns}\n${attrs}\npublic class ThingsController : ControllerBase\n{\n${body}\n}\n`;

test('ASP.NET Core: controller routes, [controller] and [action] tokens, constraints, absolute templates, and a block scoped namespace', () => {
  const files = { 'App.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>', 'Things.cs': CTL('[ApiController]\n[Route("api/[controller]")]', `
  [HttpGet] public IActionResult List() => Ok();
  [HttpGet("{id:int}")] public IActionResult Get(int id) => Ok();
  [HttpPost("[action]")] public IActionResult Make() => Ok();
  [HttpPut("/absolute/{name?}")] public IActionResult Put(string name) => Ok();
  public IActionResult NotAnAction() => Ok();`) };
  const m2 = mapOf(project(files));
  assert.deepEqual(m2.entry_points.map((e) => `${e.method} ${e.path}`).sort(), ['GET /api/things', 'GET /api/things/:id', 'POST /api/things/make', 'PUT /absolute/:name']);
  const blockNs = mapOf(project({ ...files, 'Things.cs': files['Things.cs'].replace('namespace App;', 'namespace App\n{').concat('}\n') }));
  assert.equal(blockNs.entry_points.length, 4, 'a class inside a block scoped namespace is found');
  assert.deepEqual(m2.coverage.map((c) => [c.language, c.status, c.extractor]), [['csharp', 'mapped', 'aspnet']]);
});

test('ASP.NET Core: [Authorize], roles, policies, and [AllowAnonymous] turning them off', () => {
  const m = mapOf(project({
    'App.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    'A.cs': CTL('[ApiController]\n[Route("a")]\n[Authorize]', `
  [HttpGet("one")] public IActionResult One() => Ok();
  [HttpGet("two"), Authorize(Roles = "Admin")] public IActionResult Two() => Ok();
  [HttpGet("three")]
  [AllowAnonymous]
  public IActionResult Three() => Ok();
  [HttpGet("four")]
  [Authorize(Policy = "Billing")]
  public IActionResult Four() => Ok();`),
  }));
  assert.deepEqual(kinds(find(m, 'GET', '/a/one')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/a/two')), ['role_check', 'session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/a/three')), []);
  assert.deepEqual(kinds(find(m, 'GET', '/a/four')), ['role_check', 'session_read']);
});

test('ASP.NET Core: minimal APIs, groups, RequireAuthorization, AllowAnonymous on a group member, and a method group handler', () => {
  const m = mapOf(project({
    'App.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    'Program.cs': PROGRAM(`
app.MapGet("/open", () => "x");
app.MapGet("/closed", () => "x").RequireAuthorization();
var api = app.MapGroup("/api").RequireAuthorization();
api.MapGet("/things/{id}", (int id) => id);
api.MapPost("/login", (LoginRequest body) => "x").AllowAnonymous();
var admin = api.MapGroup("/admin");
admin.MapPost("/purge", Handlers.Purge).RequireAuthorization("AdminOnly");
app.MapMethods("/multi", new[] { "GET", "POST" }, () => "x");`),
    'Handlers.cs': 'public static class Handlers\n{\n    public static IResult Purge(AppDb db)\n    {\n        db.Things.RemoveRange(db.Things);\n        return Results.Ok();\n    }\n}\n',
  }));
  assert.deepEqual(kinds(find(m, 'GET', '/open')), []);
  assert.deepEqual(kinds(find(m, 'GET', '/closed')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/api/things/:id')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'POST', '/api/login')), []);
  assert.deepEqual(kinds(find(m, 'POST', '/api/admin/purge')), ['role_check', 'session_read']);
  assert.ok(find(m, 'POST', '/api/admin/purge').data.some((d) => d.op === 'delete'), 'the method group handler body is read');
  assert.deepEqual(m.entry_points.filter((e) => e.path === '/multi').map((e) => e.method).sort(), ['GET', 'POST']);
});

test('ASP.NET Core: a fallback policy that needs a sign in covers every endpoint that is not anonymous', () => {
  const m = mapOf(project({
    'App.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    'Program.cs': PROGRAM('builder.Services.AddAuthorization(o => { o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); });\napp.MapGet("/a", () => "x");\napp.MapGet("/b", () => "x").AllowAnonymous();'),
    'C.cs': CTL('[ApiController]\n[Route("c")]', '  [HttpGet] public IActionResult G() => Ok();'),
  }));
  assert.deepEqual(kinds(find(m, 'GET', '/a')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/b')), []);
  assert.deepEqual(kinds(find(m, 'GET', '/c')), ['session_read']);
});

test('ASP.NET Core: the body is read (a find by id with no owner, an owner in the query, a signature check before use)', () => {
  const m = mapOf(project({
    'App.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    'N.cs': CTL('[ApiController]\n[Route("n")]\n[Authorize]', `
  [HttpGet("a/{id}")] public async Task<IActionResult> A(int id) { var n = await _db.Notes.FindAsync(id); return Ok(n); }
  [HttpGet("b/{id}")] public async Task<IActionResult> B(int id) { var uid = User.FindFirstValue(ClaimTypes.NameIdentifier); var n = await _db.Notes.FirstOrDefaultAsync(x => x.Id == id && x.OwnerId == uid); return Ok(n); }
  [HttpPost("hook"), AllowAnonymous] public async Task<IActionResult> H() { var p = await new StreamReader(Request.Body).ReadToEndAsync(); var e = EventUtility.ConstructEvent(p, sig, secret); return Ok(); }`),
  }));
  assert.ok(find(m, 'GET', '/n/a/:id').data.some((d) => d.by_id && !d.owner_scoped && d.target === 'Notes'));
  assert.ok(find(m, 'GET', '/n/b/:id').data.some((d) => d.by_id && d.owner_scoped));
  assert.ok(kinds(find(m, 'POST', '/n/hook')).includes('signature_verify'));
});

test('Spring and ASP.NET Core maps are deterministic and match the codemap schema', () => {
  const dir = project({
    'pom.xml': POM_SEC, [J]: ctl('  @GetMapping("/x") public String x() { return "x"; }'), 'src/S.java': cfg('.authorizeHttpRequests(a -> a.anyRequest().authenticated())'),
    'App.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>', 'Program.cs': PROGRAM('app.MapGet("/y", () => "x");'),
  });
  const a = stableJson(mapOf(dir));
  assert.equal(a, stableJson(mapOf(dir)));
  assert.deepEqual(validate(schema, JSON.parse(a)), []);
  assert.ok(!a.includes(dir), 'no absolute path');
});
