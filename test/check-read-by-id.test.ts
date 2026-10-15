// check.map.read-by-id-without-owner: a signed in route reads a record by an id from the request with no owner value in the query.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { discover } from '../src/discover/discover.ts';
import { makeContext } from '../src/checks/context.ts';
import { loadChecks, runChecks } from '../src/checks/run.ts';

const ID = 'check.map.read-by-id-without-owner';
function run(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'hp-idor-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  const r = runChecks(makeContext(dir, discover(dir)), loadChecks().filter((c) => c.id === ID));
  return { res: r.results[0], notRun: r.not_run[0] };
}
const SPRING_POM = '<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency><dependency><artifactId>spring-boot-starter-security</artifactId></dependency></dependencies></project>';
const spring = (body: string): Record<string, string> => ({ 'pom.xml': SPRING_POM, 'src/main/java/app/web/C.java': `package app.web;\n@RestController\n@RequestMapping("/api")\npublic class C {\n${body}\n}\n` });

test('a signed in Spring read by id with no owner fails; the same read with the owner passes', () => {
  const bad = run(spring('  @GetMapping("/n/{id}") public Note get(@PathVariable Long id) { return noteRepository.findById(id).orElseThrow(); }'));
  assert.equal(bad.res?.result, 'FAIL');
  assert.match(bad.res.evidence[0].note, /by an id from the request/);
  const good = run(spring('  @GetMapping("/n/{id}") public Note get(@AuthenticationPrincipal UserPrincipal user, @PathVariable Long id) { return noteRepository.findByIdAndOwnerId(id, user.getId()).orElseThrow(); }'));
  assert.notEqual(good.res?.result, 'FAIL');
});

test('it leaves out a route with a role check, a public route and a read that is not by id', () => {
  const admin = run({ ...spring('  @GetMapping("/admin/n/{id}") @PreAuthorize("hasRole(\'ADMIN\')") public Note get(@PathVariable Long id) { return noteRepository.findById(id).orElseThrow(); }\n  @GetMapping("/n") public List<Note> all(@AuthenticationPrincipal UserPrincipal u) { return noteRepository.findAll(); }'), 'src/main/java/app/S.java': 'package app;\n@EnableMethodSecurity\n@Configuration\npublic class S {}\n' });
  assert.notEqual(admin.res?.result, 'FAIL');
  const noSession = run({ 'package.json': '{"dependencies":{"express":"4"}}', 'server.js': "const express = require('express');\nconst app = express();\napp.get('/p/:id', async (req, res) => { res.json(await db.query('SELECT * FROM posts WHERE id = $1', [req.params.id])); });\napp.listen(3000);\n" });
  assert.notEqual(noSession.res?.result, 'FAIL', 'an unauthenticated read is the job of data-read-without-auth');
});

test('with no signed in read by id the check does not apply', () => {
  const r = run({ 'package.json': '{"dependencies":{"express":"4"}}', 'server.js': "const express = require('express');\nconst app = express();\napp.get('/ping', (req, res) => res.send('x'));\napp.listen(3000);\n" });
  assert.match(r.notRun?.reason ?? '', /not applicable/);
});

test('a read of a record that is not personal data (a story, a domain, a tag) is not flagged, a read of an invoice is', () => {
  const body = (noun: string): string => `  @GetMapping("/x/{id}") public Thing get(@AuthenticationPrincipal UserPrincipal user, @PathVariable Long id) { return ${noun}Repository.findById(id).orElseThrow(); }`;
  assert.notEqual(run(spring(body('story'))).res?.result, 'FAIL');
  assert.equal(run(spring(body('invoice'))).res?.result, 'FAIL');
});

test('Rails: a redirect to a route helper with a request value inside is not an open redirect lead', () => {
  const r = (line: string) => {
    const dir = mkdtempSync(join(tmpdir(), 'hp-redir-'));
    for (const [f, t] of Object.entries({ 'Gemfile': "gem 'rails'\n", 'config/routes.rb': "Rails.application.routes.draw do\n  get '/go' => 'go#index'\nend\n", 'app/controllers/go_controller.rb': `class GoController < ApplicationController\n  def index\n    ${line}\n  end\nend\n` })) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
    return runChecks(makeContext(dir, discover(dir)), loadChecks().filter((c) => c.id === 'check.map.redirect-from-request')).results[0]?.result;
  };
  assert.equal(r('redirect_to params[:next]'), 'FAIL');
  assert.notEqual(r('redirect_to thing_path(params[:id])'), 'FAIL');
});

const DOTNET_CSPROJ = '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>';
const dotnet = (body: string): Record<string, string> => ({
  'App.csproj': DOTNET_CSPROJ,
  'Controllers/InvoicesController.cs': `using Microsoft.AspNetCore.Authorization;\nusing Microsoft.AspNetCore.Mvc;\n\n[ApiController]\n[Authorize]\n[Route("api/invoices")]\npublic class InvoicesController : ControllerBase {\n  private readonly AppDb _db;\n  public InvoicesController(AppDb db) { _db = db; }\n${body}\n}\n`,
});

test('ASP.NET Core: a signed in read by id with no owner fails; the same read with the owner passes', () => {
  const bad = run(dotnet('  [HttpGet("{id}")]\n  public async Task<IActionResult> Get(int id) {\n    var invoice = await _db.Invoices.FindAsync(id);\n    return Ok(invoice);\n  }'));
  assert.equal(bad.res?.result, 'FAIL', bad.notRun?.reason);
  assert.match(bad.res.evidence[0].note, /by an id from the request/);
  const good = run(dotnet('  [HttpGet("{id}")]\n  public async Task<IActionResult> Get(int id) {\n    var userId = User.FindFirst(ClaimTypes.NameIdentifier)!.Value;\n    var invoice = await _db.Invoices.FirstOrDefaultAsync(i => i.Id == id && i.OwnerId == userId);\n    return Ok(invoice);\n  }'));
  assert.notEqual(good.res?.result, 'FAIL');
});
