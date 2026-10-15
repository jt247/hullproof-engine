// The code map for the second wave stacks: Go (chi, gin, net/http, echo, fiber, gorilla/mux), Rails, Laravel and Expo.
// Small synthetic apps in test/fixtures/map-more (a fail copy with the planted flaws and a pass copy that fixes them), plus
// inline projects for the routing forms the fixtures do not use. No third party code is copied.
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
import { stableJson } from '../src/util.ts';
import type { CodeMap, EntryPoint } from '../src/types/index.ts';
import { validate } from './helpers/schema.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MORE = join(ROOT, 'test/fixtures/map-more');
const schema = JSON.parse(readFileSync(join(ROOT, 'schemas/codemap.schema.json'), 'utf8'));
const mapOf = (dir: string): CodeMap => getMap(makeContext(dir, discover(dir)));
const sig = (m: CodeMap, stack: string): string[] => m.entry_points.filter((e) => e.file.startsWith(stack + '/')).map((e) => `${e.kind} ${e.method ?? '-'} ${e.path ?? e.name}`).sort();

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-more-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  return dir;
}
const find = (m: CodeMap, method: string, path: string): EntryPoint => {
  const e = m.entry_points.find((x) => x.method === method && x.path === path);
  assert.ok(e, `${method} ${path} in ${m.entry_points.map((x) => `${x.method} ${x.path}`).join(', ')}`);
  return e;
};
const has = (e: EntryPoint, kind: string, scope?: string): boolean => e.protections.some((p) => p.kind === kind && p.confidence !== 'low' && p.enforced !== false && (!scope || p.scope === scope));

const NINE_GO = ['http_route DELETE /api/notes/:id', 'http_route GET /api/export', 'http_route GET /api/items', 'http_route POST /api/admin/users/role', 'http_route POST /api/import', 'http_route POST /api/login', 'http_route POST /api/notes', 'http_route POST /api/upload', 'webhook POST /webhooks/pay'];
const NINE_RAILS = ['http_route DELETE /notes/:id', 'http_route GET /api/export', 'http_route GET /api/items', 'http_route POST /admin/users/:id/role', 'http_route POST /api/import', 'http_route POST /api/upload', 'http_route POST /login', 'http_route POST /notes', 'webhook POST /webhooks/pay'];
const NINE_LARAVEL = ['http_route DELETE /notes/:note', 'http_route GET /api/export', 'http_route GET /api/items', 'http_route POST /admin/users/:user/role', 'http_route POST /api/import', 'http_route POST /api/upload', 'http_route POST /login', 'http_route POST /notes', 'webhook POST /webhooks/pay'];
const EXPO = ['deep_link - Linking url listener', 'deep_link - https://notes.example.com/', 'deep_link - https://notes.example.com/n', 'deep_link - notesapp://', 'http_route POST /api/notes', 'page - /', 'page - /account', 'page - /notes/:id', 'page - /sign-in'];

for (const side of ['fail', 'pass']) {
  test(`entry points of Go, Rails, Laravel and Expo (${side} copy)`, () => {
    const m = mapOf(join(MORE, side));
    assert.deepEqual(sig(m, 'go'), NINE_GO);
    assert.deepEqual(sig(m, 'rails'), NINE_RAILS);
    assert.deepEqual(sig(m, 'laravel'), NINE_LARAVEL);
    assert.deepEqual(sig(m, 'expo'), EXPO);
    assert.equal(sig(m, 'gin').length, 3);
    assert.deepEqual(m.coverage.map((c) => [c.language, c.status, c.extractor]), [['go', 'mapped', 'go'], ['php', 'mapped', 'laravel'], ['ruby', 'mapped', 'rails'], ['typescript', 'mapped', 'node-ts']]);
  });
}

// Which stacks each check must flag in the fail copy. The pass copy must not be flagged by any check.
const OPEN: Record<string, string[]> = {
  'admin-route-without-role': ['go', 'laravel', 'rails'],
  'data-read-without-auth': ['go', 'laravel', 'rails'],
  'mutating-route-without-auth': ['expo', 'gin', 'go', 'laravel', 'rails'],
  'privileged-action-without-audit': ['go', 'laravel', 'rails'],
  'privileged-field-from-request': ['gin', 'go', 'laravel', 'rails'],
  'redirect-from-request': ['go', 'laravel', 'rails'],
  'request-url-fetched': ['go', 'laravel', 'rails'],
  'webhook-verify-before-use': ['go', 'laravel', 'rails'],
  'write-by-id-without-owner': ['gin', 'go', 'laravel', 'rails'],
};
// The four checks that settle only Pro requirements are loaded only in an edition that has them (src/checks/pro-map.ts).
const PRO: Record<string, string[]> = {
  'auth-endpoint-without-rate-limit': ['go', 'laravel', 'rails'],
  'input-without-schema': ['expo', 'gin', 'go', 'laravel', 'rails'],
  'page-size-from-request': ['go', 'laravel', 'rails'],
  'upload-without-limits': ['go', 'laravel', 'rails'],
};
const MATRIX = PRO_MAP_CHECKS.length > 0 ? { ...OPEN, ...PRO } : OPEN;

test('each map check flags the fail copy of the second wave stacks it applies to, and nothing in the pass copy', () => {
  const checks = loadChecks().filter((c) => c.id.startsWith('check.map.') && !/supabase|firebase|android|ios-|cargo-|mobile-|read-by-id-/.test(c.id));
  assert.deepEqual(checks.map((c) => c.id.slice('check.map.'.length)).sort(), Object.keys(MATRIX).sort());
  const run = (side: string) => { const dir = join(MORE, side); return runChecks(makeContext(dir, discover(dir), [], null), checks); };
  const fail = run('fail');
  const pass = run('pass');
  for (const [name, stacks] of Object.entries(MATRIX)) {
    const id = `check.map.${name}`;
    const f = fail.results.find((r) => r.check_id === id);
    assert.equal(f?.result, 'FAIL', id);
    assert.deepEqual([...new Set(f!.evidence.map((e) => e.file.split('/')[0]))].sort(), stacks.slice().sort(), `${id}: stacks flagged`);
    for (const e of f!.evidence) assert.ok(e.line && e.line >= 1 && e.note.length > 10, JSON.stringify(e));
    const p = pass.results.find((r) => r.check_id === id);
    assert.equal(p?.result, 'NOT ASSESSED: NEEDS DYNAMIC TEST', `${id}: pass copy ${JSON.stringify(p?.evidence)}`);
  }
});

test('codemap.json of the second wave fixtures matches its schema and two builds give the same bytes', () => {
  for (const side of ['fail', 'pass']) {
    const dir = join(MORE, side);
    const a = stableJson(mapOf(dir));
    assert.equal(a, stableJson(mapOf(dir)));
    assert.deepEqual(validate(schema, JSON.parse(a)), []);
    assert.ok(!a.includes(ROOT), 'no absolute path');
  }
});

test('Go: protections come from group and route middleware, and a webhook check that does not stop the request is recorded as ignored', () => {
  const m = mapOf(join(MORE, 'fail'));
  const del = m.entry_points.find((e) => e.file === 'go/main.go' && e.method === 'DELETE')!;
  assert.ok(has(del, 'session_read'), JSON.stringify(del.protections));
  const hook = m.entry_points.find((e) => e.file === 'go/main.go' && e.kind === 'webhook')!;
  assert.deepEqual(hook.protections.filter((p) => p.kind === 'signature_verify').map((p) => p.enforced), [false]);
  const login = m.entry_points.find((e) => e.path === '/api/login' && e.file === 'go/main.go')!;
  assert.ok(login.tags.includes('auth_endpoint') && !has(login, 'rate_limit'));
  const p = mapOf(join(MORE, 'pass'));
  const adm = p.entry_points.find((e) => e.file === 'go/main.go' && e.path === '/api/admin/users/role')!;
  assert.ok(has(adm, 'role_check', 'router') && has(adm, 'session_read'), JSON.stringify(adm.protections));
  assert.ok(has(p.entry_points.find((e) => e.file === 'go/main.go' && e.path === '/api/login')!, 'rate_limit'));
});

test('Go: net/http patterns with a method, echo, fiber, gorilla/mux and a chi router mounted from a function', () => {
  const dir = project({
    'go.mod': 'module example.com/x\n\ngo 1.22\n\nrequire (\n\tgithub.com/labstack/echo/v4 v4.11.0\n\tgithub.com/gofiber/fiber/v2 v2.52.0\n\tgithub.com/gorilla/mux v1.8.1\n\tgithub.com/go-chi/chi/v5 v5.0.12\n)\n',
    'std.go': 'package main\n\nimport "net/http"\n\nfunc routes() {\n\tmux := http.NewServeMux()\n\tmux.HandleFunc("GET /things/{id}", showThing)\n\tmux.HandleFunc("POST /things", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })\n\tmux.Handle("/health", http.HandlerFunc(health))\n}\n\nfunc showThing(w http.ResponseWriter, r *http.Request) {}\nfunc health(w http.ResponseWriter, r *http.Request) {}\n',
    'echo.go': 'package main\n\nimport "github.com/labstack/echo/v4"\n\nfunc setup() {\n\te := echo.New()\n\tg := e.Group("/v1", requireAuth)\n\tg.POST("/orders", createOrder, auditMW)\n\te.GET("/open", listOpen)\n}\n\nfunc requireAuth(next echo.HandlerFunc) echo.HandlerFunc { return next }\nfunc auditMW(next echo.HandlerFunc) echo.HandlerFunc { return next }\nfunc createOrder(c echo.Context) error { return nil }\nfunc listOpen(c echo.Context) error { return nil }\n',
    'fiber.go': 'package main\n\nimport "github.com/gofiber/fiber/v2"\n\nfunc fiberRoutes(app *fiber.App) {\n\tapp.Use("/secure", AuthMiddleware())\n\tapp.Get("/secure/me", me)\n\tapp.Post("/public/ping", ping)\n}\n\nfunc AuthMiddleware() fiber.Handler { return func(c *fiber.Ctx) error { return c.Next() } }\nfunc me(c *fiber.Ctx) error { return nil }\nfunc ping(c *fiber.Ctx) error { return nil }\n',
    'gorilla.go': 'package main\n\nimport "github.com/gorilla/mux"\n\nfunc gorilla() {\n\tr := mux.NewRouter()\n\tapi := r.PathPrefix("/api").Subrouter()\n\tapi.HandleFunc("/ping", ping2).Methods("POST")\n}\n\nfunc ping2(w http.ResponseWriter, r *http.Request) {}\n',
    'mount.go': 'package main\n\nimport "github.com/go-chi/chi/v5"\n\nfunc root() {\n\tr := chi.NewRouter()\n\tr.Mount("/admin", adminRouter())\n}\n\nfunc adminRouter() chi.Router {\n\tr := chi.NewRouter()\n\tr.Use(AdminOnly)\n\tr.Get("/stats", stats)\n\treturn r\n}\n\nfunc AdminOnly(next http.Handler) http.Handler { return next }\nfunc stats(w http.ResponseWriter, r *http.Request) {}\n',
  });
  const m = mapOf(dir);
  const sigs = sig(m, '').concat();
  void sigs;
  const all = m.entry_points.map((e) => `${e.framework} ${e.method} ${e.path}`).sort();
  assert.ok(all.includes('net-http GET /things/:id'), all.join('\n'));
  assert.ok(all.includes('net-http POST /things'));
  assert.ok(all.includes('net-http ANY /health'));
  assert.ok(all.includes('echo POST /v1/orders'));
  assert.ok(all.includes('echo GET /open'));
  assert.ok(all.includes('fiber GET /secure/me'));
  assert.ok(all.includes('fiber POST /public/ping'));
  assert.ok(all.includes('gorilla-mux POST /api/ping'));
  assert.ok(all.includes('chi GET /admin/stats'), 'a mounted router is read at its mount prefix');
  assert.equal(all.filter((x) => x.endsWith('/stats')).length, 1, 'the mounted function is not read twice');
  assert.ok(has(find(m, 'POST', '/v1/orders'), 'session_read'), 'group middleware reaches the echo route');
  assert.ok(!has(find(m, 'GET', '/open'), 'session_read'));
  assert.ok(has(find(m, 'GET', '/secure/me'), 'session_read'), 'a path scoped fiber middleware reaches routes under the path');
  assert.ok(!has(find(m, 'POST', '/public/ping'), 'session_read'));
  assert.ok(has(find(m, 'GET', '/admin/stats'), 'role_check'), 'the mounted router carries its own middleware');
});

test('Rails: filters are inherited, skipped by action and read from concerns; resources expand to their actions', () => {
  const dir = project({
    'Gemfile': "gem 'rails'\n",
    'config/application.rb': 'module X\n  class Application < Rails::Application\n  end\nend\n',
    'config/routes.rb': "Rails.application.routes.draw do\n  root 'pages#home'\n  resources :posts, only: %i[index show create] do\n    resources :comments, only: [:create]\n    member do\n      post :publish\n    end\n  end\n  authenticate :user do\n    get '/dash', to: 'dashboard#show'\n  end\n  namespace :api do\n    get 'ping', to: 'health#ping'\n  end\nend\n",
    'app/controllers/application_controller.rb': 'class ApplicationController < ActionController::Base\n  include Authentication\nend\n',
    'app/controllers/concerns/authentication.rb': 'module Authentication\n  extend ActiveSupport::Concern\n\n  included do\n    before_action :require_authentication\n  end\n\n  class_methods do\n    def allow_unauthenticated_access(**options)\n      skip_before_action :require_authentication, **options\n    end\n  end\n\n  private\n\n  def require_authentication\n    redirect_to new_session_path unless Current.session\n  end\nend\n',
    'app/controllers/pages_controller.rb': 'class PagesController < ApplicationController\n  allow_unauthenticated_access only: :home\n\n  def home\n    render plain: "hi"\n  end\nend\n',
    'app/controllers/posts_controller.rb': 'class PostsController < ApplicationController\n  allow_unauthenticated_access only: %i[index show]\n  before_action :require_admin, only: :publish\n\n  def index\n    @posts = Post.all\n  end\n\n  def show\n    @post = Post.find(params[:id])\n  end\n\n  def create\n    @post = Post.create(post_params)\n  end\n\n  def publish\n    Post.find(params[:id]).update(published: true)\n  end\n\n  private\n\n  def post_params\n    params.require(:post).permit(:title, :role)\n  end\n\n  def require_admin\n    head :forbidden unless Current.user.admin?\n  end\nend\n',
    'app/controllers/comments_controller.rb': 'class CommentsController < ApplicationController\n  def create\n    Comment.create(body: params[:body])\n  end\nend\n',
    'app/controllers/dashboard_controller.rb': 'class DashboardController < ApplicationController\n  skip_before_action :require_authentication\n\n  def show\n    render plain: "dash"\n  end\nend\n',
    'app/controllers/api/health_controller.rb': 'class Api::HealthController < ApplicationController\n  allow_unauthenticated_access\n\n  def ping\n    render json: { ok: true }\n  end\nend\n',
  });
  const m = mapOf(dir);
  const all = m.entry_points.map((e) => `${e.method} ${e.path}`).sort();
  assert.deepEqual(all, ['GET /', 'GET /api/ping', 'GET /dash', 'GET /posts', 'GET /posts/:id', 'POST /posts', 'POST /posts/:id/publish', 'POST /posts/:post_id/comments']);
  assert.ok(!has(find(m, 'GET', '/'), 'session_read'), 'allow_unauthenticated_access only: :home');
  assert.ok(!has(find(m, 'GET', '/posts'), 'session_read') && !has(find(m, 'GET', '/posts/:id'), 'session_read'));
  const create = find(m, 'POST', '/posts');
  assert.ok(has(create, 'session_read', 'router'), 'the concern filter reaches the create action');
  assert.deepEqual(create.data.find((d) => d.op === 'write')!.sets, ['role'], 'a privileged column in the permit list is reported');
  const publish = find(m, 'POST', '/posts/:id/publish');
  assert.ok(has(publish, 'role_check'), 'before_action :require_admin resolved through its definition');
  assert.ok(has(find(m, 'POST', '/posts/:post_id/comments'), 'session_read'));
  const dash = find(m, 'GET', '/dash');
  assert.ok(dash.protections.some((p) => p.kind === 'session_read' && p.scope === 'router' && p.via === 'route authenticate block'), 'the devise authenticate block counts even when the controller skips its own filter');
  assert.ok(!has(find(m, 'GET', '/api/ping'), 'session_read'));
});

test('Laravel: groups, prefix, controller middleware with only and except, resources, invokable and closure routes', () => {
  const dir = project({
    'composer.json': '{"require":{"laravel/framework":"^11.0"}}\n',
    'routes/api.php': "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\PostController;\nuse App\\Http\\Controllers\\HookController;\nuse App\\Http\\Controllers\\Admin\\StatsController;\n\nRoute::get('/ping', fn () => 'pong');\nRoute::apiResource('posts', PostController::class)->only(['index', 'store', 'destroy']);\nRoute::prefix('v1')->middleware(['auth:sanctum', 'throttle:60,1'])->group(function () {\n    Route::post('/hooks/stripe', HookController::class);\n    Route::controller(StatsController::class)->group(function () {\n        Route::get('/stats', 'index');\n    });\n});\n",
    'bootstrap/app.php': "<?php\n\nreturn Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function ($middleware) {\n        $middleware->throttleApi();\n    });\n",
    'app/Models/Post.php': '<?php\n\nnamespace App\\Models;\n\nuse Illuminate\\Database\\Eloquent\\Model;\n\nclass Post extends Model\n{\n}\n',
    'app/Http/Controllers/PostController.php': "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n\nclass PostController extends Controller\n{\n    public function __construct()\n    {\n        $this->middleware('auth')->except(['index']);\n    }\n\n    public function index()\n    {\n        return Post::all();\n    }\n\n    public function store(Request $request)\n    {\n        return Post::create($request->all());\n    }\n\n    public function destroy(Post $post)\n    {\n        $post->delete();\n    }\n}\n",
    'app/Http/Controllers/HookController.php': "<?php\n\nnamespace App\\Http\\Controllers;\n\nuse Illuminate\\Http\\Request;\n\nclass HookController extends Controller\n{\n    public function __invoke(Request $request)\n    {\n        return response()->noContent();\n    }\n}\n",
    'app/Http/Controllers/Admin/StatsController.php': "<?php\n\nnamespace App\\Http\\Controllers\\Admin;\n\nuse App\\Http\\Controllers\\Controller;\n\nclass StatsController extends Controller\n{\n    public function index()\n    {\n        return [];\n    }\n}\n",
  });
  const m = mapOf(dir);
  const all = m.entry_points.map((e) => `${e.method} ${e.path}`).sort();
  assert.deepEqual(all, ['DELETE /api/posts/:post', 'GET /api/ping', 'GET /api/posts', 'GET /api/v1/stats', 'POST /api/posts', 'POST /api/v1/hooks/stripe']);
  assert.ok(!has(find(m, 'GET', '/api/ping'), 'session_read'));
  assert.ok(!has(find(m, 'GET', '/api/posts'), 'session_read'), 'except([index]) leaves the list public');
  assert.ok(has(find(m, 'POST', '/api/posts'), 'session_read'), 'constructor middleware reaches store');
  assert.ok(has(find(m, 'POST', '/api/v1/hooks/stripe'), 'session_read'), 'the group middleware array reaches the invokable controller');
  assert.ok(has(find(m, 'GET', '/api/v1/stats'), 'session_read'), 'controller() groups keep the outer middleware');
  assert.ok(has(find(m, 'POST', '/api/posts'), 'rate_limit'), 'the api throttle group from bootstrap/app.php');
  assert.ok(!has(find(m, 'GET', '/api/ping'), 'rate_limit') === false, 'the api throttle group covers every route in api.php');
  const del = find(m, 'DELETE', '/api/posts/:post');
  assert.ok(del.data.some((d) => d.op === 'delete' && d.by_id && !d.owner_scoped), 'a bound model is a record loaded by the id in the URL');
  assert.ok(find(m, 'POST', '/api/posts').data.some((d) => d.mass_assign));
});

test('Expo: layout guards cover the screens under them, the public group stays open, API routes and deep links are entry points', () => {
  const m = mapOf(join(MORE, 'pass'));
  const screens = m.entry_points.filter((e) => e.file.startsWith('expo/') && e.kind === 'page');
  const guarded = screens.filter((e) => e.protections.some((p) => p.via === 'expo layout guard (client side)'));
  assert.deepEqual(guarded.map((e) => e.path).sort(), ['/account', '/notes/:id']);
  assert.ok(screens.find((e) => e.path === '/sign-in')!.tags.includes('public'));
  const f = mapOf(join(MORE, 'fail'));
  assert.equal(f.entry_points.filter((e) => e.file.startsWith('expo/') && e.protections.some((p) => p.kind === 'session_read')).length, 0, 'a layout that reads the session but never redirects is not a guard');
  const links = f.entry_points.filter((e) => e.kind === 'deep_link' && e.framework === 'expo').map((e) => e.path).sort();
  assert.deepEqual(links, ['https://notes.example.com/', 'https://notes.example.com/n', 'notesapp://'], 'scheme, universal link and Android app link from app.json');
  assert.ok(f.entry_points.some((e) => e.kind === 'deep_link' && e.framework === 'react-native'), 'Linking.addEventListener url');
  const note = f.entry_points.find((e) => e.path === '/notes/:id')!;
  assert.ok(note.data.some((d) => d.store === 'supabase' && d.by_id), 'a screen that queries Supabase by the id in the route');
});

test('local auth helpers: names in .hullproof/kit.local.json count as a session read, and unrecognised names are listed', () => {
  const files = {
    'package.json': '{"name":"x","dependencies":{"express":"^4.0.0"}}\n',
    'server.js': "const express = require('express');\nconst app = express();\napp.post('/api/things', (req, res) => {\n  const who = requireMember(req);\n  res.json({ who });\n});\napp.post('/api/other', (req, res) => {\n  requireMember(req);\n  res.json({});\n});\n",
    'lib/members.js': "exports.requireMember = (req) => req.headers['x-member'];\n",
  };
  const before = mapOf(project(files));
  assert.ok(!find(before, 'POST', '/api/things').protections.some((p) => p.kind === 'session_read' && p.confidence !== 'low'));
  assert.ok(before.config.auth_helper_candidates.some((c) => c.name === 'requireMember' && c.entry_points === 2), JSON.stringify(before.config.auth_helper_candidates));
  const dir = project({ ...files, '.hullproof/kit.local.json': '{"auth_helpers":["requireMember","not a name!","x"],"role_helpers":[]}\n' });
  const after = mapOf(dir);
  assert.deepEqual(after.config.local_vocab, { auth_helpers: ['requireMember', 'x'], role_helpers: [] });
  for (const p of ['/api/things', '/api/other']) {
    const e = find(after, 'POST', p);
    assert.ok(e.protections.some((x) => x.kind === 'session_read' && x.via === 'local auth helper' && x.confidence === 'medium'), JSON.stringify(e.protections));
  }
  assert.deepEqual(after.config.auth_helper_candidates, []);
  assert.equal(stableJson(after), stableJson(mapOf(dir)));
});

test('local auth helpers work in Go, Ruby and PHP too', () => {
  const dir = project({
    '.hullproof/kit.local.json': '{"auth_helpers":["MemberOnly","require_member","ensureMember"]}\n',
    'go.mod': 'module x\n\nrequire github.com/go-chi/chi/v5 v5.0.0\n',
    'main.go': 'package main\n\nimport "github.com/go-chi/chi/v5"\n\nfunc main() {\n\tr := chi.NewRouter()\n\tr.With(MemberOnly).Post("/g", gh)\n}\n\nfunc MemberOnly(next http.Handler) http.Handler { return next }\nfunc gh(w http.ResponseWriter, r *http.Request) {}\n',
    'Gemfile': "gem 'rails'\n",
    'config/application.rb': 'class Application < Rails::Application\nend\n',
    'config/routes.rb': "Rails.application.routes.draw do\n  post '/r', to: 'things#create'\nend\n",
    'app/controllers/things_controller.rb': 'class ThingsController < ActionController::Base\n  before_action :require_member\n\n  def create\n    Thing.create(name: params[:name])\n  end\nend\n',
    'composer.json': '{"require":{"laravel/framework":"^11.0"}}\n',
    'routes/web.php': "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/p', function () {\n    ensureMember();\n    return 'ok';\n});\n",
  });
  const m = mapOf(dir);
  for (const [method, path] of [['POST', '/g'], ['POST', '/r'], ['POST', '/p']] as const) {
    const e = find(m, method, path);
    assert.ok(e.protections.some((x) => x.kind === 'session_read' && x.via === 'local auth helper'), `${path}: ${JSON.stringify(e.protections)}`);
  }
});

test('a Go, Ruby or PHP repository with no framework this extractor reads is partly mapped, never clean', () => {
  const dir = project({ 'Gemfile': "gem 'sinatra'\n", 'app.rb': "require 'sinatra'\nget '/x' do\n  'ok'\nend\n" });
  const m = mapOf(dir);
  const ruby = m.coverage.find((c) => c.language === 'ruby')!;
  assert.equal(ruby.status, 'partial');
  assert.match(ruby.note, /sinatra/);
  assert.equal(m.counts.entry_points, 0);
});

test('Rails: a filter name that ends in ! counts, a set_x filter loads the record the action changes, and option lists are not read as filters', () => {
  const dir = project({
    'Gemfile': "gem 'rails'\n",
    'config/application.rb': 'class Application < Rails::Application\nend\n',
    'config/routes.rb': "Rails.application.routes.draw do\n  namespace :api do\n    resources :articles, only: [:index, :update, :destroy]\n  end\n  mount Sidekiq::Web => '/sidekiq'\nend\n",
    'app/controllers/api/articles_controller.rb': "module Api\n  class ArticlesController < ApplicationController\n    before_action :authenticate_user!, except: %i[index]\n    before_action :set_article, only: %i[update destroy]\n\n    def index\n      render json: Article.all\n    end\n\n    def update\n      @article.update!(article_params)\n    end\n\n    def destroy\n      @article.destroy\n    end\n\n    private\n\n    def set_article\n      @article = Article.find(params[:id])\n    end\n\n    def article_params\n      params.require(:article).permit(:title)\n    end\n  end\nend\n",
  });
  const m = mapOf(dir);
  assert.ok(!has(find(m, 'GET', '/api/articles'), 'session_read'), 'except: %i[index]');
  const del = find(m, 'DELETE', '/api/articles/:id');
  assert.ok(has(del, 'session_read', 'router'), 'authenticate_user! with the exclamation mark');
  assert.ok(del.data.some((d) => d.op === 'delete' && d.by_id && !d.owner_scoped && d.target === 'Article'), JSON.stringify(del.data));
  const upd = find(m, 'PATCH', '/api/articles/:id');
  assert.ok(!upd.protections.some((p) => /helper:update/.test(p.via)), 'the words in only: are not looked up as helpers');
  const mount = m.entry_points.find((e) => e.framework === 'rails-mount')!;
  assert.equal(mount.path, '/sidekiq');
  assert.ok(!has(mount, 'session_read'), 'a mounted engine outside an authenticate block has no sign in check');
  assert.deepEqual(m.config.auth_helper_candidates, []);
});

test('Rails: an unrecognised before_action name is listed as a candidate for kit.local.json', () => {
  const dir = project({
    'Gemfile': "gem 'rails'\n",
    'config/application.rb': 'class Application < Rails::Application\nend\n',
    'config/routes.rb': "Rails.application.routes.draw do\n  resources :tasks, only: [:create]\nend\n",
    'app/controllers/tasks_controller.rb': 'class TasksController < ActionController::Base\n  before_action :ensure_team_member\n\n  def create\n    Task.create(name: params[:name])\n  end\n\n  private\n\n  def ensure_team_member\n    head :forbidden unless Team.find(params[:team]).includes?(Current.person)\n  end\nend\n',
  });
  const m = mapOf(dir);
  assert.ok(m.config.auth_helper_candidates.some((c) => c.name === 'ensure_team_member'), JSON.stringify(m.config.auth_helper_candidates));
});

test('Laravel: a table named in DB::table and a Supabase client call chain are read', () => {
  const dir = project({
    'composer.json': '{"require":{"laravel/framework":"^11.0"}}\n',
    'routes/web.php': "<?php\nuse Illuminate\\Support\\Facades\\Route;\nuse Illuminate\\Support\\Facades\\DB;\n\nRoute::delete('/comments/{comment}', function ($comment) {\n    DB::table('comments')->where('id', $comment)->delete();\n});\n",
    'package.json': '{"name":"x","dependencies":{"express":"^4.0.0"}}\n',
    'api.js': "const express = require('express');\nconst { supabase } = require('./s');\nconst app = express();\napp.get('/n', async (req, res) => {\n  const r = await supabase.from('notes')\n    .select('*')\n    .eq('id', req.query.id);\n  res.json(r);\n});\n",
  });
  const m = mapOf(dir);
  const d = find(m, 'DELETE', '/comments/:comment').data[0];
  assert.deepEqual([d.store, d.op, d.target, d.by_id], ['sql', 'delete', 'comments', true]);
  const n = find(m, 'GET', '/n').data[0];
  assert.deepEqual([n.store, n.op, n.target, n.by_id], ['supabase', 'read', 'notes', true]);
});
