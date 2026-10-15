// Regression tests for extractor bugs that real applications exposed in Phase 6c. Each case is a small inline project that reproduces the
// form the real code used. No third party code is copied.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { discover } from '../src/discover/discover.ts';
import { makeContext } from '../src/checks/context.ts';
import { getMap } from '../src/checks/map/shared.ts';
import type { CodeMap, EntryPoint } from '../src/types/index.ts';

function project(files: Record<string, string>): CodeMap {
  const dir = mkdtempSync(join(tmpdir(), 'hp-real-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  return getMap(makeContext(dir, discover(dir)));
}
const find = (m: CodeMap, method: string | null, path: string): EntryPoint => { const e = m.entry_points.find((x) => x.method === method && x.path === path); assert.ok(e, `${method} ${path} in ${m.entry_points.map((x) => `${x.method} ${x.path}`).join(', ')}`); return e; };
const kinds = (e: EntryPoint): string[] => [...new Set(e.protections.filter((p) => p.confidence !== 'low' && p.enforced !== false && ['session_read', 'role_check'].includes(p.kind)).map((p) => p.kind))].sort();

test('Laravel: a route file named api.base.php, and a long comment between two calls of one chain', () => {
  const m = project({
    'composer.json': '{"require":{"laravel/framework":"^11"}}',
    'routes/api.base.php': "<?php\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::prefix('api')\n    ->middleware('api')\n    // @lint:halstead (a flat list of route definitions, not logic to break up, and this comment is long enough to pass forty characters easily)\n    ->group(static function (): void {\n        Route::get('ping', static fn () => null);\n        Route::middleware('auth')->group(static function (): void {\n            Route::get('me', [MeController::class, 'show']);\n        });\n    });\n",
  });
  assert.deepEqual(m.entry_points.map((e) => `${e.method} ${e.path}`).sort(), ['GET /api/me', 'GET /api/ping']);
  assert.deepEqual(kinds(find(m, 'GET', '/api/me')), ['session_read']);
});

test('NestJS: a method with a generic return type, and module middleware applied with forRoutes', () => {
  const m = project({
    'package.json': '{"dependencies":{"@nestjs/core":"10"}}',
    'src/user/user.controller.ts': "import { Controller, Get, Put } from '@nestjs/common';\n@Controller()\nexport class UserController {\n  @Get('user')\n  async findMe(@User('email') email: string): Promise<IUserRO> {\n    return this.svc.find(email);\n  }\n  @Put('user')\n  async update(): Promise<void> {}\n  @Get('open')\n  async open(): Promise<string> { return 'x'; }\n}\n",
    'src/user/user.module.ts': "@Module({ controllers: [UserController] })\nexport class UserModule implements NestModule {\n  configure(consumer: MiddlewareConsumer) {\n    consumer.apply(AuthMiddleware).forRoutes({ path: 'user', method: RequestMethod.GET }, { path: 'user', method: RequestMethod.PUT });\n  }\n}\n",
  });
  assert.deepEqual(m.entry_points.map((e) => `${e.method} ${e.path}`).sort(), ['GET /open', 'GET /user', 'PUT /user']);
  assert.deepEqual(kinds(find(m, 'GET', '/user')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'PUT', '/user')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/open')), []);
});

test('NestJS: forRoutes with a method only protects that method', () => {
  const m = project({
    'package.json': '{"dependencies":{"@nestjs/core":"10"}}',
    'src/a.controller.ts': "@Controller('a')\nexport class A {\n  @Get()\n  list() {}\n  @Post()\n  make() {}\n}\n",
    'src/a.module.ts': "export class AModule {\n  configure(consumer) {\n    consumer.apply(AuthMiddleware).forRoutes({ path: 'a', method: RequestMethod.POST });\n  }\n}\n",
  });
  assert.deepEqual(kinds(find(m, 'GET', '/a')), []);
  assert.deepEqual(kinds(find(m, 'POST', '/a')), ['session_read']);
});

test('ASP.NET Core: a controller with a primary constructor and no base class is found by its [Route] and its name', () => {
  const m = project({
    'App.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>',
    'UsersController.cs': 'using Microsoft.AspNetCore.Mvc;\nnamespace App;\n\n[Route("users")]\npublic class UsersController(IMediator mediator)\n{\n    [HttpPost]\n    public async ValueTask<ObjectResult> Create([FromBody] Create.Command command) => new(await mediator.Send(command));\n\n    [HttpPost("login")]\n    public ValueTask<UserEnvelope> Login([FromBody] Login.Command command) => mediator.Send(command);\n}\n',
  });
  assert.deepEqual(m.entry_points.map((e) => `${e.method} ${e.path}`).sort(), ['POST /users', 'POST /users/login']);
});

test('Expo Router: a screen that re-exports its default, and a layout guard that compares a status string', () => {
  const m = project({
    'package.json': '{"dependencies":{"expo":"~54","expo-router":"~6"}}',
    'src/app/(app)/_layout.tsx': "import { Redirect } from 'expo-router';\nimport { useAuthStore as useAuth } from '@/auth';\nexport default function Layout() {\n  const status = useAuth.use.status();\n  if (status === 'signOut') {\n    return <Redirect href=\"/login\" />;\n  }\n  return null;\n}\n",
    'src/app/(app)/settings.tsx': "export { SettingsScreen as default } from '@/features/settings';\n",
    'src/app/login.tsx': "export { LoginScreen as default } from '@/features/login';\n",
  });
  assert.deepEqual(m.entry_points.map((e) => e.path).sort(), ['/login', '/settings']);
  assert.deepEqual(kinds(find(m, null, '/settings')), ['session_read']);
  assert.deepEqual(kinds(find(m, null, '/login')), []);
});

test('Django: a view name that exists in a model, an admin class and a views module resolves to the views module the url file imports', () => {
  const m = project({
    'requirements.txt': 'Django==5.0\n',
    'manage.py': 'import django\n',
    'app/urls.py': 'from django.urls import path\nfrom app import views\n\nurlpatterns = [\n    path("things/add/", views.add, name="add"),\n]\n',
    'app/views.py': 'from django.http import HttpResponse\n\ndef add(request):\n    return HttpResponse("ok")\n',
    'app/models.py': 'class Thing:\n    def add(self, x):\n        return x\n',
    'app/admin.py': 'class ThingAdmin:\n    def add(self, request):\n        return 1\n',
  });
  const e = m.entry_points.find((x) => x.path === '/things/add');
  assert.ok(e, JSON.stringify(m.entry_points.map((x) => [x.file, x.path])));
  assert.equal(e.file, 'app/views.py');
  assert.equal(m.entry_points.length, 1);
});

test('Rails: require_logged_in filters are a session read, moderator filters a role check, and MiniProfiler authorize is neither', () => {
  const m = project({
    'Gemfile': "gem 'rails'\n",
    'config/routes.rb': "Rails.application.routes.draw do\n  get '/things' => 'things#index'\n  post '/things/:id/approve' => 'things#approve'\n  get '/open' => 'open#index'\nend\n",
    'app/controllers/application_controller.rb': "class ApplicationController < ActionController::Base\n  before_action :mini_profiler\n  def mini_profiler\n    Rack::MiniProfiler.authorize_request if Rails.env.production?\n  end\nend\n",
    'app/controllers/things_controller.rb': "class ThingsController < ApplicationController\n  before_action :require_logged_in_user\n  before_action :require_logged_in_moderator, only: [:approve]\n  def index\n    render plain: 'x'\n  end\n  def approve\n    render plain: 'y'\n  end\nend\n",
    'app/controllers/open_controller.rb': "class OpenController < ApplicationController\n  def index\n    render plain: 'z'\n  end\nend\n",
  });
  assert.deepEqual(kinds(find(m, 'GET', '/things')), ['session_read']);
  assert.deepEqual(kinds(find(m, 'POST', '/things/:id/approve')), ['role_check', 'session_read']);
  assert.deepEqual(kinds(find(m, 'GET', '/open')), [], 'the profiler hook is not a sign in');
});

test('FastAPI: a dependency named for a superuser is a role check', () => {
  const m = project({
    'requirements.txt': 'fastapi==0.115.0\n',
    'app/main.py': 'from fastapi import APIRouter, Depends\nrouter = APIRouter()\n\n' + '@router.delete("/{user_id}", dependencies=[Depends(get_current_active_superuser)])\ndef delete_user(user_id: int, session: SessionDep, current_user: CurrentUser):\n    return {"ok": True}\n',
  });
  assert.ok(kinds(find(m, 'DELETE', '/:user_id')).includes('role_check'));
});

test('Go: a group that calls Use with a package qualified Require middleware is signed in, and Rails authenticate_user without a bang is a session read', () => {
  const go = project({
    'go.mod': 'module x\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.0\n',
    'main.go': 'package main\n\nimport "github.com/gin-gonic/gin"\n\nfunc routes(g *gin.Engine) {\n\tg.GET("/open", open)\n\tclientAuth := g.Group("")\n\t{\n\t\tclientAuth.Use(authentication.RequireClient)\n\t\tclientAuth.GET("/stream", stream)\n\t}\n}\n\nfunc open(c *gin.Context)   {}\nfunc stream(c *gin.Context) {}\n',
  });
  assert.deepEqual(kinds(find(go, 'GET', '/stream')), ['session_read']);
  assert.deepEqual(kinds(find(go, 'GET', '/open')), []);
  const rb = project({
    'Gemfile': "gem 'rails'\n",
    'config/routes.rb': "Rails.application.routes.draw do\n  post '/filters' => 'filters#update'\nend\n",
    'app/controllers/filters_controller.rb': "class FiltersController < ApplicationController\n  before_action :authenticate_user\n  def update\n    render plain: 'x'\n  end\nend\n",
  });
  assert.deepEqual(kinds(find(rb, 'POST', '/filters')), ['session_read']);
});

test('Django: a custom @authorize decorator, and Laravel: a route middleware alias ending in .auth, are session reads', () => {
  const dj = project({
    'requirements.txt': 'Django==5.0\n', 'manage.py': 'import django\n',
    'api/urls.py': 'from django.urls import path\nfrom api import views\nurlpatterns = [path("checks/", views.list_checks), path("ping/", views.ping)]\n',
    'api/views.py': 'from api.decorators import authorize\n\n@authorize\ndef list_checks(request):\n    return None\n\ndef ping(request):\n    return None\n',
  });
  assert.deepEqual(kinds(find(dj, 'ANY', '/checks')), ['session_read']);
  assert.deepEqual(kinds(find(dj, 'ANY', '/ping')), []);
  const lv = project({
    'composer.json': '{"require":{"laravel/framework":"^11"}}',
    'routes/web.php': "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('os.auth')->prefix('os')->group(function () {\n    Route::delete('song', [S3::class, 'remove']);\n});\nRoute::get('open', [S3::class, 'open']);\n",
  });
  assert.deepEqual(kinds(find(lv, 'DELETE', '/os/song')), ['session_read']);
  assert.deepEqual(kinds(find(lv, 'GET', '/open')), []);
});

test('Django: a named helper list of patterns is read where include() names it, not at the top level', () => {
  const m = project({
    'requirements.txt': 'Django==5.0\n', 'manage.py': 'import django\n',
    'api/urls.py': 'from django.urls import path, include\nfrom api import views\n\nv1 = [\n    path("checks/", views.list_checks),\n]\n\nurlpatterns = [\n    path("api/v1/", include(v1)),\n    path("api/v2/", include(v1)),\n]\n',
    'api/views.py': 'def list_checks(request):\n    return None\n',
  });
  const paths = m.entry_points.map((e) => e.path).sort();
  assert.deepEqual(paths, ['/api/v1/checks', '/api/v2/checks']);
});

test('Rails: a redirect behind a host comparison is guarded; Laravel: a middleware array with an Authenticate class protects the group', () => {
  const r = project({
    'Gemfile': "gem 'rails'\n", 'config/routes.rb': 'Rails.application.routes.draw do\n  post "/login" => "login#login"\nend\n',
    'app/controllers/login_controller.rb': 'class LoginController < ApplicationController\n  def login\n    ru = URI.parse(params[:referer])\n    if ru.host == Rails.application.domain\n      return redirect_to ru.to_s\n    end\n  end\nend\n',
  });
  assert.ok(r.entry_points.every((e) => e.outbound.filter((o) => o.kind === 'redirect').every((o) => o.guarded)));
  const l = project({
    'composer.json': '{"require":{"laravel/framework":"^11"}}',
    'routes/api.php': "<?php\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::prefix('rest')\n    ->middleware([NormalizeParams::class, AuthenticateSubsonicRequests::class])\n    ->group(static function (): void {\n        Route::post('star', StarController::class);\n    });\n",
  });
  assert.ok(l.entry_points[0].protections.some((p) => p.kind === 'session_read'));
});

test('Rails: authenticate_user that only looks the user up lets a guest through, so it is not a protection; require_logged_in_user is', () => {
  const m = project({
    'Gemfile': "gem 'rails'\n",
    'config/routes.rb': 'Rails.application.routes.draw do\n  post "/signup" => "signup#create"\n  get "/messages" => "messages#index"\nend\n',
    'app/controllers/concerns/authenticatable.rb': 'module Authenticatable\n  extend ActiveSupport::Concern\n  included do\n    before_action :authenticate_user\n  end\n\n  def authenticate_user\n    @user = User.find_by(session_token: session[:u]) if session[:u]\n  end\nend\n',
    'app/controllers/application_controller.rb': 'class ApplicationController < ActionController::Base\n  include Authenticatable\n\n  def require_logged_in_user\n    return redirect_to "/login" unless @user\n  end\nend\n',
    'app/controllers/signup_controller.rb': 'class SignupController < ApplicationController\n  def create\n    User.create!(params[:email])\n  end\nend\n',
    'app/controllers/messages_controller.rb': 'class MessagesController < ApplicationController\n  before_action :require_logged_in_user\n\n  def index\n    render json: Message.all\n  end\nend\n',
  });
  assert.deepEqual(kinds(find(m, 'POST', '/signup')), []);
  assert.deepEqual(kinds(find(m, 'GET', '/messages')), ['session_read']);
});

test('Express with Sequelize: a shorthand id inside { where: { id } } counts as a read by id from the request', () => {
  const m = project({
    'package.json': '{"dependencies":{"express":"4","sequelize":"6"}}',
    'server.js': "const express = require('express');\nconst app = express();\napp.get('/rest/basket/:id', async (req, res) => {\n  const id = req.params.id;\n  const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel }] });\n  res.json(basket);\n});\napp.listen(3000);\n",
  });
  assert.ok(find(m, 'GET', '/rest/basket/:id').data.some((d) => d.op === 'read' && d.by_id));
});
