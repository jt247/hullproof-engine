// Extractor details on small synthetic projects: NestJS, tRPC, edge functions, jobs, AI tools, Next.js pages routes and
// middleware, FastAPI routers, Flask hooks, Django REST framework, Celery.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { discover } from '../src/discover/discover.ts';
import { makeContext } from '../src/checks/context.ts';
import { getMap } from '../src/checks/map/shared.ts';
import type { CodeMap, EntryPoint } from '../src/types/index.ts';

function build(files: Record<string, string>): CodeMap {
  const dir = mkdtempSync(join(tmpdir(), 'hp-ex-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  return getMap(makeContext(dir, discover(dir)));
}
// A Python source from its lines, so that a decorator is not written as \n@name inside a string.
const py = (...lines: string[]): string => lines.join('\n') + '\n';

const find = (m: CodeMap, pred: (e: EntryPoint) => boolean): EntryPoint => { const e = m.entry_points.find(pred); assert.ok(e, JSON.stringify(m.entry_points.map((x) => [x.kind, x.method, x.path, x.name]))); return e; };
const kinds = (m: CodeMap): string[] => m.entry_points.map((e) => `${e.kind}:${e.method ?? '-'}:${e.path ?? e.name}`).sort();
const has = (e: EntryPoint, kind: string): boolean => e.protections.some((p) => p.kind === kind);

test('NestJS: resolvers, consumers, cron jobs, global guard and public marker', () => {
  const m = build({
    'package.json': '{"name":"x","dependencies":{"@nestjs/core":"^10.0.0","@nestjs/graphql":"^12.0.0"}}\n',
    'app.module.ts': "import { APP_GUARD } from '@nestjs/core';\n@Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })\nexport class AppModule {}\n",
    'users.resolver.ts': "@Resolver()\nexport class UsersResolver {\n  @Query(() => [User])\n  users() { return []; }\n  @Mutation(() => User)\n  deleteUser(@Args('id') id: string) { return this.db.query('DELETE FROM users WHERE id = $1', [id]); }\n}\n",
    'jobs.service.ts': "export class JobsService {\n  @Cron('0 3 * * *')\n  nightly() { return 1; }\n  @MessagePattern('order.created')\n  onOrder(data: any) { return data; }\n}\n",
    'health.controller.ts': "@Controller('health')\nexport class HealthController {\n  @Public()\n  @Get()\n  ping() { return 'ok'; }\n}\n",
  });
  assert.deepEqual(kinds(m), ['graphql_resolver:MUTATION:deleteUser', 'graphql_resolver:QUERY:users', 'http_route:GET:/health', 'job:-:0 3 * * *', 'message_consumer:-:order.created']);
  const del = find(m, (e) => e.name === 'deleteUser');
  assert.ok(has(del, 'session_read'), 'the global JwtAuthGuard reaches the resolver');
  assert.ok(del.data.some((d) => d.op === 'delete' && d.by_id));
  assert.ok(find(m, (e) => e.path === '/health').tags.includes('public'));
});

test('tRPC procedures: the procedure name and .input() decide the protections', () => {
  const m = build({
    'package.json': '{"name":"x","dependencies":{"@trpc/server":"^10.0.0"}}\n',
    'router.ts': "import { initTRPC } from '@trpc/server';\nconst t = initTRPC.create();\nexport const appRouter = t.router({\n  hello: publicProcedure.query(() => 'hi'),\n  rename: protectedProcedure.input(z.object({ name: z.string() })).mutation(async ({ input, ctx }) => { return ctx.db.update(input); }),\n  wipe: adminProcedure.mutation(async () => 1),\n});\n",
  });
  assert.deepEqual(kinds(m), ['rpc:MUTATION:rename', 'rpc:MUTATION:wipe', 'rpc:QUERY:hello']);
  assert.ok(has(find(m, (e) => e.name === 'rename'), 'session_read'));
  assert.ok(has(find(m, (e) => e.name === 'rename'), 'input_validation'));
  assert.ok(has(find(m, (e) => e.name === 'wipe'), 'role_check'));
  assert.ok(!has(find(m, (e) => e.name === 'hello'), 'session_read'));
});

test('Supabase edge functions: the path, and verify_jwt from config.toml', () => {
  const m = build({
    'supabase/config.toml': '[functions.open]\nverify_jwt = false\n',
    'supabase/functions/open/index.ts': "Deno.serve(async (req) => new Response('hi'));\n",
    'supabase/functions/closed/index.ts': "Deno.serve(async (req) => new Response('hi'));\n",
  });
  assert.ok(!has(find(m, (e) => e.path === '/functions/v1/open'), 'session_read'));
  assert.ok(has(find(m, (e) => e.path === '/functions/v1/closed'), 'session_read'));
});

test('jobs and AI tools in Node: cron, tools object, tool() and MCP', () => {
  const m = build({
    'package.json': '{"name":"x","dependencies":{"node-cron":"^3.0.0","ai":"^3.0.0"}}\n',
    'jobs.js': "const cron = require('node-cron');\ncron.schedule('*/5 * * * *', async () => { await sweep(); });\n",
    'tools.ts': "import { tool } from 'ai';\nexport const lookup = tool({ description: 'x', parameters: z.object({}), execute: async (args) => 1 });\nexport const tools = { send_mail: (args, ctx) => 2 };\nserver.tool('search', schema, async (args) => 3);\n",
  });
  assert.deepEqual(kinds(m), ['ai_tool:-:lookup', 'ai_tool:-:search', 'ai_tool:-:send_mail', 'job:-:*/5 * * * *']);
});

test('Next.js: pages router API methods, and middleware that checks only the prefixes it names', () => {
  const m = build({
    'package.json': '{"name":"x","dependencies":{"next":"14.0.0"}}\n',
    'pages/api/things.ts': "export default async function handler(req, res) {\n  if (req.method === 'POST') { return res.json({}); }\n  if (req.method === 'GET') { return res.json([]); }\n}\n",
    'src/middleware.ts': "import { NextResponse } from 'next/server';\nexport function middleware(req) {\n  const ok = Boolean(req.cookies.get('session')?.value);\n  if (req.nextUrl.pathname.startsWith('/admin')) {\n    if (!ok) return NextResponse.redirect(new URL('/login', req.url));\n  }\n  return NextResponse.next();\n}\nexport const config = { matcher: ['/admin/:path*', '/api/:path*'] };\n",
    'app/admin/stats/route.ts': 'export async function GET() { return Response.json({}); }\n',
    'app/api/open/route.ts': 'export async function GET() { return Response.json({}); }\n',
  });
  assert.deepEqual(m.entry_points.filter((e) => e.framework === 'next-pages').map((e) => `${e.method} ${e.path}`).sort(), ['GET /api/things', 'POST /api/things']);
  const admin = find(m, (e) => e.path === '/admin/stats');
  const open = find(m, (e) => e.path === '/api/open');
  assert.ok(admin.protections.some((p) => p.scope === 'middleware' && p.confidence === 'low'), 'the cookie check in middleware reaches /admin');
  assert.ok(!open.protections.some((p) => p.scope === 'middleware'), 'but not /api/open');
});

test('FastAPI: router prefix and dependencies, mounted from another file', () => {
  const m = build({
    'main.py': "from fastapi import FastAPI, Depends\nfrom routers import items\nfrom auth import get_current_user\napp = FastAPI()\napp.include_router(items.router, prefix='/v1', dependencies=[Depends(get_current_user)])\n",
    'routers/items.py': py("from fastapi import APIRouter", "router = APIRouter(prefix='/items')", '', "@router.get('/{item_id}')", 'def read_item(item_id: int):', "    return {'id': item_id}"),
    'auth.py': "def get_current_user():\n    return None\n",
  });
  const e = find(m, (x) => x.name === 'read_item');
  assert.equal(e.path, '/v1/items/:item_id');
  assert.ok(e.protections.some((p) => p.kind === 'session_read' && p.scope === 'router'), JSON.stringify(e.protections));
});

test('Flask: a before_request hook that rejects covers the blueprint, and add_url_rule registers a view', () => {
  const m = build({
    'app.py': py('from flask import Flask, Blueprint, request, abort', 'from flask_login import current_user', 'app = Flask(__name__)', "bp = Blueprint('api', __name__, url_prefix='/api')", '', '@bp.before_request', 'def check():', '    if not current_user.is_authenticated:', '        abort(401)', '', "@bp.route('/things', methods=['GET', 'POST'])", 'def things():', "    return 'ok'", '', 'def plain():', "    return 'x'", '', "app.add_url_rule('/plain', view_func=plain)", 'app.register_blueprint(bp)'),
  });
  assert.deepEqual(kinds(m), ['http_route:GET:/api/things', 'http_route:GET:/plain', 'http_route:POST:/api/things']);
  assert.ok(has(find(m, (e) => e.method === 'POST'), 'session_read'));
});

test('Django REST framework: router.register expands a ModelViewSet, permission_classes protects it, and the admin site is listed', () => {
  const m = build({
    'config/urls.py': "from django.contrib import admin\nfrom django.urls import include, path\nurlpatterns = [path('admin/', admin.site.urls), path('api/', include('shop.urls'))]\n",
    'shop/urls.py': "from rest_framework.routers import DefaultRouter\nfrom .views import NoteViewSet\nrouter = DefaultRouter()\nrouter.register(r'notes', NoteViewSet)\nurlpatterns = router.urls\nurlpatterns += [path('', include(router.urls))]\n",
    'shop/views.py': "from rest_framework import viewsets\nfrom rest_framework.permissions import IsAuthenticated\nclass NoteViewSet(viewsets.ModelViewSet):\n    permission_classes = [IsAuthenticated]\n    serializer_class = NoteSerializer\n    def list(self, request):\n        return Response([])\n",
  });
  const list = find(m, (e) => e.name === 'NoteViewSet.list');
  assert.equal(list.path, '/api/notes');
  assert.ok(has(list, 'session_read'));
  assert.ok(m.entry_points.some((e) => e.framework === 'django-admin'));
  assert.ok(m.entry_points.some((e) => e.name === 'NoteViewSet.destroy' && e.path === '/api/notes/:pk'), 'implied methods of a ModelViewSet');
});

test('Celery tasks and Python AI tools', () => {
  const m = build({
    'tasks.py': "from celery import shared_task\n\n@shared_task\ndef send_digest(user_id):\n    return 1\n",
    'tools.py': "from langchain.tools import tool\n\n@tool\ndef lookup(order_id: str):\n    \"\"\"Look up an order.\"\"\"\n    return db.execute('SELECT * FROM orders WHERE id = ?', (order_id,))\n",
  });
  assert.deepEqual(kinds(m), ['ai_tool:-:lookup', 'job:-:send_digest']);
  assert.ok(find(m, (e) => e.name === 'lookup').data.some((d) => d.by_id && !d.owner_scoped));
});
