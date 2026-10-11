// surface.json: what the scan looked at, by kind of entry point or configuration, so the report can say what was read.
// A file level summary found with the same selectors the older checks use. The entry point inventory is in codemap.json.
import type { CheckContext } from '../checks/context.ts';
import { handlerFiles } from '../checks/code/shared.ts';

export interface SurfaceFile {
  schema_version: '1.0.0';
  files_listed: number;
  surfaces: { kind: string; count: number; files: string[] }[];
}

const MAX_LISTED = 50;

export function surface(ctx: CheckContext): SurfaceFile {
  const handlers = handlerFiles(ctx);
  const kinds: [string, string[]][] = [
    ['server request handlers', handlers],
    ['webhook handlers', handlers.filter((f) => /webhook/i.test(f))],
    ['admin handlers', handlers.filter((f) => /(^|\/)(admin|backoffice|staff)(\/|\.|$)/i.test(f))],
    ['sign in and account routes', handlers.filter((f) => /login|signin|sign-in|signup|sign-up|register|password|otp|auth/i.test(f))],
    ['AI tool and model code', ctx.select(['**/{ai,llm,agent,agents,mcp}/**/*', '**/*tool*.{ts,js,py}'])],
    ['database migrations and rules', ctx.select(['**/migrations/**/*.sql', '**/schema.sql', '**/*.rules', '**/database.rules.json'])],
    ['CI workflows', ctx.select(['.github/workflows/*.{yml,yaml}', '.gitlab-ci.yml', 'bitbucket-pipelines.yml', '.circleci/config.yml', 'azure-pipelines.yml'])],
    ['infrastructure code', ctx.select(['**/*.tf', '**/*.tf.json', '**/*.bicep', '**/template.{yml,yaml}', '**/Dockerfile*', '**/*compose*.{yml,yaml}', '**/k8s/**/*.{yml,yaml}'])],
    ['framework and platform configuration', ctx.select(['next.config.*', 'nuxt.config.*', 'vite.config.*', 'vercel.json', 'netlify.toml', 'firebase.json', 'supabase/config.toml', '**/settings.py', 'app.json', 'app.config.*'])],
  ];
  return {
    schema_version: '1.0.0',
    files_listed: ctx.files.length,
    surfaces: kinds.map(([kind, files]) => ({ kind, count: files.length, files: files.slice(0, MAX_LISTED) })),
  };
}
