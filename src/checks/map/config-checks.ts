// Checks that read the configuration maps: Supabase tables (grants and policies) and Firebase rules. Start as leads.
import { fileURLToPath } from 'node:url';
import type { CheckEvidence, SupabaseTable } from '../../types/index.ts';
import { PRIVILEGED } from '../../map/vocab.ts';
import type { CodeCheck } from '../types.ts';
import { mapCheck } from './shared.ts';

const source = fileURLToPath(import.meta.url);
const NATIVE_FIXTURES = { pass: 'test/fixtures/map-native/pass', fail: 'test/fixtures/map-native/fail' };
const CLIENT_ROLES = new Set(['anon', 'authenticated', 'public']);
const tables = (m: { config: { supabase: { tables: SupabaseTable[] } | null } }): SupabaseTable[] => m.config.supabase?.tables ?? [];
const alwaysTrue = (e: string | null): boolean => e !== null && /^\(?\s*true\s*\)?$/i.test(e.trim());
const WRITE_PRIVS = new Set(['insert', 'update', 'delete', 'all', 'truncate']);

export const supabaseOpenTable = mapCheck({
  id: 'check.map.supabase-open-table', sec_ids: ['SEC-DB-001', 'SEC-DB-003'], name: 'supabase-open-table', source,
  pattern: 'a table granted to anon without row level security, or with a policy for anon or public that is always true',
  none: 'the code map has no Supabase table',
  candidates: (m) => tables(m).length,
  fails: (m) => tables(m).flatMap((t): CheckEvidence[] => {
    const out: CheckEvidence[] = [];
    const anon = t.grants.filter((g) => g.role === 'anon' || g.role === 'public');
    if (t.rls_enabled !== true && anon.length) out.push({ file: t.file, line: anon[0].line, note: `${t.name} has no row level security and ${anon[0].role} holds ${[...new Set(anon.flatMap((g) => g.privileges))].join(', ')}` });
    for (const p of t.policies) {
      if (p.roles.some((r) => r === 'anon' || r === 'public') && (alwaysTrue(p.using) || (p.using === null && alwaysTrue(p.check)) || alwaysTrue(p.check))) out.push({ file: t.file, line: p.line, note: `${t.name} policy ${p.name} lets ${p.roles.join(', ')} ${p.op} with an expression that is always true` });
    }
    return out;
  }),
});

export const supabasePrivilegedColumnGrant = mapCheck({
  id: 'check.map.supabase-privileged-column-grant', sec_ids: ['SEC-DB-033'], name: 'supabase-privileged-column-grant', source,
  pattern: 'a client role holding insert or update on a table that has a role, plan, admin or similar column, without a column list that leaves it out',
  none: 'the code map has no Supabase table with a role, plan or admin column',
  candidates: (m) => tables(m).filter((t) => t.columns.some((c) => PRIVILEGED.test(c))).length,
  fails: (m) => tables(m).flatMap((t): CheckEvidence[] => {
    const priv = t.columns.filter((c) => PRIVILEGED.test(c) && !/^(?:owner_?id|org_?id|tenant_?id)$/i.test(c));
    if (!priv.length) return [];
    const lines = new Map<string, { role: string; privileges: Set<string>; columns: string[] | null; line: number }>();
    for (const g of t.grants.filter((x) => CLIENT_ROLES.has(x.role) && x.privileges.some((p) => p === 'update' || p === 'insert' || p === 'all'))) {
      const k = `${g.role}|${g.line}|${(g.columns ?? ['*']).join(',')}`;
      const cur = lines.get(k) ?? { role: g.role, privileges: new Set<string>(), columns: g.columns, line: g.line };
      for (const p of g.privileges) cur.privileges.add(p);
      lines.set(k, cur);
    }
    return [...lines.values()].flatMap((g) => {
      const reach = g.columns === null ? priv : priv.filter((c) => g.columns!.includes(c));
      return reach.length ? [{ file: t.file, line: g.line, note: `${t.name}: ${g.role} can ${[...g.privileges].sort().join(', ')} ${g.columns === null ? 'every column' : 'the listed columns'} including ${reach.join(', ')}` }] : [];
    });
  }),
});

export const supabasePolicyTrustsClaims = mapCheck({
  id: 'check.map.supabase-policy-trusts-claims', sec_ids: ['SEC-DB-006'], name: 'supabase-policy-trusts-claims', source,
  pattern: 'a policy expression that reads user_metadata or raw_user_meta_data',
  none: 'the code map has no Supabase policy',
  candidates: (m) => tables(m).reduce((n, t) => n + t.policies.length, 0),
  fails: (m) => tables(m).flatMap((t): CheckEvidence[] => t.policies.filter((p) => /user_metadata|raw_user_meta_data/i.test(`${p.using ?? ''} ${p.check ?? ''}`)).map((p) => ({ file: t.file, line: p.line, note: `${t.name} policy ${p.name} trusts user_metadata, which the signed in user can edit` }))),
});

export const firebaseAuthOnlyRule = mapCheck({
  id: 'check.map.firebase-auth-only-rule', sec_ids: ['SEC-AUTHZ-010'], name: 'firebase-auth-only-rule', source,
  pattern: 'a rule on a path with an owner wildcard whose only condition is that the caller is signed in',
  none: 'the code map has no Firebase rule on a path with an owner wildcard',
  candidates: (m) => (m.config.firebase?.rules ?? []).filter((r) => r.owner_wildcard).length,
  fails: (m) => (m.config.firebase?.rules ?? []).filter((r) => r.owner_wildcard && r.uses_auth && !r.owner_bound && !r.always_true).map((r) => ({
    file: r.file, line: r.line, note: `${r.service} ${r.path} allows ${r.ops.join(', ')} to any signed in user, not to the owner named in the path`,
  })),
});

export const mobileSecretInConfig = mapCheck({
  id: 'check.map.mobile-secret-in-config', sec_ids: ['SEC-MOBILE-001'], name: 'mobile-secret-in-config', source, fixtures: NATIVE_FIXTURES,
  pattern: 'a value written in AndroidManifest.xml, an Android strings file or an iOS Info.plist under a name that says secret, password or private key',
  none: 'the code map has no Android or iOS configuration file',
  candidates: (m) => (m.config.android?.manifests.length ?? 0) + (m.config.ios?.plists.length ?? 0),
  fails: (m) => m.config.secrets.map((x): CheckEvidence => ({ file: x.file, line: x.line, note: `${x.where}: the name ${x.key} holds a value written into the file, and this file ships inside the app` })),
});

export const CONFIG_CHECKS: CodeCheck[] = [supabaseOpenTable, supabasePrivilegedColumnGrant, supabasePolicyTrustsClaims, firebaseAuthOnlyRule, mobileSecretInConfig];
