// Spring MVC entry points (Java): @RestController and @Controller classes with @RequestMapping, @GetMapping, @PostMapping, @PutMapping,
// @DeleteMapping and @PatchMapping, joined to what protects them: method security annotations (@PreAuthorize, @Secured, @RolesAllowed),
// the Spring Security filter chain (authorizeHttpRequests and authorizeRequests rules, first matching rule wins), the default of
// requiring a sign in when the security starter is on the class path, and what the handler body does. A method security annotation
// counts as enforced only when @EnableMethodSecurity or @EnableGlobalMethodSecurity is somewhere in the project. Pattern based, like the
// other extractors; every fact carries a confidence.
import type { Gate, Protection } from '../types/index.ts';
import type { FileView } from './analyze.ts';
import { annotationBlocks, splitTop, strings, type Anno } from './cblocks.ts';
import { empty, joinPath, makeEntry, normPath, type Extracted } from './entry.ts';
import { cMethod, type FnIndex } from './light-index.ts';
import { analyzeLight, type LightDeco } from './light.ts';
import { closeOf } from './lex.ts';
import type { LocalVocab } from './local-vocab.ts';
import type { Repo } from './repo.ts';

const MAPPING_VERB: Record<string, string> = { GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT', DeleteMapping: 'DELETE', PatchMapping: 'PATCH' };
const REQUEST_SEEDS = /@(?:PathVariable|RequestParam|RequestBody|RequestHeader|CookieValue|ModelAttribute|MatrixVariable|RequestPart)\b/;
const SIMPLE_TYPES = /^(?:String|Long|Integer|int|long|UUID|Boolean|boolean|Double|double|LocalDate|BigDecimal)\b/;
const METHOD_SECURITY = /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b/;

export function springFiles(repo: Repo): string[] {
  return repo.filesOf('java').filter((f) => { const v = repo.view(f); return !!v && /@(?:Rest)?Controller\b/.test(v.masked); });
}

interface SecRule { methods: string[]; patterns: string[]; any: boolean; effect: 'permit' | 'authenticated' | 'role' | 'deny'; roles: string[]; file: string; line: number; readable: boolean }
interface SecurityInfo { rules: SecRule[]; chains: number; methodSecurity: boolean; starter: boolean; securityMatchers: boolean }

const EFFECT: [RegExp, SecRule['effect']][] = [
  [/^permitAll$|^anonymous$/, 'permit'], [/^authenticated$|^fullyAuthenticated$|^rememberMe$/, 'authenticated'],
  [/^hasRole$|^hasAnyRole$|^hasAuthority$|^hasAnyAuthority$|^access$/, 'role'], [/^denyAll$/, 'deny'],
];

function securityInfo(repo: Repo): SecurityInfo {
  const info: SecurityInfo = { rules: [], chains: 0, methodSecurity: false, starter: false, securityMatchers: false };
  for (const f of ['pom.xml', 'build.gradle', 'build.gradle.kts']) if (/spring-boot-starter-security|spring-security-web|spring-security-config/.test(repo.ctx.text(f))) info.starter = true;
  for (const file of repo.filesOf('java')) {
    const v = repo.view(file);
    if (!v) continue;
    const m = v.masked;
    if (/@EnableMethodSecurity\b|@EnableGlobalMethodSecurity\b/.test(m)) info.methodSecurity = true;
    if (!/\bSecurityFilterChain\b|\bWebSecurityConfigurerAdapter\b|\bauthorizeHttpRequests\b|\bauthorizeRequests\b/.test(m)) continue;
    if (/\bsecurityMatchers?\s*\(/.test(m)) info.securityMatchers = true;
    for (const start of [...m.matchAll(/\.\s*(?:authorizeHttpRequests|authorizeRequests)\s*\(/g)]) {
      info.chains++;
      const open = start.index! + start[0].length - 1;
      const close = closeOf(m, open);
      let end = close > 0 ? close : open;
      // authorizeRequests() with no argument is followed by a chain that runs to the end of the statement
      if (close > 0 && close === open + 2) { const semi = m.indexOf(';', close); end = semi < 0 ? m.length : semi; }
      const region = m.slice(open, end);
      const text = v.text.slice(open, end);
      for (const tok of region.matchAll(/\.\s*(requestMatchers|antMatchers|mvcMatchers|regexMatchers|anyRequest)\s*\(/g)) {
        const any = tok[1] === 'anyRequest';
        let a = tok.index! + tok[0].length - 1;
        let argsText = '';
        if (!any) { const c = closeOf(region, a); if (c < 0) continue; argsText = text.slice(a + 1, c - 1); a = c; }
        else { const c = closeOf(region, a); a = c > 0 ? c : a + 1; }
        const eff = /^\s*\.\s*(permitAll|anonymous|authenticated|fullyAuthenticated|rememberMe|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|access|denyAll)\s*\(([^)]*)\)/.exec(region.slice(a));
        if (!eff) continue;
        const effect = EFFECT.find(([re]) => re.test(eff[1]))![1];
        const lits = strings(argsText);
        const methods = [...argsText.matchAll(/\bHttpMethod\s*\.\s*([A-Z]+)/g)].map((x) => x[1]);
        const roles = strings(text.slice(a, a + eff[0].length)).map((r) => r.replace(/^ROLE_/, ''));
        const line = v.lines.at(open + tok.index!);
        info.rules.push({ methods, patterns: lits, any, effect, roles, file, line, readable: any || lits.length > 0 });
      }
    }
  }
  return info;
}

// An Ant style pattern from the filter chain against a path of the map (parameters written :name).
function antMatch(pattern: string, path: string): boolean {
  const re = pattern.replace(/[.+^$|\\()[\]]/g, '\\$&').replace(/\{[^/}]+\}/g, '[^/]+').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\u0000/g, '.*');
  const p = path.replace(/:\w+/g, 'x');
  return new RegExp(`^${re}$`).test(p) || (pattern.endsWith('/**') && p === pattern.slice(0, -3));
}

interface ParamInfo { seeds: string[]; principal: boolean }
function params(text: string): ParamInfo {
  const seeds: string[] = [];
  let principal = false;
  for (const part of splitTop(text)) {
    const name = /(\w+)\s*$/.exec(part.replace(/\s*=\s*[^,]*$/, ''))?.[1];
    if (!name) continue;
    if (/@AuthenticationPrincipal\b|\b(?:Principal|Authentication)\s+\w+$/.test(part)) { principal = true; continue; }
    const bare = part.replace(/@\w+(?:\([^)]*\))?\s*/g, '').trim();
    if (REQUEST_SEEDS.test(part) || (!/@/.test(part) && SIMPLE_TYPES.test(bare))) seeds.push(name);
  }
  return { seeds, principal };
}

const pathsOf = (a: Anno | undefined, text: string): string[] => {
  if (!a || !a.args) return [''];
  const args = text.slice(a.args.start, a.args.end);
  const named = /\b(?:value|path)\s*=\s*(\{[^}]*\}|"(?:[^"\\]|\\.)*")/.exec(args);
  const lits = named ? strings(named[1]) : /^\s*(\{[^}]*\}|"(?:[^"\\]|\\.)*")/.exec(args) ? strings(/^\s*(\{[^}]*\}|"(?:[^"\\]|\\.)*")/.exec(args)![1]) : [];
  return lits.length ? lits : [''];
};

export function extractSpring(repo: Repo, fn: FnIndex, local: LocalVocab | null): Extracted {
  const out = empty();
  const sec = securityInfo(repo);
  const gates: Gate[] = sec.rules.map((r, i) => ({
    id: `spring:${r.file}:${r.line}:${i}`, kind: 'guard', framework: 'spring', file: r.file, line: r.line,
    paths: r.any ? ['*'] : r.patterns.map((p) => p.replace(/\/?\*\*?.*$/, '') || '/'), methods: r.methods,
    protections: ruleProtections(r), confidence: sec.securityMatchers ? 'medium' : 'high',
  }));
  out.gates.push(...gates);

  const fileOf = (v: FileView): void => {
    const m = v.masked;
    for (const cls of annotationBlocks(m, 0, m.length)) {
      const names = cls.annos.map((a) => a.name);
      if (!names.some((n) => n === 'RestController' || n === 'Controller')) continue;
      const decl = /^(?:(?:public|abstract|final|static)\s+)*class\s+(\w+)[^{]*\{/.exec(m.slice(cls.declStart, cls.declStart + 400));
      if (!decl) continue;
      const className = decl[1];
      const bodyOpen = cls.declStart + decl[0].length - 1;
      const bodyClose = closeOf(m, bodyOpen);
      if (bodyClose < 0) continue;
      const classMap = cls.annos.find((a) => a.name === 'RequestMapping');
      const prefix = pathsOf(classMap, v.text)[0];
      const classDeco: LightDeco = { view: v, start: cls.start, end: cls.end, scope: 'router' };
      for (const blk of annotationBlocks(m, bodyOpen + 1, bodyClose - 1)) {
        const mappings = blk.annos.filter((a) => a.name === 'RequestMapping' || MAPPING_VERB[a.name]);
        if (!mappings.length) continue;
        const nameAt = /(\w+)\s*\(/.exec(m.slice(blk.declStart, blk.declStart + 300));
        if (!nameAt) continue;
        const at = blk.declStart + nameAt.index;
        const f = cMethod(m, at);
        if (!f) continue;
        const pr = params(f.params);
        const decos: LightDeco[] = [{ view: v, start: blk.start, end: blk.end, scope: 'wrapper' }];
        if (cls.annos.some((a) => a !== classMap)) decos.push(classDeco);
        const methodAt = blk.declStart;
        for (const a of mappings) {
          const verbs = MAPPING_VERB[a.name]
            ? [MAPPING_VERB[a.name]]
            : (() => { const mm = a.args ? /\bmethod\s*=\s*(\{[^}]*\}|[\w.]+)/.exec(v.text.slice(a.args.start, a.args.end)) : null; const vs = mm ? [...mm[1].matchAll(/\b([A-Z]{3,7})\b/g)].map((x) => x[1]).filter((x) => x !== 'RequestMethod') : []; return vs.length ? vs : ['ANY']; })();
          for (const p of pathsOf(a, v.text)) {
            const joined = joinPath(prefix, p) || '/';
            const full = joined.startsWith('/') ? joined : `/${joined}`;
            for (const verb of verbs) {
              const extra = globalProtections(sec, verb, full);
              const an = analyzeLight(v, { start: methodAt, end: f.end, seeds: pr.seeds, decorators: decos, extra, lookup: fn.find, local });
              if (!sec.methodSecurity) for (const q of an.protections) if (METHOD_SECURITY.test(lineText(v, q.line))) { q.enforced = false; q.via += ' (method security is not enabled)'; }
              out.entries.push(makeEntry(repo, {
                kind: 'http_route', framework: 'spring', file: v.file, line: v.lines.at(mappings[0].start), method: verb, path: normPath(full), name: `${className}.${nameAt[1]}`,
                confidence: 'high', handlerView: v, spec: { start: methodAt, end: f.end, seeds: pr.seeds }, analysis: an,
              }));
            }
          }
        }
      }
    }
  };
  for (const file of springFiles(repo)) { const v = repo.view(file); if (v) fileOf(v); }
  return out;
}

const lineText = (v: FileView, line: number): string => v.text.slice(v.lines.start(line), v.lines.start(line + 1));

function ruleProtections(r: SecRule): Protection[] {
  const base = { scope: 'global' as const, file: r.file, line: r.line, enforced: true, confidence: 'high' as const };
  if (r.effect === 'authenticated') return [{ ...base, kind: 'session_read', via: 'authorizeHttpRequests authenticated' }];
  if (r.effect === 'role') return [{ ...base, kind: 'session_read', via: 'authorizeHttpRequests role rule' }, { ...base, kind: 'role_check', via: `authorizeHttpRequests ${r.roles.length ? 'role ' + r.roles.join(', ') : 'role rule'}` }];
  if (r.effect === 'deny') return [{ ...base, kind: 'session_read', via: 'authorizeHttpRequests denyAll' }, { ...base, kind: 'role_check', via: 'authorizeHttpRequests denyAll' }];
  return [];
}

// What the filter chain says about one route: the first rule that matches decides. Without a chain, the security starter's default needs a
// sign in for every request.
function globalProtections(sec: SecurityInfo, method: string, path: string): Protection[] {
  const conf = sec.securityMatchers ? 'medium' : 'high';
  for (const r of sec.rules) {
    if (!r.readable) continue;
    if (r.methods.length && method !== 'ANY' && !r.methods.includes(method)) continue;
    if (!r.any && !r.patterns.some((p) => antMatch(p, path))) continue;
    return ruleProtections(r).map((q) => ({ ...q, confidence: conf }));
  }
  if (!sec.chains && sec.starter) return [{ kind: 'session_read', scope: 'global', file: 'pom.xml', line: 1, via: 'Spring Security default: every request needs a sign in', enforced: true, confidence: 'medium' }];
  return [];
}
