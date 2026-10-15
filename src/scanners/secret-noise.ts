// Secret hits that are almost surely not a live secret: a placeholder or a published example value, or a shapeless rule
// (a generic key, a curl header, a bare JWT) matching in documentation, fixture data, an example env file, a lockfile,
// vendored or generated code, or a migration. The hit is kept and reported as an example value; it does not hold the gate.
//
// What stays held, on purpose: a rule with a vendor shape (AWS, GitHub, Stripe, a private key block and so on) anywhere
// except where its value is a placeholder, and every rule in source and config files and in test source files.

// Rules with no vendor shape: they match on a variable name or a loose pattern, so a path says more than the value does.
export const WEAK_RULES = new Set(['generic-api-key', 'curl-auth-header', 'curl-auth-user', 'jwt', 'hullproof-url-with-password']);

const FOLDERS = (s: string): Set<string> => new Set(s.split(' '));
const DOC_FOLDERS = FOLDERS('docs doc documentation api-docs apidocs');
const DOC_EXT = /\.(?:md|mdx|rst|adoc|txt|html?|ya?ml|json)$/i;
const DOC_FILE = /\.(?:md|mdx|rst|adoc)$|^(?:readme|changelog|changes|history|contributing|license|notice)(?:\.\w+)?$/i;
const FIXTURE_FOLDERS = FOLDERS('fixtures fixture __fixtures__ testdata test-data test_data testfixtures __snapshots__ cassettes');
const TEST_FOLDERS = FOLDERS('test tests __tests__ spec specs e2e cypress');
const DATA_EXT = /\.(?:json|ya?ml|txt|csv|xml|toml|snap|har|md)$/i;
const MIGRATION_FOLDERS = FOLDERS('migrations migrate alembic');
const VENDOR_FOLDERS = FOLDERS('vendor vendors third_party third-party node_modules bower_components site-packages pods plugins webjars');
const LOCKFILES = /^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|cargo\.lock|composer\.lock|poetry\.lock|pipfile\.lock|gemfile\.lock|go\.sum|packages\.lock\.json|gradle\.lockfile|mix\.lock|pubspec\.lock|podfile\.lock|flake\.lock)$/i;
const EXAMPLE_FILE = /(?:^|\/)\.env\.(?:example|sample|template|dist|tpl)$|\.(?:example|sample|template|dist|tpl)$|\.(?:example|sample|template)\.\w+$/i;
const GENERATED = /(?:\.min\.(?:js|css)|\.pb\.go|_pb2\.py|\.g\.dart|\.generated\.\w+|_generated\.\w+|\.snap)$/i;

// Why a repository relative path makes a shapeless rule's hit an example value, or null.
export function pathNoise(file: string): string | null {
  const parts = file.split('/');
  const name = parts.pop() ?? '';
  const dirs = parts.map((p) => p.toLowerCase());
  const has = (set: Set<string>): string | undefined => parts.find((p) => set.has(p.toLowerCase()));
  if (LOCKFILES.test(name)) return 'lockfile';
  if (DOC_FILE.test(name)) return 'documentation file';
  if (EXAMPLE_FILE.test(file)) return 'example or sample file';
  const doc = has(DOC_FOLDERS);
  if (doc && DOC_EXT.test(name)) return `documentation folder ${doc}/`;
  const fx = has(FIXTURE_FOLDERS);
  if (fx) return `fixture data folder ${fx}/`;
  if (/\.(?:fixtures?)\.\w+$/i.test(name)) return 'fixture file';
  const t = has(TEST_FOLDERS);
  if (t && DATA_EXT.test(name)) return `test data in ${t}/`;
  const mg = has(MIGRATION_FOLDERS) ?? (dirs.includes('db') && dirs.includes('migrate') ? 'migrate' : undefined);
  if (mg) return `migration folder ${mg}/`;
  const vd = has(VENDOR_FOLDERS);
  if (vd) return `vendored code in ${vd}/`;
  if (GENERATED.test(name) || dirs.includes('__generated__')) return 'generated file';
  return null;
}

// Values that are published examples, never a credential.
const KNOWN_EXAMPLES = [
  'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'ASIAIOSFODNN7EXAMPLE',
  // The jwt.io sample token (John Doe, iat 1516239022).
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
];
const PLACEHOLDER = /^(?:(.)\1{5,}|(?:0123456789|1234567890|12345678|abcdef|abcdefgh)[\w-]*|.*(?:example|your[-_.]|changeme|change[-_]me|placeholder|dummy|sample|redacted|fake|insert|replace|todo)[\w-]*|x{4,}[\w-]*|\*{4,})$/i;
const GUID_SEQ = /^(?:12345678-1234-1234-1234-1234567890ab|12345678-1234-1234-1234-123456789abc|00000000-0000-0000-0000-000000000000)$/i;

// The values on a line: the text inside quotes (after a "name:" or "name=" prefix if it has one), or else what follows a : or =.
// A line with no such value is never judged a placeholder, so a short real password beside a variable named EXAMPLE_PASSWORD still holds.
function valuesOf(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(/(["'`])((?:(?!\1).){4,})\1/g)) out.push(m[2].replace(/^.*?[:=]\s*(?=\S)/, (pre) => (/^[\w.-]+\s*[:=]\s*$/.test(pre) ? '' : pre)).trim());
  if (!out.length) for (const m of line.matchAll(/[:=]\s*([^\s"'`,;]{4,})/g)) out.push(m[1]);
  return out;
}

// A line holds a placeholder when it has values and every one is placeholder shaped or a known example. The secret itself is
// redacted by the scanner, so the line is the only place the value can be judged.
export function valueNoise(line: string): string | null {
  if (KNOWN_EXAMPLES.some((k) => line.includes(k))) return 'published example value';
  const vs = valuesOf(line);
  if (!vs.length) return null;
  return vs.every((v) => PLACEHOLDER.test(v) || GUID_SEQ.test(v) || /^(?:<[\w\s.-]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|\$\w+)$/.test(v)) ? 'placeholder value' : null;
}

// The reason a Gitleaks hit is an example value, or null when it must hold. `line` is the source line, or null when it is not known.
export function secretNoise(rule: string, file: string, line: string | null): string | null {
  const v = line === null ? null : valueNoise(line);
  if (v) return v;
  return WEAK_RULES.has(rule) ? pathNoise(file) : null;
}
