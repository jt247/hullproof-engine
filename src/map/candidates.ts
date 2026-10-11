// Names in entry points that look like sign in helpers and that the vocabulary did not recognise. The owner reads the list
// and copies the real ones into auth_helpers in .hullproof/kit.local.json (see local-vocab.ts). Only entry points that
// change state or read data and show no session read are looked at, so a list on a repository the map already understands
// is short or empty. The list is sorted by how many entry points use the name, then by name.
import type { AuthHelperCandidate, EntryPoint } from '../types/index.ts';
import type { Repo } from './repo.ts';

const AUTHISH = /auth|login|logged|session|token|jwt|bearer|guard|protect|permission|member|tenant|signed|credential|principal|identity|viewer|whoami|current|require|ensure|verify|owner|account|user/i;
const SKIP = /^(?:console|log|logger|status|json|send|redirect|render|parse|stringify|then|catch|require|import|function|return|if|for|while|switch|await|async|new|super|print|puts|len|str|int|dict|list|set|get|post|put|patch|delete|use|map|filter|reduce|find|from|select|where|insert|update|create|emit|on|once|next|type|isinstance|self|this|params|param|query|body|request|response|req|res|ctx|c|r|w|id|name|email|password|user|users|account|accounts|session|token|userId|user_id|accountId|find_by|find_by_id|findOne|findById|first|last|all|count|exists|save|destroy|build|new_record|dispatch|useState|useEffect|useMemo|useCallback|useRef|useRouter|useParams|useSearchParams|useLocalSearchParams|useNavigation|useRoute|useContext|useQuery|useMutation|useTranslation|useForm|useWatch|useTheme|useColorScheme|useWindowDimensions)$/;
const MAX = 25;

export function authHelperCandidates(repo: Repo, entries: EntryPoint[]): AuthHelperCandidate[] {
  const seen = new Map<string, { n: number; file: string; line: number }>();
  const judged = entries.filter((e) => !e.test_code && ['http_route', 'server_action', 'graphql_resolver', 'rpc'].includes(e.kind) && e.kind !== 'webhook' && (e.tags.includes('state_changing') || e.data.length > 0)
    && !e.tags.includes('auth_endpoint') && !e.tags.includes('public') && !e.protections.some((p) => p.kind === 'session_read' && p.confidence !== 'low' && p.enforced !== false));
  for (const e of judged) {
    const file = e.handler?.file ?? e.file;
    const first = e.handler?.line ?? e.line;
    const lines = repo.ctx.text(file).split('\n').slice(Math.max(0, first - 4), Math.max(first, e.end_line));
    const names = new Set<string>();
    const ruby = /\.rb$/.test(file);
    if (ruby) {
      // Class level filters of the controller that run before this action.
      const action = e.name?.split('#')[1];
      for (const fl of repo.ctx.text(file).matchAll(/^[ \t]*(?:prepend_)?before_action\b([^\n]*)$/gm)) {
        const only = /\bonly:\s*(%i\[([^\]]*)\]|\[([^\]]*)\]|:(\w+))/.exec(fl[1]);
        const except = /\bexcept:\s*(%i\[([^\]]*)\]|\[([^\]]*)\]|:(\w+))/.exec(fl[1]);
        const list = (m: RegExpExecArray | null): string[] => (m ? (m[2] ?? m[3] ?? m[4] ?? '').split(/[\s,]+/).map((x) => x.replace(/^:/, '')).filter(Boolean) : []);
        if (action && ((only && !list(only).includes(action)) || (except && list(except).includes(action)))) continue;
        for (const n of fl[1].replace(/\b(?:only|except|if|unless)\s*:.*$/, '').matchAll(/:(\w+[?!]?)/g)) names.add(n[1]);
      }
    }
    for (const l of lines) {
      if (/^\s*(?:func|def|function|public|private|protected|class|module|before_action|prepend_before_action|skip_before_action|skip_before_filter|allow_unauthenticated_access)\b/.test(l)) continue;
      const code = l.replace(/\/\/.*$|#(?!\[).*$/, '');
      for (const m of code.matchAll(ruby ? /(?:@|->|::|\.|\b)([A-Za-z_$][\w$]*[!?]?)\s*(?:\(|\b(?=\s*$)|(?=\s*,|\s*\)))/g : /(?:@|->|::|\.|\b)([A-Za-z_$][\w$]*[!?]?)\s*(?:\(|(?=\s*,|\s*\)))/g)) names.add(m[1]);
      for (const m of code.matchAll(/:(\w+[!?]?)/g)) if (/^\s*(?:before_action|skip_before_action)/.test(code)) names.add(m[1]);
    }
    for (const n of names) {
      if (n.length < 4 || SKIP.test(n) || !AUTHISH.test(n)) continue;
      const cur = seen.get(n);
      if (cur) cur.n++; else seen.set(n, { n: 1, file: e.file, line: e.line });
    }
  }
  return [...seen.entries()].map(([name, v]) => ({ name, entry_points: v.n, file: v.file, line: v.line }))
    .sort((a, b) => b.entry_points - a.entry_points || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)).slice(0, MAX);
}
