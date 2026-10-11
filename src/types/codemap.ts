// codemap.json, written by `hullproof map` and by `scan`. JSON schema: schemas/codemap.schema.json. Design: docs/PHASE-2-DESIGN.md.
import type { Confidence } from './stack.ts';

export type EntryKind =
  | 'http_route' | 'webhook' | 'server_action' | 'page' | 'ai_tool' | 'job' | 'graphql_resolver' | 'rpc'
  | 'message_consumer' | 'websocket' | 'deep_link';

export type ProtectionKind = 'session_read' | 'role_check' | 'owner_filter' | 'signature_verify' | 'rate_limit' | 'input_validation' | 'audit_log';
export type Scope = 'handler' | 'wrapper' | 'router' | 'middleware' | 'global';

export interface Protection {
  kind: ProtectionKind;
  scope: Scope;
  file: string;
  line: number;
  via: string;                    // the call, decorator or name that matched
  enforced: boolean | null;       // true: a failed check stops the request; false: it carries on; null: cannot tell
  after_parse?: boolean;          // signature_verify only: the body is parsed before the signature is checked
  confidence: Confidence;
}

export type InputSource = 'body' | 'query' | 'params' | 'headers' | 'cookies' | 'form' | 'file';
export interface InputRead { source: InputSource; line: number }

export type StoreKind = 'sql' | 'prisma' | 'drizzle' | 'mongo' | 'supabase' | 'firebase' | 'redis' | 'orm' | 'filesystem' | 'object_storage';
export interface DataTouch {
  store: StoreKind;
  op: 'read' | 'write' | 'delete' | 'unknown';
  target: string | null;          // table or model name when known
  line: number;
  by_id: boolean;                 // filters on an id column with a value from the request
  limit_from_request: boolean;    // a limit or page size comes from the request
  request_derived: boolean;       // the query text or its arguments contain a request derived value
  owner_scoped: boolean;          // the where clause names an owner, user, tenant or account column and the value comes from the session
  raw_sql: boolean;
  sets: string[];                 // privileged columns (role, plan, is_admin ...) a write sets from a request value, sorted
  mass_assign: boolean;           // a whole request object goes into a create or update
  confidence: Confidence;
}

export type OutboundKind = 'http' | 'ai_model' | 'email' | 'sms' | 'payment' | 'process' | 'redirect' | 'queue';
export interface Outbound {
  kind: OutboundKind;
  line: number;
  target: string;                 // the target expression, clipped to 120 characters
  request_derived: boolean;
  guarded: boolean;               // an allowlist or host check in the same function
  confidence: Confidence;
}

export interface EntryPoint {
  id: string;
  kind: EntryKind;
  framework: string;
  file: string;
  line: number;
  end_line: number;
  method: string | null;
  path: string | null;
  name: string | null;
  handler: { file: string; line: number } | null;   // where the handler body is, when it is registered by reference
  confidence: Confidence;
  test_code: boolean;
  tags: string[];                 // sorted: admin, auth_endpoint, public, state_changing, upload, webhook
  protections: Protection[];
  reads: InputRead[];
  data: DataTouch[];
  outbound: Outbound[];
}

export interface Gate {
  id: string;
  kind: 'middleware' | 'guard' | 'router_dependency' | 'global_pipe' | 'mount';
  framework: string;
  file: string;
  line: number;
  paths: string[];                // path prefixes covered; ['*'] for everything
  methods: string[];              // [] for all
  protections: Protection[];
  confidence: Confidence;
}

export type CoverageStatus = 'mapped' | 'partial' | 'not_mapped';
export interface Coverage {
  language: string;
  files: number;
  extractor: string | null;
  status: CoverageStatus;
  entry_points: number;
  note: string;
}

export interface SupabasePolicy { name: string; op: string; roles: string[]; using: string | null; check: string | null; line: number; permissive: boolean }
export interface SupabaseGrant { role: string; privileges: string[]; columns: string[] | null; line: number }
export interface SupabaseTable {
  name: string; file: string; line: number; rls_enabled: boolean | null; columns: string[];
  policies: SupabasePolicy[]; grants: SupabaseGrant[];
}
export interface FirebaseRule {
  service: 'firestore' | 'storage' | 'realtime';
  file: string; line: number; path: string; ops: string[]; condition: string;
  uses_auth: boolean; owner_bound: boolean; always_true: boolean; owner_wildcard: boolean;
}

export interface AuthHelperCandidate { name: string; entry_points: number; file: string; line: number }
export interface LocalVocabRecord { auth_helpers: string[]; role_helpers: string[] }

export interface CodeMap {
  schema_version: '1.0.0';
  engine_version: string;
  commit: string | null;
  coverage: Coverage[];
  entry_points: EntryPoint[];
  gates: Gate[];
  config: { supabase: { tables: SupabaseTable[] } | null; firebase: { rules: FirebaseRule[] } | null; local_vocab: LocalVocabRecord; auth_helper_candidates: AuthHelperCandidate[] };
  counts: { entry_points: number; by_kind: Record<string, number>; by_framework: Record<string, number> };
}
