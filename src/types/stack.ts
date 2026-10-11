// stack.json, written by `hullproof discover`. JSON schema: schemas/stack.schema.json. Documented in docs/INTERFACES.md.

export type Confidence = 'high' | 'medium' | 'low';

export const STACK_CATEGORIES = [
  'languages', 'runtimes', 'frameworks', 'package_managers', 'data_stores', 'auth', 'payments', 'ai',
  'hosting', 'iac', 'containers', 'ci', 'mobile',
] as const;
export type StackCategory = typeof STACK_CATEGORIES[number];

// One proof that an item is present. Exactly one of line or key is set.
// line: 1 based line in file. key: a JSON key path such as "dependencies.express", or "(present)" when the file itself
// is the signal (vercel.json, Dockerfile), or "(extension)" when the file extension is the signal.
export interface Evidence {
  file: string;            // repository relative POSIX path
  line?: number;
  key?: string;
  rule: string;            // detector rule id, for example "frameworks.express.dep.npm"
  confidence: Confidence;
}

export interface StackItem {
  id: string;
  confidence: Confidence;  // the best confidence among all evidence
  evidence: Evidence[];    // at most 5, best confidence first, then file, then line
  evidence_count: number;  // all evidence found, including entries not listed
  versions?: string[];     // declared versions or ranges from manifests, as written
  file_count?: number;     // languages only: files with this language's extensions
  kind?: string;           // hosting only: "platform" or "cloud"
  clouds?: string[];       // iac only: providers found in those files
  lockfiles?: string[];    // package_managers only
  manifests?: string[];    // package_managers only
}

export interface Skipped { path: string; reason: 'gitignore' | 'dependency folder' | 'build output' | 'tool folder' | 'symlink' }
export interface Unknown { file: string; note: string }

export interface Stack {
  schema_version: '1.0.0';
  engine_version: string;
  detectors_sha256: string;       // sha256 over the sorted detector files
  commit: string | null;          // HEAD commit read from .git without running git; null when not a git repository
  confirmed_by_user: boolean;     // false until `--confirm` exists (later phase)
  files: { listed: number; scanned_for_imports: number };
  limits: { max_files: number; max_bytes_per_file: number; file_cap_reached: boolean; truncated_files: string[] };
  skipped: Skipped[];
  languages: StackItem[];
  runtimes: StackItem[];
  frameworks: StackItem[];
  package_managers: StackItem[];
  data_stores: StackItem[];
  auth: StackItem[];
  payments: StackItem[];
  ai: StackItem[];
  hosting: StackItem[];
  iac: StackItem[];
  containers: StackItem[];
  ci: StackItem[];
  mobile: StackItem[];
  unknown: Unknown[];
}
