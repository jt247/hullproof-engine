// The escape hatch: a check written as TypeScript when no declarative op can say it. The shared shape is
// CodeCheckDefinition in src/types/check.ts; here it gets the absolute source path and run().
import type { CheckDefinition, CodeCheckDefinition } from '../types/index.ts';
import type { CheckContext } from './context.ts';
import type { OpOutcome } from './ops.ts';

export interface CodeCheck extends Omit<CodeCheckDefinition, 'module'> {
  source: string;               // absolute path of the module, hashed into machine_evidence.config_sha256
  run(ctx: CheckContext): OpOutcome;
}

export type AnyCheck = (CheckDefinition & { source: string }) | CodeCheck;
