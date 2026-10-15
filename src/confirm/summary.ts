// The two lines `hullproof hunt` prints about a result.
import type { HuntResult } from '../types/index.ts';

export function summary(r: HuntResult): string[] {
  return [
    `hullproof hunt: ${r.confirmed.length} confirmed, ${r.leads.length} leads not confirmed, ${r.hallucinations.count} hallucinations dropped, ${r.malformed.count} malformed`,
    `hullproof hunt: calls ${r.calls.complete} complete, ${r.calls.incomplete} incomplete, ${r.calls.missing} not saved; tokens ${r.usage.input_tokens} in, ${r.usage.output_tokens} out (reported, not limited)`,
  ];
}
