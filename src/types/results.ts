// results.json: the per requirement result list the kit gate (hullproof-gate.mjs, loadResults) already reads.

export type RouteState = 'NEEDS DASHBOARD' | 'NEEDS BUILD' | 'NEEDS DYNAMIC TEST' | 'ASK OWNER' | 'ATTESTATION' | 'UNKNOWN';

// The result words of STANDARD.md. "PASS (static)" settles only repo authority controls; the gate enforces that.
export type ResultWord = 'FAIL' | 'PASS (static)' | 'NOT APPLICABLE' | `NOT ASSESSED: ${RouteState}`;

export interface ResultRow {
  id: string;        // SEC-XXX-000
  result: ResultWord;
  notes: string;     // NOT APPLICABLE needs a reason here; plain text, no secret values
}

// results.json is a JSON array of ResultRow sorted by id.
export type ResultsFile = ResultRow[];
