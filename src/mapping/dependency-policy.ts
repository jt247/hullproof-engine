// The dependency gate rule for OSV Scanner advisories (SEC-SUPPLY-002). Configurable. Default, set on
// 2026-10-10: CRITICAL and HIGH advisories, and any advisory past its fix deadline, fail SEC-SUPPLY-002 and hold the
// gate; MEDIUM and LOW inside their deadline are reported and do not hold the gate. The two fields for missing data
// (unknown_as, unknown_published) are an engine addition outside that decision.
//
// Severity class comes from the advisory level as in STANDARD.md "Dependency advisories": a CVSS base score
// (9.0 to 10.0 CRITICAL, 7.0 to 8.9 HIGH, 4.0 to 6.9 MEDIUM, 0.1 to 3.9 LOW), else the GHSA level word.
// Deadlines are the maximum fix times in the Standard, in calendar days, counted from the advisory's publication date.

export type SeverityClass = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface DependencyPolicy {
  fail_always: SeverityClass[];                         // these fail whatever their age
  deadline_days: Record<Exclude<SeverityClass, 'UNKNOWN'>, number>;
  unknown_as: Exclude<SeverityClass, 'UNKNOWN'>;        // class used for deadline and fail_always when the advisory has none
  unknown_published: 'fail' | 'report';                 // what to do when the advisory has no publication date
}

export const DEFAULT_POLICY: DependencyPolicy = {
  fail_always: ['CRITICAL', 'HIGH'],
  deadline_days: { CRITICAL: 7, HIGH: 30, MEDIUM: 90, LOW: 180 },
  unknown_as: 'HIGH',
  unknown_published: 'fail',
};

export function classFromScore(score: number): SeverityClass {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNKNOWN';
}

export function classFromWord(word: string | undefined): SeverityClass {
  switch ((word ?? '').toUpperCase()) {
    case 'CRITICAL': return 'CRITICAL';
    case 'HIGH': return 'HIGH';
    case 'MODERATE': case 'MEDIUM': return 'MEDIUM';
    case 'LOW': return 'LOW';
    default: return 'UNKNOWN';
  }
}

const DAY = 86_400_000;
const days = (from: string, to: string): number => Math.floor((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY);

export interface Decision { deadline_days: number; past_deadline: boolean; decision: 'fail' | 'report' }

export function decide(cls: SeverityClass, published: string | null, asOf: string, policy: DependencyPolicy = DEFAULT_POLICY): Decision {
  const eff = cls === 'UNKNOWN' ? policy.unknown_as : cls;
  const deadline_days = policy.deadline_days[eff];
  const past_deadline = published === null ? policy.unknown_published === 'fail' : days(published, asOf) > deadline_days;
  const fail = policy.fail_always.includes(eff) || past_deadline;
  return { deadline_days, past_deadline, decision: fail ? 'fail' : 'report' };
}
