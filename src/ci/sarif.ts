// results.sarif: the fail records of the findings file as SARIF 2.1.0, for GitHub code scanning and other viewers.
// Same findings, same bytes: no clock, no absolute path, everything sorted. Only fail records are results. Observations, leads and
// routed items stay out, as they stay out of the gate.
import { cmp, stableJson } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import type { FailRecord, FindingsFile, Severity } from '../types/index.ts';
import type { Kit } from '../report/kit.ts';

export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

// GitHub reads the security-severity property as a score: above 9 critical, 7 to 8.9 high, 4 to 6.9 medium, below 4 low.
const SCORE: Record<Severity, string> = { BLOCKER: '9.8', CRITICAL: '9.1', HIGH: '7.5', MEDIUM: '5.0', LOW: '2.0' };
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { BLOCKER: 'error', CRITICAL: 'error', HIGH: 'warning', MEDIUM: 'warning', LOW: 'note' };

interface SarifLocation { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } }; message?: { text: string } }

// A repository path as a relative URI: no leading slash or dot segment, percent encoded where a URI needs it.
export const uriOf = (file: string): string => file.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/^\/+/, '').split('/').map(encodeURIComponent).join('/');

export function buildSarif(findings: FindingsFile, kit: Kit, fallbackFile: string): object {
  const fails = findings.records.filter((r): r is FailRecord => r.kind === 'fail').sort((a, b) => cmp(a.fingerprint, b.fingerprint));
  // One SARIF rule per requirement id that appears in a fail record, in id order.
  const ids = [...new Set(fails.flatMap((f) => f.sec_ids))].sort(cmp);
  const rules = ids.map((id) => {
    const c = kit.byId.get(id);
    return {
      id,
      name: id.replace(/[^A-Za-z0-9]/g, ''),
      shortDescription: { text: c?.title ?? id },
      fullDescription: { text: c ? `${c.title}. Severity ${c.severity}, ${c.authority} authority, ${c.edition} edition.` : id },
      defaultConfiguration: { level: LEVEL[c?.severity ?? 'HIGH'] },
      properties: { 'security-severity': SCORE[c?.severity ?? 'HIGH'], tags: ['security', c?.severity ?? 'HIGH'] },
    };
  });
  const ruleIndex = new Map(ids.map((id, i) => [id, i]));

  const results = fails.map((f) => {
    const primary = f.sec_ids[0];
    const ev = f.evidence.length ? f.evidence : [{ file: fallbackFile, line: 1, note: '' }];
    const locations: SarifLocation[] = ev.slice(0, 8).map((e) => ({
      physicalLocation: { artifactLocation: { uri: uriOf(e.file) }, region: { startLine: Math.max(1, e.line) } },
      ...(e.note ? { message: { text: e.note } } : {}),
    }));
    return {
      ruleId: primary,
      ruleIndex: ruleIndex.get(primary)!,
      level: LEVEL[f.severity],
      message: { text: `${f.severity}: ${f.title}. ${f.impact_statement} How to fix it: ${f.remediation.strategy}` },
      locations,
      partialFingerprints: { 'hullproofFingerprint/v1': f.fingerprint },
      properties: {
        severity: f.severity, confidence: f.confidence, requirements: f.sec_ids, tool: f.machine_evidence?.tool ?? 'unknown',
        'security-severity': SCORE[f.severity],
      },
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: { driver: { name: 'Hullproof Engine', version: ENGINE_VERSION, semanticVersion: ENGINE_VERSION, rules } },
      // Paths are relative to the repository root. The category keeps one code scanning history for the engine.
      automationDetails: { id: 'hullproof/' },
      columnKind: 'utf16CodeUnits',
      results,
    }],
  };
}

export const sarifJson = (s: object): string => stableJson(s);
