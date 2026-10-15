// A strict structural check of the SARIF 2.1.0 file the engine writes. The official JSON Schema of SARIF 2.1.0 is not shipped with
// the engine and was not available offline when this was written, so this checks the parts of that schema the engine uses: required
// properties, types, enum values, array minimums, the allowed property names of every object the engine writes, and the links
// between a result and its rule. It does not claim to be the whole schema. GitHub code scanning applies the real schema on upload.
const LEVELS = new Set(['none', 'note', 'warning', 'error']);
const OBJ = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

// The property names the engine may write in each object, taken from the SARIF 2.1.0 definitions of those objects.
const ALLOWED: Record<string, string[]> = {
  log: ['$schema', 'version', 'runs'],
  run: ['tool', 'results', 'automationDetails', 'columnKind'],
  driver: ['name', 'version', 'semanticVersion', 'rules', 'informationUri'],
  rule: ['id', 'name', 'shortDescription', 'fullDescription', 'defaultConfiguration', 'properties'],
  result: ['ruleId', 'ruleIndex', 'level', 'message', 'locations', 'partialFingerprints', 'properties'],
  location: ['physicalLocation', 'message'],
  physical: ['artifactLocation', 'region'],
  artifact: ['uri'],
  region: ['startLine'],
};

export function checkSarif(doc: unknown): string[] {
  const errs: string[] = [];
  const e = (path: string, why: string): void => { errs.push(`${path}: ${why}`); };
  const only = (v: Record<string, unknown>, kind: string, path: string): void => {
    for (const k of Object.keys(v)) if (!ALLOWED[kind].includes(k)) e(path, `property "${k}" is not one the engine writes`);
  };
  const text = (v: unknown, path: string): void => {
    if (!OBJ(v) || typeof v.text !== 'string' || v.text.length === 0) e(path, 'needs a non empty "text"');
  };
  if (!OBJ(doc)) return ['$: not an object'];
  only(doc, 'log', '$');
  if (doc.version !== '2.1.0') e('$.version', 'must be "2.1.0"');
  if (typeof doc.$schema !== 'string' || !doc.$schema.includes('sarif-2.1.0')) e('$.$schema', 'must name the 2.1.0 schema');
  if (!Array.isArray(doc.runs) || doc.runs.length < 1) { e('$.runs', 'needs at least one run'); return errs; }
  doc.runs.forEach((run: unknown, ri: number) => {
    const rp = `$.runs[${ri}]`;
    if (!OBJ(run)) { e(rp, 'not an object'); return; }
    only(run, 'run', rp);
    const tool = run.tool;
    if (!OBJ(tool) || !OBJ(tool.driver)) { e(`${rp}.tool.driver`, 'required'); return; }
    const d = tool.driver;
    only(d, 'driver', `${rp}.tool.driver`);
    if (typeof d.name !== 'string' || !d.name) e(`${rp}.tool.driver.name`, 'required');
    const rules = d.rules === undefined ? [] : d.rules;
    if (!Array.isArray(rules)) e(`${rp}.tool.driver.rules`, 'must be an array');
    const ruleIds: string[] = [];
    (Array.isArray(rules) ? rules : []).forEach((r: unknown, i: number) => {
      const p = `${rp}.tool.driver.rules[${i}]`;
      if (!OBJ(r)) { e(p, 'not an object'); return; }
      only(r, 'rule', p);
      if (typeof r.id !== 'string' || !r.id) e(`${p}.id`, 'required');
      else { if (ruleIds.includes(r.id)) e(`${p}.id`, 'duplicate rule id'); ruleIds.push(r.id); }
      if (r.shortDescription !== undefined) text(r.shortDescription, `${p}.shortDescription`);
      if (r.fullDescription !== undefined) text(r.fullDescription, `${p}.fullDescription`);
      if (OBJ(r.defaultConfiguration) && r.defaultConfiguration.level !== undefined && !LEVELS.has(String(r.defaultConfiguration.level))) e(`${p}.defaultConfiguration.level`, 'not a SARIF level');
      const sev = OBJ(r.properties) ? r.properties['security-severity'] : undefined;
      if (sev !== undefined && !(typeof sev === 'string' && /^\d+(\.\d+)?$/.test(sev) && Number(sev) <= 10)) e(`${p}.properties.security-severity`, 'must be a string number from 0 to 10');
    });
    if (!Array.isArray(run.results)) { e(`${rp}.results`, 'must be an array'); return; }
    run.results.forEach((res: unknown, i: number) => {
      const p = `${rp}.results[${i}]`;
      if (!OBJ(res)) { e(p, 'not an object'); return; }
      only(res, 'result', p);
      text(res.message, `${p}.message`);
      if (res.level !== undefined && !LEVELS.has(String(res.level))) e(`${p}.level`, 'not a SARIF level');
      if (typeof res.ruleId !== 'string' || !res.ruleId) e(`${p}.ruleId`, 'required');
      if (res.ruleIndex !== undefined) {
        if (!Number.isInteger(res.ruleIndex) || (res.ruleIndex as number) < 0 || (res.ruleIndex as number) >= ruleIds.length) e(`${p}.ruleIndex`, 'not an index into tool.driver.rules');
        else if (ruleIds[res.ruleIndex as number] !== res.ruleId) e(`${p}.ruleIndex`, 'points at a rule with another id');
      } else if (!ruleIds.includes(String(res.ruleId))) e(`${p}.ruleId`, 'names no rule in tool.driver.rules');
      if (!Array.isArray(res.locations) || res.locations.length < 1) e(`${p}.locations`, 'needs at least one location');
      else res.locations.forEach((l: unknown, li: number) => {
        const lp = `${p}.locations[${li}]`;
        if (!OBJ(l)) { e(lp, 'not an object'); return; }
        only(l, 'location', lp);
        if (l.message !== undefined) text(l.message, `${lp}.message`);
        const ph = l.physicalLocation;
        if (!OBJ(ph)) { e(`${lp}.physicalLocation`, 'required'); return; }
        only(ph, 'physical', `${lp}.physicalLocation`);
        const al = ph.artifactLocation;
        if (!OBJ(al)) e(`${lp}.physicalLocation.artifactLocation`, 'required');
        else {
          only(al, 'artifact', `${lp}.physicalLocation.artifactLocation`);
          const u = al.uri;
          if (typeof u !== 'string' || !u) e(`${lp}.physicalLocation.artifactLocation.uri`, 'required');
          else if (/^[a-z][a-z0-9+.-]*:|^\/|(^|\/)\.\.(\/|$)|\\/i.test(u)) e(`${lp}.physicalLocation.artifactLocation.uri`, 'must be a relative path inside the repository');
        }
        const rg = ph.region;
        if (rg !== undefined) {
          if (!OBJ(rg)) e(`${lp}.physicalLocation.region`, 'not an object');
          else { only(rg, 'region', `${lp}.physicalLocation.region`); if (!Number.isInteger(rg.startLine) || (rg.startLine as number) < 1) e(`${lp}.physicalLocation.region.startLine`, 'must be an integer of 1 or more'); }
        }
      });
      if (res.partialFingerprints !== undefined) {
        if (!OBJ(res.partialFingerprints) || Object.values(res.partialFingerprints).some((x) => typeof x !== 'string' || !x)) e(`${p}.partialFingerprints`, 'must map names to non empty strings');
      }
    });
  });
  return errs;
}
