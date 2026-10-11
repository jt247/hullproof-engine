// A small JSON Schema checker for the keywords the engine's schemas use (type, const, enum, pattern, lengths, ranges,
// required, properties, additionalProperties false, items, $ref to #/$defs, oneOf). Test helper only; no dependency.
type S = Record<string, any>;

export function validate(schema: S, value: unknown, root: S = schema, path = '$'): string[] {
  if (schema.$ref) return validate(root.$defs[schema.$ref.replace('#/$defs/', '')], value, root, path);
  const errs: string[] = [];
  const t = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
  if (schema.type) {
    const types = [schema.type].flat();
    if (!types.includes(t) && !(t === 'integer' && types.includes('number'))) return [`${path}: type ${t}, want ${types.join('|')}`];
  }
  if ('const' in schema && value !== schema.const) errs.push(`${path}: want ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errs.push(`${path}: ${JSON.stringify(value)} not in enum`);
  if (schema.oneOf) {
    const ok = schema.oneOf.filter((s: S) => validate(s, value, root, path).length === 0).length;
    if (ok !== 1) errs.push(`${path}: matches ${ok} of oneOf`);
  }
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) errs.push(`${path}: does not match ${schema.pattern}`);
    if (schema.minLength !== undefined && value.length < schema.minLength) errs.push(`${path}: too short`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) errs.push(`${path}: too long`);
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errs.push(`${path}: below minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) errs.push(`${path}: above maximum`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errs.push(`${path}: too few items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errs.push(`${path}: too many items`);
    if (schema.items) value.forEach((v, i) => errs.push(...validate(schema.items, v, root, `${path}[${i}]`)));
  }
  if (t === 'object') {
    const o = value as Record<string, unknown>;
    for (const k of schema.required ?? []) if (!(k in o)) errs.push(`${path}: missing ${k}`);
    for (const [k, v] of Object.entries(o)) {
      if (schema.properties?.[k]) errs.push(...validate(schema.properties[k], v, root, `${path}.${k}`));
      else if (schema.additionalProperties === false) errs.push(`${path}: unexpected ${k}`);
    }
  }
  return errs;
}
