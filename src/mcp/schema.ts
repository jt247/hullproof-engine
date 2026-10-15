// A small checker for the input schemas of the tools: the subset they use (object, string, integer, enum, pattern, length, range,
// required, additionalProperties false). Returns a plain sentence for the first problem, or null.
export interface Schema {
  type?: 'object' | 'string' | 'integer'; enum?: readonly string[]; pattern?: string; maxLength?: number; minimum?: number; maximum?: number;
  required?: string[]; additionalProperties?: boolean; properties?: Record<string, Schema & { description?: string }>; description?: string;
}

export function checkSchema(schema: Schema, value: unknown, path = 'arguments'): string | null {
  if (schema.enum) return typeof value === 'string' && schema.enum.includes(value) ? null : `${path} must be one of ${schema.enum.join(', ')}`;
  switch (schema.type) {
    case 'string':
      if (typeof value !== 'string') return `${path} must be a string`;
      if (schema.maxLength !== undefined && value.length > schema.maxLength) return `${path} is longer than ${schema.maxLength} characters`;
      if (schema.pattern && !new RegExp(schema.pattern).test(value)) return `${path} does not match the expected format`;
      return null;
    case 'integer':
      if (typeof value !== 'number' || !Number.isInteger(value)) return `${path} must be a whole number`;
      if (schema.minimum !== undefined && value < schema.minimum) return `${path} must be at least ${schema.minimum}`;
      if (schema.maximum !== undefined && value > schema.maximum) return `${path} must be at most ${schema.maximum}`;
      return null;
    case 'object': {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) return `${path} must be an object`;
      const obj = value as Record<string, unknown>;
      for (const r of schema.required ?? []) if (!(r in obj)) return `${path}.${r} is required`;
      for (const [k, v] of Object.entries(obj)) {
        const sub = schema.properties?.[k];
        if (!sub) { if (schema.additionalProperties === false) return `${path}.${k} is not a known argument`; continue; }
        const bad = checkSchema(sub, v, `${path}.${k}`);
        if (bad) return bad;
      }
      return null;
    }
    default: return null;
  }
}
