export const db = { prepare: (sql: string) => ({ run: (..._a: unknown[]) => ({ changes: 1 }), get: (..._a: unknown[]) => null, all: (..._a: unknown[]) => [] as unknown[] }) };
