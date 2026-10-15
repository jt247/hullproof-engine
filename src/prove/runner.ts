// The runner interface of the proof sandbox. One backend is a container runtime (container.ts). The other, a plain local process
// (local.ts), is labelled unsafe and exists only for the engine's own fixtures. The prove step knows only this interface.
import type { NotProvableCode, Recipe, Spec, StepRecord } from '../types/index.ts';
import type { RunOutcome } from '../types/prove.ts';

export interface Limits { memory: string; cpus: string; pids: number; instanceMs: number; execMs: number; healthMs: number }
export const DEFAULT_LIMITS: Limits = { memory: '512m', cpus: '1', pids: 128, instanceMs: 180_000, execMs: 60_000, healthMs: 30_000 };

export interface Exec { code: number | null; stdout: string; stderr: string; timedOut: boolean }
export interface Teardown { left_behind: string[] }
export type SpecRun = { ok: true; outcome: RunOutcome; detail: string; steps: StepRecord[] } | { ok: false; reason: string };

export interface Instance {
  readonly baseUrl: string;
  exec(cmd: string[], o?: { input?: string; timeoutMs?: number }): Promise<Exec>;   // inside the sandbox, with the same limits as the app
  runSpec(spec: Spec): Promise<SpecRun>;                                              // the step executor, inside the sandbox
  stop(): Promise<Teardown>;
}
export type StartResult = { ok: true; instance: Instance } | { ok: false; code: NotProvableCode; reason: string };
export interface Prepared { start(): Promise<StartResult>; dispose(): Promise<Teardown> }
export type PrepareResult = { ok: true; prepared: Prepared } | { ok: false; code: NotProvableCode; reason: string };

export interface PrepareRequest { recipe: Recipe; copyDir: string; sourceDir: string; limits: Limits }
export interface Runner {
  readonly name: string;
  available(): Promise<{ ok: true } | { ok: false; reason: string }>;
  prepare(r: PrepareRequest): Promise<PrepareResult>;
}
