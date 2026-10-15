// Where the tests find a Hullproof kit: HULLPROOF_KIT, else a folder called hullproof-free/kit next to this repository.
// The kit is never copied into this repository. A test that needs it is skipped when no kit holds a controls file.
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SIBLING = fileURLToPath(new URL('../../../hullproof-free/kit/', import.meta.url));
const CONTROLS = 'docs/hullproof/security-controls.json';

export const KIT: string = resolve(process.env.HULLPROOF_KIT ?? SIBLING);
export const KIT_SKIP: string | false = existsSync(join(KIT, CONTROLS)) ? false : 'kit not present (set HULLPROOF_KIT)';
export const KIT_CONTROLS = join(KIT, CONTROLS);

// Some tests check the engine's rules and mapping tables against the kit. A copy of the engine that carries Pro additions (its folder of Pro
// rules) passes them only with the Pro kit, which holds more requirements than the Free kit's 110. The public edition passes with either kit.
const FREE_REQUIREMENTS = 110;
const HAS_PRO_PARTS = existsSync(fileURLToPath(new URL(`../../${['rules', 'pro'].join('-')}/`, import.meta.url)));
const KIT_IS_PRO = !KIT_SKIP && (JSON.parse(readFileSync(KIT_CONTROLS, 'utf8')) as { controls: unknown[] }).controls.length > FREE_REQUIREMENTS;
export const NEEDS_PRO_KIT: string | false = HAS_PRO_PARTS && !KIT_IS_PRO ? 'this copy carries Pro parts and needs the Pro kit (set HULLPROOF_KIT to the Pro kit)' : false;
