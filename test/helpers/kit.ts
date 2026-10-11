// Where the tests find a Hullproof kit: HULLPROOF_KIT, else a folder called hullproof-free/kit next to this repository.
// The kit is never copied into this repository. A test that needs it is skipped when no kit holds a controls file.
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SIBLING = fileURLToPath(new URL('../../../hullproof-free/kit/', import.meta.url));
const CONTROLS = 'docs/hullproof/security-controls.json';

export const KIT: string = resolve(process.env.HULLPROOF_KIT ?? SIBLING);
export const KIT_SKIP: string | false = existsSync(join(KIT, CONTROLS)) ? false : 'kit not present (set HULLPROOF_KIT)';
export const KIT_CONTROLS = join(KIT, CONTROLS);
