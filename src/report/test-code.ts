// Test code: findings in test, fixture, spec, mock and example files are kept, marked as test code and reported apart.
// They never fail a requirement or reach the gate, except for requirements whose subject is test material that ships
// (TEST_ARTIFACT_IDS), where a test file is exactly the thing the requirement is about.

import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// A path is test code when a folder in it, or its file name, follows a convention the language's own tools use:
//
// | Kind | Folder names (any folder in the path, any case) | File names |
// |---|---|---|
// | any language | test, tests, __tests__, __test__, spec, specs, e2e, cypress, __mocks__, mocks, mock, fixtures, fixture, __fixtures__, testdata, test-data, test_data, testfixtures, androidtest, example, examples, sample, samples | |
// | JavaScript, TypeScript | | *.test.*, *.spec.*, *.e2e.*, *.cy.*, *.mock.*, *.fixture.*, *.fixtures.* (js, jsx, ts, tsx, mjs, cjs, mts, cts) |
// | Python | | test_*.py, *_test.py, conftest.py, tests.py |
// | Go | | *_test.go (testdata/ is Go's fixture folder, above) |
// | Java, Kotlin, Groovy, Scala | | *Test, *Tests, *IT, *Spec (.java, .kt, .groovy, .scala); src/test/ through the folder rule |
// | PHP | | *Test.php |
// | Ruby | | *_spec.rb, *_test.rb |
// | C# | | *Test.cs, *Tests.cs |
// | Dart | | *_test.dart |
//
// "testing" is not on the list: Go and Python use it for shipped helper packages. A production file that happens to sit
// in a folder named like this (an `examples/` folder that is deployed, for instance) is still marked test code; the
// report lists every such record so a person can see it.

const TEST_FOLDERS = new Set([
  'test', 'tests', '__tests__', '__test__', 'spec', 'specs', 'e2e', 'cypress', '__mocks__', 'mocks', 'mock', 'fixtures',
  'fixture', '__fixtures__', 'testdata', 'test-data', 'test_data', 'testfixtures', 'androidtest', 'example', 'examples',
  'sample', 'samples',
]);

const TEST_FILES: { re: RegExp; kind: string }[] = [
  { re: /\.(test|spec|e2e|cy|mock|fixtures?)\.[cm]?[jt]sx?$/i, kind: 'JavaScript or TypeScript test file name' },
  { re: /^(test_.*|.*_test|conftest|tests)\.py$/, kind: 'Python test file name' },
  { re: /_test\.go$/, kind: 'Go test file name' },
  { re: /(Test|Tests|IT|Spec)\.(java|kt|groovy|scala)$/, kind: 'JVM test class name' },
  { re: /Test\.php$/, kind: 'PHP test class name' },
  { re: /_(spec|test)\.rb$/, kind: 'Ruby test file name' },
  { re: /Tests?\.cs$/, kind: 'C# test class name' },
  { re: /_test\.dart$/, kind: 'Dart test file name' },
];

// Requirements about test material in the shipped product (test routes, seed scripts and sample code kept out of
// production, seed and fixture data kept out of the migration chain): a hit in a test path still fails these. The IDs
// are data in rules/test-artifact-ids.json, so each edition of the rules lists the ones it has.
const ARTIFACT_FILE = fileURLToPath(new URL('../../rules/test-artifact-ids.json', import.meta.url));
export const TEST_ARTIFACT_IDS = new Set<string>(existsSync(ARTIFACT_FILE) ? (JSON.parse(readFileSync(ARTIFACT_FILE, 'utf8')) as { sec_ids: string[] }).sec_ids : []);

// Why a repository relative POSIX path counts as test code, or null when it does not.
export function testCodeReason(file: string): string | null {
  const parts = file.split('/');
  const name = parts.pop() ?? '';
  const folder = parts.find((p) => TEST_FOLDERS.has(p.toLowerCase()));
  if (folder) return `folder ${folder}/`;
  return TEST_FILES.find((t) => t.re.test(name))?.kind ?? null;
}
