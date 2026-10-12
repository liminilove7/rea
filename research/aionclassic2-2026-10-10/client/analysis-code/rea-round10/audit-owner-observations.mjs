import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, '../../../../..');
const study = path.resolve(here, '../../..');
const directory = path.join(study, 'evidence/round10/ida95-owner-diagnostic');
const { IdaOperationRunner } = await import(pathToFileURL(path.join(repository, 'dist/ida/IdaOperationRunner.js')).href);
const { jsonValueSchema } = await import(pathToFileURL(path.join(repository, 'dist/domain/jsonValue.js')).href);
const observed = JSON.parse(await readFile(path.join(directory, 'producer-observations.json'), 'utf8'));
let cursor = 3;
const database = observed[3].arguments.database;
const connection = { call: async (name, args) => {
  const next = observed[cursor++];
  if (next?.name !== name || JSON.stringify(next.arguments) !== JSON.stringify(args)) {
    throw Error(`Recorded producer call mismatch: ${name}`);
  }
  return next.result;
} };
const runner = new IdaOperationRunner(connection, 'modern', database);
const report = { source: 'Offline REA normalizer audit of captured real producer responses; no live analysis claim', passed: false };
try {
  const normalized = await runner.run('analyze_function', { procedure: '0x18039d860' });
  jsonValueSchema.parse({ metadata_before: observed[2].result, observations: runner.raw });
  await writeFile(path.join(directory, 'normalized-owner.json'), JSON.stringify(normalized, null, 2));
  report.passed = true;
  report.callees = normalized.callees.length;
  report.instructions = normalized.assembly.length;
  report.pseudocodeLines = normalized.pseudocode.split('\n').length;
} catch (cause) {
  report.failure = { name: cause.name, message: cause.message, issues: cause.issues ?? null };
}
report.capturedClose = observed.at(-2).result;
report.capturedInventory = observed.at(-1).result;
report.privateInputPath = observed[2].result.input_path;
await writeFile(path.join(directory, 'normalizer-audit.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report));
