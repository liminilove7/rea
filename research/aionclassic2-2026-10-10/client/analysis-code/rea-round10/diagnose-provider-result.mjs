import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../..');
const { readIdaConfiguration } = await import(pathToFileURL(path.join(repository, 'dist/ida/IdaConfiguration.js')).href);
const { createIdaMcpConnection } = await import(pathToFileURL(path.join(repository, 'dist/ida/IdaMcpConnection.js')).href);
const { IdaSessionClient } = await import(pathToFileURL(path.join(repository, 'dist/ida/IdaSessionClient.js')).href);
const { parseExecutableHeader } = await import(pathToFileURL(path.join(repository, 'dist/domain/binaryTarget.js')).href);
const { values } = parseArgs({ options: {
  config: { type: 'string' }, target: { type: 'string' }, procedure: { type: 'string' }, output: { type: 'string' },
} });
for (const field of ['config', 'target', 'output']) {
  if (!values[field] || !path.isAbsolute(values[field])) throw Error(`${field} must be an absolute path`);
}
if (!values.procedure) throw Error('An explicit procedure is required');
const registration = readIdaConfiguration(values.config);
if (!registration.ok) throw registration.error;
const bytes = await readFile(values.target);
const sha256 = createHash('sha256').update(bytes).digest('hex');
if (sha256 !== '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786') throw Error('Unexpected Game.dll identity');
const metadata = parseExecutableHeader(bytes, process.arch);
if (!metadata.ok) throw Error(metadata.error);
await mkdir(values.output);
const connection = createIdaMcpConnection(registration.value);
const observations = [];
const recordingConnection = {
  connect: () => connection.connect(),
  serverInfo: () => connection.serverInfo(),
  close: () => connection.close(),
  call: async (name, args) => {
    try {
      const result = await connection.call(name, args);
      observations.push({ name, arguments: args, result });
      await writeFile(path.join(values.output, 'producer-observations.json'), JSON.stringify(observations, null, 2));
      return result;
    } catch (cause) {
      observations.push({ name, arguments: args, failure: String(cause) });
      await writeFile(path.join(values.output, 'producer-observations.json'), JSON.stringify(observations, null, 2));
      throw cause;
    }
  },
};
const target = { path: values.target, sha256, kind: 'executable', ...metadata.value };
const client = new IdaSessionClient(registration.value, target, recordingConnection);
const errorView = (error) => ({ name: error.name, tag: error._tag, message: error.message,
  diagnostics: error.diagnostics, cause: error.cause === undefined ? null : String(error.cause) });
let result;
let closed;
try {
  result = await client.execute('analyze_function', { procedure: values.procedure });
  await writeFile(path.join(values.output, 'execution-result.json'), JSON.stringify(
    result.ok ? result : { ok: false, error: errorView(result.error) }, null, 2));
} finally {
  closed = await client.closeWithOutcome();
}
const report = { source: 'REA production IdaSessionClient; diagnostic harness, not a CLI/MCP Evidence record',
  targetSha256: sha256, procedure: values.procedure, observations: observations.length,
  result: result.ok ? { ok: true } : { ok: false, error: errorView(result.error) },
  close: closed.ok ? { ok: true } : { ok: false, error: errorView(closed.error) },
  afterSha256: createHash('sha256').update(await readFile(values.target)).digest('hex'), targetExecuted: false };
await writeFile(path.join(values.output, 'diagnostic-summary.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report));
