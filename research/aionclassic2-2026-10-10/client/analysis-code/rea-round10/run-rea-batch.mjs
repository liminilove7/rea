import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const here = path.dirname(fileURLToPath(import.meta.url));
const studyRoot = path.resolve(here, '../../..');
const repositoryRoot = path.resolve(studyRoot, '../..');
const { values } = parseArgs({ options: {
  config: { type: 'string' }, jobs: { type: 'string' }, target: { type: 'string' },
  output: { type: 'string' }, help: { type: 'boolean', default: false },
} });
if (values.help) {
  console.log('node run-rea-batch.mjs --config ABSOLUTE_IDA_MCP_JSON --jobs ABSOLUTE_JOBS_JSON [--target ABSOLUTE_GAME_DLL] [--output NEW_ABSOLUTE_DIRECTORY]');
  process.exit(0);
}
if (!values.config || !path.isAbsolute(values.config)) throw Error('An absolute --config path is required');
if (!values.jobs || !path.isAbsolute(values.jobs)) throw Error('An absolute --jobs path is required');
const target = values.target ?? path.join(studyRoot, 'samples/Game.dll');
if (!path.isAbsolute(target)) throw Error('The target path must be absolute');
const targetSha256 = createHash('sha256').update(await readFile(target)).digest('hex');
if (targetSha256 !== '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786') {
  throw Error('The target does not match the round9 Game.dll identity');
}
const output = values.output ?? path.join(studyRoot, 'evidence/round10', 'ida-' + Date.now());
if (!path.isAbsolute(output)) throw Error('The output path must be absolute');
await mkdir(path.dirname(output), { recursive: true });
await mkdir(output); // Refuse to overwrite an existing batch.
const jobs = JSON.parse(await readFile(values.jobs, 'utf8'));
if (!Array.isArray(jobs) || !jobs.length) throw Error('The jobs file must contain a nonempty array');
const uniqueNames = new Set();
for (const job of jobs) {
  if (!job || typeof job.file !== 'string' || !/^[a-z0-9-]+$/.test(job.file) || uniqueNames.has(job.file)) throw Error('Invalid or repeated output name');
  if (typeof job.name !== 'string' || !job.arguments || typeof job.arguments !== 'object') throw Error('Invalid tool request');
  uniqueNames.add(job.file);
}
const client = new Client({ name: 'rea-aion-round10', version: '1' });
const transport = new StdioClientTransport({ command: process.execPath,
  args: [path.join(repositoryRoot, 'scripts/rea.mjs'), 'mcp'],
  env: { ...process.env, REA_IDA_MCP_CONFIG: values.config, REA_ANALYSIS_PROVIDER: 'ida' }, stderr: 'pipe' });
const stderr = [];
transport.stderr?.on('data', chunk => stderr.push(String(chunk)));
const results = [];
let failed = false;
let connected = false;
const save = (name, value) => writeFile(path.join(output, name), JSON.stringify(value, null, 2));
try {
  await client.connect(transport);
  connected = true;
  const catalog = await client.listTools();
  await save('rea-tool-catalog.json', catalog);
  const toolNames = new Set(catalog.tools.map(tool => tool.name));
  for (const job of jobs) if (!toolNames.has(job.name)) throw Error('Unadvertised tool: ' + job.name);
  const opened = await client.callTool({ name: 'open_binary', arguments: { path: target, provider_id: 'ida' } }, { timeout: 300000 });
  await save('open-session.json', opened);
  if (opened.isError) throw Error('IDA target binding failed; see open-session.json');
  for (const job of jobs) {
    const started = Date.now();
    try {
      const result = await client.callTool({ name: job.name, arguments: job.arguments }, { timeout: 300000 });
      await save(job.file + '.mcp.json', { name: job.name, arguments: job.arguments, result });
      if (result.structuredContent?.evidence) await save(job.file + '.evidence.json', result.structuredContent.evidence);
      if (result.structuredContent?.result !== undefined) await save(job.file + '.normalized.json', result.structuredContent.result);
      const row = { file: job.file, name: job.name, isError: result.isError ?? false,
        evidenceId: result.structuredContent?.evidence_id ?? null, elapsedMs: Date.now() - started };
      results.push(row);
      failed ||= row.isError;
      console.log(JSON.stringify(row));
    } catch (error) {
      failed = true;
      const row = { file: job.file, name: job.name, error: String(error), elapsedMs: Date.now() - started };
      results.push(row);
      await save(job.file + '.failure.json', row);
      console.log(JSON.stringify(row));
    }
  }
} catch (error) {
  failed = true;
  await save('batch-failure.json', { error: String(error) });
  console.error(String(error));
} finally {
  if (connected) {
    try {
      const closed = await client.callTool({ name: 'close_binary', arguments: {} }, { timeout: 300000 });
      await save('close-session.json', closed);
      failed ||= closed.isError ?? false;
    } catch (error) {
      failed = true;
      await save('close-failure.json', { error: String(error) });
    }
  }
  await client.close();
  await writeFile(path.join(output, 'rea-stderr.log'), stderr.join(''));
  await save('batch-summary.json', { target, targetSha256, results, failed, targetExecuted: false });
}
console.log(JSON.stringify({ output, calls: results.length, failed }));
if (failed) process.exitCode = 1;
