import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const here = path.dirname(fileURLToPath(import.meta.url));
const study = path.resolve(here, '../../..');
const repository = path.resolve(study, '../..');
const { values } = parseArgs({ options: { config: { type: 'string' }, output: { type: 'string' }, sample: { type: 'string', default: 'Game.dll' } } });
for (const key of ['config', 'output']) if (!values[key] || !path.isAbsolute(values[key])) throw Error(`${key} must be absolute`);
const sampleDigests = new Map([
  ['Game.dll', '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'],
  ['CrySystem.dll', '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061'],
  ['ScriptDLL64.dll', 'ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27'],
  ['Aion.bin', '17c8de936526f119e16c1923ba5922d3a524698f04c01562fc878424653cda1e'],
  ['CryEntitySystem.dll', 'd99a60818f27bbe7f50ebef6e4ba6026b25b6d062b60db3ad3ae0eace22f4b90'],
  ['CryPhysics.dll', '7afd2f7080d8180888d47a790acb1e5ae31533ee260c6563e18661057cf7c38f'],
]);
const expected = sampleDigests.get(values.sample);
if (!expected) throw Error('Sample must be an identity-locked case input');
const target = ['CryEntitySystem.dll', 'CryPhysics.dll'].includes(values.sample)
  ? path.join(study, 'client/programs/aion-bin64/bin64', values.sample)
  : path.join(study, 'samples', values.sample);
const digest = async () => createHash('sha256').update(await readFile(target)).digest('hex');
if (await digest() !== expected) throw Error('Unexpected case sample');
await mkdir(path.dirname(values.output), { recursive: true });
await mkdir(values.output);
const queue = path.join(values.output, 'requests');
await mkdir(queue);
const save = (file, value) => writeFile(path.join(values.output, file), JSON.stringify(value, null, 2));
const client = new Client({ name: 'rea-aion-continuous-analysis', version: '1' });
const transport = new StdioClientTransport({ command: process.execPath,
  args: [path.join(repository, 'scripts/rea.mjs'), 'mcp'],
  env: { ...process.env, REA_IDA_MCP_CONFIG: values.config, REA_ANALYSIS_PROVIDER: 'ida' }, stderr: 'pipe' });
const stderr = [];
transport.stderr?.on('data', chunk => stderr.push(String(chunk)));
const allowed = new Set(['xrefs', 'analyze_function', 'read_function_instructions', 'procedure_pseudo_code',
  'procedure_address', 'address_name', 'address_to_file_offset', 'list_procedures', 'list_strings', 'search_procedures', 'search_strings', 'binary_session']);
const seen = new Set();
const records = [];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
let connected = false;
try {
  await client.connect(transport);
  connected = true;
  const catalog = await client.listTools();
  await save('rea-tool-catalog.json', catalog);
  const available = new Set(catalog.tools.map(item => item.name));
  const opened = await client.callTool({ name: 'open_binary', arguments: { path: target, provider_id: 'ida' } }, { timeout: 300000 });
  await save('open-session.json', opened);
  if (opened.isError) throw Error('Target admission failed');
  console.log(JSON.stringify({ state: 'waiting', queue, target, targetSha256: expected }));
  while (true) {
    const files = (await readdir(queue)).filter(file => /^\d+-[a-z0-9-]+\.json$/.test(file)).sort();
    for (const file of files) {
      if (seen.has(file)) continue;
      const jobs = JSON.parse(await readFile(path.join(queue, file), 'utf8'));
      if (!Array.isArray(jobs)) throw Error('A request file must be a job array');
      for (const job of jobs) {
        if (!allowed.has(job.name) || !available.has(job.name)) throw Error('Not an admitted read-only analysis tool');
        if (!/^[a-z0-9-]+$/.test(job.file) || records.some(row => row.file === job.file)) throw Error('Repeated/invalid result filename');
        const started = Date.now();
        const result = await client.callTool({ name: job.name, arguments: job.arguments }, { timeout: 300000 });
        await save(job.file + '.mcp.json', { name: job.name, arguments: job.arguments, result });
        if (result.structuredContent?.evidence) await save(job.file + '.evidence.json', result.structuredContent.evidence);
        if (result.structuredContent?.result !== undefined) await save(job.file + '.normalized.json', result.structuredContent.result);
        const row = { file: job.file, name: job.name, requestFile: file, isError: result.isError ?? false,
          evidenceId: result.structuredContent?.evidence_id ?? null, elapsedMs: Date.now() - started };
        records.push(row);
        await save('progress.json', { target, targetSha256: expected, records, targetExecuted: false });
        console.log(JSON.stringify(row));
        // The upstream health probe can report the previous call's busy state.
        await delay(1500);
      }
      seen.add(file);
      console.log(JSON.stringify({ state: 'waiting', completedRequestFile: file, requests: records.length }));
    }
    if ((await readdir(queue)).includes('finish.json')) break;
    await delay(500);
  }
} catch (error) {
  await save('session-failure.json', { message: String(error) });
  console.error(String(error));
  process.exitCode = 1;
} finally {
  if (connected) {
    try {
      const closed = await client.callTool({ name: 'close_binary', arguments: {} }, { timeout: 300000 });
      await save('close-session.json', closed);
      if (closed.isError === true) process.exitCode = 1;
    }
    catch (error) { await save('close-failure.json', { message: String(error) }); process.exitCode = 1; }
  }
  await client.close();
  await writeFile(path.join(values.output, 'rea-stderr.log'), stderr.join(''));
  await save('session-summary.json', { target, targetSha256: expected, afterSha256: await digest(), records,
    targetExecuted: false, finished: [...seen], unexpectedExit: process.exitCode === 1 });
}
