import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

const root = 'D:/RVE/.codex/local/aion-action-20261024/rea-action-' + new Date().toISOString().replaceAll(':', '-');
await mkdir(root, { recursive: false });
const client = new Client({ name: 'rea-aion-action-20261024', version: '1' });
const transport = new StdioClientTransport({
  command: 'D:/nodejs/node.exe', args: ['D:/RVE/scripts/rea.mjs', 'mcp'],
  env: { ...process.env, REA_IDA_MCP_CONFIG: 'D:/RVE/.codex/local/aion-tw-20261019/ida-mcp.json' }, stderr: 'pipe'
});
const stderr = [];
transport.stderr?.on('data', chunk => stderr.push(String(chunk)));
const jobs = process.argv[2] ? JSON.parse(await readFile(process.argv[2], 'utf8')) : [];
const results = [];
let opened = false;
let failed = false;
try {
  await client.connect(transport);
  const catalog = await client.listTools();
  await writeFile(root + '/rea-tool-schemas.json', JSON.stringify(catalog.tools, null, 2));
  const selected = catalog.tools.filter(x => /procedure|references_to_address|instructions/.test(x.name));
  if (!jobs.length) console.log(JSON.stringify(selected.map(x => ({ name: x.name, inputSchema: x.inputSchema }))));
  const open = await client.callTool({ name: 'open_binary', arguments: { path: 'D:/RVE/.codex/local/aion-tw-20261019/samples/Game.dll', provider_id: 'ida' } }, { timeout: 300000 });
  opened = !open.isError;
  await writeFile(root + '/open-session.json', JSON.stringify(open, null, 2));
  if (!opened) throw new Error('REA open_binary failed: ' + JSON.stringify(open));
  for (const job of jobs) {
    if (!/^[a-z0-9-]+$/.test(job.file)) throw new Error('Invalid output filename');
    const started = Date.now();
    try {
      const result = await client.callTool({ name: job.name, arguments: job.arguments }, { timeout: 300000 });
      await writeFile(path.join(root, job.file + '.mcp.json'), JSON.stringify({ name: job.name, arguments: job.arguments, result }, null, 2));
      const evidence = result.structuredContent?.evidence;
      const normalized = result.structuredContent?.result;
      if (evidence) await writeFile(path.join(root, job.file + '.evidence.json'), JSON.stringify({ ok: !result.isError, data: evidence }, null, 2));
      if (normalized !== undefined) await writeFile(path.join(root, job.file + '.normalized.json'), JSON.stringify(normalized, null, 2));
      const row = { file: job.file, name: job.name, arguments: job.arguments, isError: result.isError ?? false, evidence_id: result.structuredContent?.evidence_id ?? null, elapsedMs: Date.now() - started, normalizedType: typeof normalized };
      results.push(row);
      if (jobs.length <= 50 || results.length % 25 === 0) console.log(JSON.stringify(row));
      if (result.isError) failed = true;
    } catch (error) {
      failed = true;
      const row = { file: job.file, name: job.name, arguments: job.arguments, error: String(error), elapsedMs: Date.now() - started };
      results.push(row);
      await writeFile(path.join(root, job.file + '.failure.json'), JSON.stringify(row, null, 2));
      if (jobs.length <= 50 || results.length % 25 === 0) console.log(JSON.stringify(row));
    }
  }
} finally {
  try {
    const close = await client.callTool({ name: 'close_binary', arguments: {} }, { timeout: 300000 });
    await writeFile(root + '/close-session.json', JSON.stringify(close, null, 2));
    if (close.isError) failed = true;
  } finally {
    await client.close();
    await writeFile(root + '/batch-' + (process.argv[2] ? path.basename(process.argv[2], '.json') : 'catalog') + '.json', JSON.stringify({ results, failed, targetExecuted: false }, null, 2));
    await writeFile(root + '/rea-proxy-stderr.log', stderr.join(''));
  }
}
console.log(JSON.stringify({ batchCalls: results.length, evidenceOutputs: results.filter(x => x.evidence_id).length, errorCalls: results.filter(x => x.isError || x.error).length }));
if (failed) process.exitCode = 1;

