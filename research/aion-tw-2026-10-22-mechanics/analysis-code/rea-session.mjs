// A single owned REA/IDA session. Queue files are explicit analyst requests.
// Usage: node rea-session.mjs TARGET CONFIG OUTPUT JOB_DIRECTORY
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { mkdir, readFile, writeFile, readdir, access } from "node:fs/promises";
import path from "node:path";
const [target, config, output, queue] = process.argv.slice(2);
if (!target || !config || !output || !queue) throw Error("Four paths required");
await mkdir(output, { recursive: true });
await mkdir(queue, { recursive: true });
const c = new Client({ name: "rea-mechanics-static-study", version: "1" });
const t = new StdioClientTransport({
  command: process.execPath,
  args: [path.resolve("scripts/rea.mjs"), "mcp"],
  env: {
    ...process.env,
    REA_IDA_MCP_CONFIG: config,
    REA_ANALYSIS_PROVIDER: "ida",
  },
  stderr: "pipe",
});
let errors = "";
t.stderr?.on("data", (b) => {
  errors += String(b);
});
let opened = false;
const requests = [];
try {
  await c.connect(t);
  const catalog = await c.listTools();
  await writeFile(
    path.join(output, "tool-catalog.json"),
    JSON.stringify(catalog, null, 2),
  );
  const r = await c.callTool(
    { name: "open_binary", arguments: { path: target, provider_id: "ida" } },
    { timeout: 300000 },
  );
  await writeFile(path.join(output, "open.json"), JSON.stringify(r, null, 2));
  opened = !r.isError;
  console.log(
    JSON.stringify({
      stage: "open",
      ok: opened,
      result: r.structuredContent?.result,
    }),
  );
  if (!opened) throw Error("open_binary failed; see open.json");
  const done = new Set();
  let active = Date.now();
  while (Date.now() - active < 1200000) {
    try {
      await access(path.join(queue, "STOP"));
      break;
    } catch {}
    for (const f of (await readdir(queue))
      .filter((f) => /^\d+.*\.json$/.test(f))
      .sort()) {
      if (done.has(f)) continue;
      const jobs = JSON.parse(await readFile(path.join(queue, f), "utf8"));
      for (const job of jobs) {
        if (!/^[a-z0-9-]+$/.test(job.file)) throw Error("Unsafe output name");
        const start = Date.now();
        let row = { file: job.file, name: job.name, arguments: job.arguments };
        try {
          const result = await c.callTool(
            { name: job.name, arguments: job.arguments },
            { timeout: 300000 },
          );
          await writeFile(
            path.join(output, job.file + ".mcp.json"),
            JSON.stringify({ request: job, result }, null, 2),
          );
          const content = result.structuredContent;
          const evidence =
            content?.predicate_type === "rea.analysis"
              ? content
              : content?.evidence;
          const normalized = evidence?.normalized_result ?? content?.result;
          if (evidence)
            await writeFile(
              path.join(output, job.file + ".evidence.json"),
              JSON.stringify(evidence, null, 2),
            );
          if (normalized !== undefined)
            await writeFile(
              path.join(output, job.file + ".result.json"),
              JSON.stringify(normalized, null, 2),
            );
          row = {
            ...row,
            isError: result.isError ?? false,
            evidence_id: result.structuredContent?.evidence_id ?? null,
          };
        } catch (e) {
          row.error = String(e);
        }
        row.elapsedMs = Date.now() - start;
        requests.push(row);
        console.log(JSON.stringify(row));
        await writeFile(
          path.join(output, "requests.json"),
          JSON.stringify(requests, null, 2),
        );
      }
      done.add(f);
      active = Date.now();
      await writeFile(path.join(output, f + ".done"), "done");
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
} finally {
  try {
    const r = await c.callTool(
      { name: "close_binary", arguments: {} },
      { timeout: 300000 },
    );
    await writeFile(
      path.join(output, "close.json"),
      JSON.stringify(r, null, 2),
    );
  } finally {
    await c.close();
    await writeFile(path.join(output, "stderr.log"), errors);
    await writeFile(
      path.join(output, "lifecycle.json"),
      JSON.stringify(
        { opened, targetExecuted: false, requests: requests.length },
        null,
        2,
      ),
    );
  }
}
