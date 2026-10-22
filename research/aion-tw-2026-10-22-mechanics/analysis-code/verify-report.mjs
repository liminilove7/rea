import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { pathToFileURL, fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const load = (p) =>
  JSON.parse(
    fs.readFileSync(path.join(root, p), "utf8").replace(/^\uFEFF/, ""),
  );
const hash = (b) => crypto.createHash("sha256").update(b).digest("hex");
(async () => {
  const checks = [],
    errors = [],
    network = [];
  const check = (name, ok) => {
    assert.ok(ok, name);
    checks.push({ name, passed: true });
  };
  const idx = load("binary-evidence/index.json"),
    req = load("binary-evidence/requests.json");
  check(
    "52 requests succeeded",
    req.length === 52 && req.every((r) => !r.isError && !r.error),
  );
  check("51 canonical Evidence records", idx.evidence.length === 51);
  for (const e of idx.evidence) {
    const bytes = fs.readFileSync(path.join(root, e.file));
    const d = JSON.parse(bytes);
    assert.equal(hash(bytes), e.sha256);
    assert.equal(d.evidence_id, e.id);
    assert.equal(d.subject.digest.sha256, idx.sample_sha256);
  }
  check("Every canonical Evidence hash and target identity matches", true);
  const close = load("binary-evidence/close.json");
  check(
    "REA close completed",
    !close.isError && Object.hasOwn(close.structuredContent, "result"),
  );
  const g = load("godstone/summary.json");
  check(
    "Godstone counts reconcile",
    g.coverage.proc_enchant_candidates === 250 &&
      g.coverage.join_status_counts.resolved === 249 &&
      g.coverage.join_status_counts.missing === 1 &&
      g.coverage.left_probability_present +
        g.coverage.left_probability_absent ===
        250,
  );
  const manifest = load("enchant/source-manifest.json");
  check(
    "28 XML members decoded with CRC",
    manifest.sources.length === 28 &&
      manifest.errors.length === 0 &&
      manifest.sources.every((s) => s.crc_verified),
  );
  const pv = load("pvp/feature-summary.json");
  check(
    "PVP declared coverage",
    pv.coverage.files === 46 &&
      pv.coverage.records === 122063 &&
      pv.explicit_damage_ratio_records === 96,
  );
  const ledger = load("finding-ledger.json");
  check(
    "Claim source files exist",
    ledger.claims.every((c) =>
      c.sources.every((p) => fs.existsSync(path.join(root, p))),
    ),
  );
  const browser = await chromium.launch({
    headless: true,
    executablePath:
      process.env.REA_REPORT_BROWSER ||
      "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  });
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("request", (r) => {
      if (/^https?:/.test(r.url())) network.push(r.url());
    });
    await page.goto(
      pathToFileURL(path.join(root, "AION-TW-机制分析.html")).href,
    );
    await page.waitForFunction(() => window.study);
    check(
      "Six sections visible in document",
      (await page.locator("section").count()) === 6,
    );
    check(
      "Chinese text renders and no replacement characters",
      await page.evaluate(
        () =>
          document.body.innerText.includes("神石") &&
          !document.body.innerText.includes("\uFFFD"),
      ),
    );
    const examples = load("enchant/current-formula-model.json").examples;
    for (const e of examples) {
      const v = await page.evaluate(
        (e) =>
          study.calculate(
            e.target.quality_code,
            e.target.level,
            e.stone.level,
            e.next_stage,
            e.supplement?.raw ?? 0,
          ),
        e,
      );
      assert.equal(v.raw, e.raw_result);
      assert.equal(v.display, e.client_display_numeric_float32);
    }
    check(
      "All seven resource-linked examples match native-derived model",
      examples.length === 7,
    );
    const cases = [
      [4, 55, 190, 10, 65535, 1000],
      [5, 55, 44, 11, 150, 150],
      [4, 55, 1, 10, 0, 0],
    ];
    for (const [q, l, s, n, a, expected] of cases)
      assert.equal(
        (await page.evaluate((v) => study.calculate(...v), [q, l, s, n, a]))
          .raw,
        expected,
      );
    check("Cap, negative intermediate and lower boundary", true);
    await page.locator("#stage").fill("21");
    check(
      "Out-of-scope stage rejected",
      (await page.locator("#calc").getAttribute("class")) === "error",
    );
    await page.locator("#stage").fill("10");
    await page.locator("#level").fill("");
    check(
      "Empty field rejected",
      (await page.locator("#calc").getAttribute("class")) === "error",
    );
    await page.locator("#level").fill("55");
    await page.locator("#stage").fill("11");
    check(
      "UI update shows 55 percent",
      (await page.locator("#calc").textContent()).includes("55%"),
    );
    await page.locator("#stage").fill("10");
    const links = await page
      .locator("a[href]")
      .evaluateAll((a) => a.map((x) => x.getAttribute("href")));
    check(
      "Local links exist",
      links
        .filter((x) => !x.startsWith("#") && x !== "verification.json")
        .every((x) => fs.existsSync(path.resolve(root, x))),
    );
    check(
      "Navigation anchors resolve",
      await page.evaluate(() =>
        [...document.querySelectorAll('a[href^="#"]')].every((a) =>
          document.getElementById(a.hash.slice(1)),
        ),
      ),
    );
    check(
      "Desktop no page overflow",
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    fs.mkdirSync(path.join(root, "previews"), { recursive: true });
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: path.join(root, "previews/desktop.png") });
    await page.locator("#enchant").scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(root, "previews/enchant.png") });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => scrollTo(0, 0));
    check(
      "Mobile no page overflow",
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await page.screenshot({ path: path.join(root, "previews/mobile.png") });
    await page.locator("#enchant details summary").first().click();
    check(
      "Detailed evidence can expand",
      (await page.locator("#enchant details").first().getAttribute("open")) !==
        null,
    );
    check("No external requests", network.length === 0);
    check("No browser errors", errors.length === 0);
  } finally {
    await browser.close();
  }
  fs.writeFileSync(
    path.join(root, "verification.json"),
    JSON.stringify(
      {
        date: "2026-10-22",
        allPassed: true,
        checks,
        errors,
        network,
        targetExecuted: false,
        gameFunctionalityTested: false,
        serverMechanicsVerified: false,
      },
      null,
      2,
    ),
  );
  console.log(JSON.stringify({ allPassed: true, checks: checks.length }));
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
