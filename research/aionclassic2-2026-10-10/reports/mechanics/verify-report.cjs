/* oxlint-disable typescript/no-var-requires -- This standalone CommonJS verifier intentionally uses require. */
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');
const { chromium } = require('C:/Users/Administrator/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const root = 'D:/RVE/.codex/local/aion-mechanics-report';
const checks = [];
const check = (name, condition) => { assert.ok(condition, name); checks.push({ name, passed: true }); };
(async () => {
  const browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const errors = [], network = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(String(error)));
    page.on('request', request => { if (/^https?:/.test(request.url())) network.push(request.url()); });
    await page.goto(pathToFileURL(root + '/AION机制分析报告.html').href);
    await page.waitForFunction(() => window.reportAPI && document.getElementById('enc-client').textContent.includes('55%'));
    check('14 report sections including REA followup', await page.locator('section').count() === 14);
    check('Followup distinguishes direction state from unproven counter window', (await page.locator('#round9').textContent()).includes('方向状态不是已证实的盾反窗口'));
    check('Received numeric consumer chain is visible', (await page.locator('#round9').textContent()).includes('0B5630(type=3)'));
    check('All 26 explicit PVP resources are included', await page.locator('#pvp-skill-table tr').count() === 26);
    const sourceItems = JSON.parse(fs.readFileSync('D:/RVE/.codex/local/aion-report-backup/binary/combat-resource-evidence.json')).speed_bonus_items;
    const reportItems = JSON.parse(fs.readFileSync(root + '/evidence/report-data.json')).items;
    check('Every bonus_attr field in selected equipment is preserved', sourceItems.every((item, i) => Object.keys(item.raw).filter(key => key.startsWith('bonus_attr')).every(key => reportItems[i][key] === item.raw[key])));
    check('No external network requests', network.length === 0);
    check('No JavaScript errors', errors.length === 0);
    check('Desktop document has no horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.locator('#round9').evaluate(el => window.scrollTo(0, el.offsetTop - 85));
    await page.screenshot({ path: root + '/preview-round9.png' });
    const calculations = await page.evaluate(() => {
      const api = window.reportAPI;
      return {
        enchant: [api.enchantClient(4, 50, 80, 10, 0), api.enchantClient(4, 50, 80, 11, 150), api.enchantClient(4, 50, 100, 11, 150)],
        threshold: api.enchantServer(15, 50, 70, 15),
        pvp: api.pvpStage(1000, 200, 100),
        critical: [440, 441, 450, 600, 601].map(c => Math.round(api.probabilityLt(api.criticalRate(c), 100) * 101)),
        god: [api.godProbability(60, 30, false), api.godProbability(60, 30, true)],
        interval: [1401, 1000, 2000].map(interval => api.deriveLab({ min: 100, max: 120, power: 100, bonus: 20, defense: 200, interval, rate: -70 }).intervalMs)
      };
    });
    assert.deepEqual(calculations.enchant.map(x => x.raw), [800, 550, 650]); check('Client enchant stage and supplement examples', true);
    check('Reference enchant threshold 90', calculations.threshold === 90);
    check('PVP sequential rounding gives 660', calculations.pvp.stage1 === 600 && calculations.pvp.stage2 === 660);
    assert.deepEqual(calculations.critical, [44, 45, 45, 52, 53]); check('Critical breakpoints and integer draw counts', true);
    check('Godstone main probability 45/1001', Math.abs(calculations.god[0].probability - 45 / 1001) < 1e-14);
    check('Godstone offhand exact discrete probability', Math.abs(calculations.god[1].probability - 690 / 31 / 1001) < 1e-14);
    assert.deepEqual(calculations.interval, [701, 600, 1000]); check('Attack interval half-base and 600 limits', true);
    const caseChecks = await page.evaluate(() => {
      const api = window.caseAPI, basic = window.reportAPI;
      const caps = [10, 11].map(n => Array.from({ length: 191 }, (_, s) => s).find(s => basic.enchantClient(5, 50, s, n, 0).base === (n === 10 ? 800 : 500)));
      const rates = [1800, 1900, 2200, 2480, 2481].map(a => api.caseRates({ a, e: 1600, p: 2200, b: 2500 }));
      const inverse = Array.from({ length: 1001 }, (_, b) => b + 20).every(b => api.defenseThreshold(b, b - 19, 50) === 1 && api.defenseThreshold(b, b - 20, 50) === 2 && api.defenseThreshold(b + 500, b, 50) === 50 && api.defenseThreshold(b + 499, b, 50) === 49);
      return { caps, rates, inverse, supplements: [10, 11].map(n => basic.enchantClient(5, 50, n === 10 ? 94 : 107, n, 150).raw), critical: [600, 700, 760].map(c => Math.round(api.caseCritical(c, 160) * 101)), noShield: api.caseRates({ a: 2200, e: 1600, p: 2200, b: 2500, shield: false }), skill: api.caseRates({ a: 2200, e: 1600, p: 2200, b: 2500, skill: true }) };
    });
    assert.deepEqual(caseChecks.caps, [94, 107]); check('Epic level50 first UI caps are L94 and L107', true);
    assert.deepEqual(caseChecks.supplements, [950, 650]); check('Epic correct supplement yields UI95/65', true);
    assert.deepEqual(caseChecks.critical, [44, 49, 52]); check('Opponent resist160 shifts critical targets to600/760', true);
    check('Inverse block targets checked on1001 representative defenses', caseChecks.inverse);
    check('Lower parry can increase block events while conditional block is capped', caseChecks.rates[1].block > caseChecks.rates[0].block && caseChecks.rates[1].bt === caseChecks.rates[0].bt);
    check('Accuracy2480 and2481 straddle block floor', caseChecks.rates[3].bt === 2 && caseChecks.rates[4].bt === 1);
    check('Twohand no-shield removes block branch', caseChecks.noShield.block === 0);
    check('Physical skill does not reuse ordinary dodge lottery', caseChecks.skill.dt === 0 && caseChecks.skill.block > caseChecks.rates[2].block);
    check('Chinese resource identities render intact', (await page.locator('#case-weapons').textContent()).includes('塔哈巴塔之双手剑') && (await page.locator('#case-weapons').textContent()).includes('101300564'));
    const caseData = JSON.parse(fs.readFileSync(root + '/evidence/case-evidence.json', 'utf8'));
    check('Selected common/China fields identical with ten pinned source blobs verified', caseData.chinaSelectedFieldsIdentical && caseData.sourceAudits.length === 10);
    check('Block-only counter skill evidence preserved', caseData.counterCandidates.some(x => x.id === '154' && x.counter_skill === 'Block' && x._label === '盾牌反击 I'));
    check('Level50 examples exclude level54/55 skills', (await page.locator('#case-skills').textContent()).includes('破坏一击 II') && !(await page.locator('#case-skills').textContent()).includes('幻影弹'));
    check('Skill rankII does not replace learned level1', (await page.locator('#case-skills').textContent()).includes('1424 + 39×1 = 1463') && (await page.locator('#case-skills').textContent()).includes('1902'));
    await page.locator('#case-a').fill('2481');
    check('Opponent-specific calculator reaches conditional floor', (await page.locator('#case-plan').textContent()).includes('条件盾防 1/101'));
    await page.locator('#case-has-shield').selectOption('0');
    check('Calculator shield selection changes result', (await page.locator('#case-plan').textContent()).includes('对方无盾'));
    await page.locator('#case-own-shield').selectOption('1');
    check('Own shield investment target responds to enemy accuracy', (await page.locator('#case-plan').textContent()).includes('封顶盾防 2500'));
    await page.locator('#case-r').fill('');
    check('Case calculator refuses missing numeric inputs', (await page.locator('#case-plan').textContent()).includes('范围'));
    await page.locator('#case-a').fill('2200'); await page.locator('#case-r').fill('160');
    await page.locator('#case-has-shield').selectOption('1'); await page.locator('#case-own-shield').selectOption('0');
    await page.locator('#attr-search').fill('attackDelay');
    check('Attribute search returns enum 29', await page.locator('#attr-table').textContent().then(x => x.includes('29')) && await page.locator('#attr-table tr').count() === 1);
    await page.locator('#attr-search').fill('');
    await page.locator('#equipment details summary').click();
    await page.locator('#item-search').fill('100000196');
    check('Equipment search returns known resource', (await page.locator('#item-table').textContent()).includes('attackDelay 3%'));
    await page.locator('#item-search').fill('');
    await page.locator('#item-next').click();
    check('Equipment pagination works', (await page.locator('#item-count').textContent()).includes('2 of'));
    await page.locator('#equipment details summary').click();
    await page.locator('#godstone details summary').click();
    await page.locator('#god-search').fill('168000034');
    check('Godstone search returns p60 L30', (await page.locator('#god-table').textContent()).includes('60 / 30'));
    await page.locator('#godstone details summary').click();
    await page.locator('[data-lab="defense"]').fill('300');
    await page.locator('#lab-apply').click();
    check('Learning modifier changes derived damage and records old/new', (await page.locator('#lab-result').textContent()).includes('90 — 110') && (await page.locator('#lab-diff').textContent()).includes('200 → 300'));
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#lab-export').click();
    const download = await downloadPromise;
    await download.saveAs(root + '/example-learning-scenario.json');
    const scenario = JSON.parse(fs.readFileSync(root + '/example-learning-scenario.json'));
    check('Export preserves model scope and derived values', scenario.state.defense === 300 && scenario.derived.damageMin === 90 && scenario.referenceCommit.length === 40);
    await page.locator('#lab-reset').click();
    check('Reset restores original model', (await page.locator('#lab-result').textContent()).includes('100 — 120'));
    await page.locator('#god-l').fill('70');
    check('Godstone invalid bounds show explicit error', (await page.locator('#god-result').textContent()).includes('范围'));
    await page.locator('#god-l').fill('30');
    await page.locator('#sample-k').fill('101');
    check('Impossible observation counts rejected', (await page.locator('#sample-result').textContent()).includes('不能大于'));
    await page.locator('#sample-k').fill('6');
    check('Wilson interval renders expected lower bound', (await page.locator('#sample-result').textContent()).includes('2.7786%'));
    const brokenLinks = await page.evaluate(() => [...document.querySelectorAll('a[href^="#"]')].map(a => a.getAttribute('href')).filter(href => !document.querySelector(href)));
    check('All internal navigation anchors resolve', brokenLinks.length === 0);
    const links = await page.locator('a[href^="evidence/"]').evaluateAll(nodes => nodes.map(a => a.getAttribute('href')));
    check('All evidence links exist on disk', links.every(link => fs.existsSync(root + '/' + link)));
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: root + '/preview-desktop.png' });
    await page.locator('header').evaluate(el => el.style.visibility = 'hidden');
    await page.locator('#enchant').screenshot({ path: root + '/preview-enchant.png' });
    await page.locator('#case-accuracy').evaluate(el => el.closest('.tablewrap').scrollIntoView({ block: 'center' }));
    await page.screenshot({ path: root + '/preview-cases.png' });
    await page.locator('header').evaluate(el => el.style.visibility = '');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('#case-plan').evaluate(el => el.scrollIntoView({ block: 'start' }));
    check('Mobile case calculator stays inside viewport', await page.locator('#case-plan').evaluate(el => el.getBoundingClientRect().right <= innerWidth));
    await page.screenshot({ path: root + '/preview-case-mobile.png' });
    await page.locator('#round9').evaluate(el => window.scrollTo(0, el.offsetTop - 85));
    check('Mobile followup remains within viewport', await page.locator('#round9').evaluate(el => el.getBoundingClientRect().right <= innerWidth));
    await page.screenshot({ path: root + '/preview-round9-mobile.png' });
    await page.evaluate(() => scrollTo(0, 0));
    check('Mobile document has no horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({ path: root + '/preview-mobile.png' });
    await page.emulateMedia({ media: 'print' });
    check('Print layout hides navigation and controls', await page.locator('nav').evaluate(el => getComputedStyle(el).display === 'none'));
    check('No JavaScript errors after interactions', errors.length === 0);
    fs.writeFileSync(root + '/verification.json', JSON.stringify({ checks, calculations, caseChecks, errors, externalNetworkRequests: network, scope: 'Report browser and model verification; not game execution or live-server validation.', passed: true }, null, 2));
    console.log(JSON.stringify({ passed: true, checks: checks.length, errors, screenshots: ['preview-desktop.png', 'preview-enchant.png', 'preview-mobile.png', 'preview-cases.png', 'preview-case-mobile.png', 'preview-round9.png', 'preview-round9-mobile.png'] }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
