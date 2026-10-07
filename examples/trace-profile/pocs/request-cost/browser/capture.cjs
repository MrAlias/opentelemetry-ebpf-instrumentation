const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');

async function main() {
  const dir = path.resolve(process.argv[2]);
  const destination = path.join(dir, 'browser');
  fs.mkdirSync(destination, { recursive: true });
  const targets = [];
  for (const cohort of ['ordinary', 'slow']) {
    const rows = JSON.parse(fs.readFileSync(path.join(dir, `${cohort}-requests.json`)));
    rows.sort((a, b) => b.total_cpu_ns - a.total_cpu_ns);
    if (!rows.length || !rows[0].total_cpu_ns) continue;
    for (const type of ['trace', 'profile']) {
      targets.push({ name: `${cohort}-${type}`, url: rows[0][`${type}_url`], trace_id: rows[0].trace_id,
        span_id: rows[0].processing_span_id });
    }
  }
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  try {
    fs.writeFileSync(path.join(destination, 'versions.json'), JSON.stringify({playwright: require('playwright/package.json').version, chromium: browser.version()}, null, 2) + '\n');
    const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
    let responseErrors = [];
    page.on('response', response => { if (response.status() >= 400) responseErrors.push({url: response.url(), status: response.status()}); });
    for (const target of targets) {
      responseErrors = [];
      await page.goto(target.url);
      await page.waitForTimeout(8000);
      const content = await page.locator('body').innerText();
      fs.writeFileSync(path.join(destination, target.name + '.txt'), content);
      await page.screenshot({ path: path.join(destination, target.name + '.png'), fullPage: true });
      target.final_url = page.url();
      target.trace_id_visible = target.name.endsWith('-trace') ? content.includes(target.trace_id) : null;
      target.http_errors = responseErrors;
    }
    fs.writeFileSync(path.join(destination, 'links.json'), JSON.stringify(targets, null, 2) + '\n');
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
