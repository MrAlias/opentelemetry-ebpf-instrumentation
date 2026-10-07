const {chromium} = require('playwright');
const fs = require('node:fs');
const path = require('node:path');

async function main() {
  const input = process.argv[2] || '/evidence/browser-links.json';
  const output = path.dirname(input);
  const links = JSON.parse(fs.readFileSync(input, 'utf8'));
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  const page = await browser.newPage({viewport: {width: 1500, height: 1000}});
  const records = [];
  try {
    for (const link of links) {
      const url = new URL(link.url);
      if (!/^[a-z0-9-]+$/.test(link.name) || url.protocol !== 'http:' ||
          !['localhost', '127.0.0.1'].includes(url.hostname) || url.port !== '3103') {
        throw new Error('Capture accepts only named local interference evidence links');
      }
      const response = await page.goto(link.url);
      await page.waitForTimeout(8000);
      const body = await page.locator('body').innerText();
      await page.screenshot({path: path.join(output, link.name + '.png'), fullPage: true});
      fs.writeFileSync(path.join(output, link.name + '.txt'), body);
      records.push({name: link.name, url: page.url(), status: response?.status(),
                    loaded_expected_text: link.expected_text ? body.includes(link.expected_text) : null});
    }
    fs.writeFileSync(path.join(output, 'browser-results.json'), JSON.stringify(records, null, 2) + '\n');
  } finally {
    await browser.close();
  }
}

main().catch(error => {console.error(error); process.exitCode = 1;});
