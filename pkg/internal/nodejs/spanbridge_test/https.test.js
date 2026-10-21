'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

for (const enabled of ['1', '0', 'reinjected', 'upgrade', 'unsupported']) {
  test(`HTTPS wire headers and bodies, propagation=${enabled}`, () => {
    const output = execFileSync(process.execPath, [path.join(__dirname, 'scenario_https.js')], {
      encoding: 'utf8', env: { ...process.env, PROPAGATION: enabled }, timeout: 20000,
    });
    const observations = JSON.parse(output);
    let connection;
    for (const { mode, traceID, observation } of observations) {
      const headers = name => observation.rawHeaders.flatMap((key, i, raw) =>
        i % 2 === 0 && key.toLowerCase() === name ? [raw[i + 1]] : []);
      assert.equal(observation.downstreamStatus, 200);
      assert.ok(Number.isInteger(observation.connection) && observation.connection > 0);
      if (mode !== 'url-only') {
        assert.deepEqual(headers('x-unrelated'), ['preserved']);
        assert.equal(observation.body, `stream-${mode}`);
      }
      if (mode === 'options') connection = observation.connection;
      if (mode === 'string' || mode === 'url') assert.equal(observation.connection, connection);
      if (mode === 'array-value') assert.deepEqual(headers('x-values'), ['traceparent', 'untouched']);
      const values = headers('traceparent');
      if (mode.includes('owned')) {
        assert.deepEqual(values, [mode === 'invalid-owned' ? 'application-owned-invalid-value' :
          '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01']);
      } else if (enabled === '0' || enabled === 'unsupported') {
        assert.deepEqual(values, []);
      } else {
        assert.equal(values.length, 1);
        assert.match(values[0], new RegExp(`^00-${traceID}-[0-9a-f]{16}-01$`));
      }
    }
  });
}
