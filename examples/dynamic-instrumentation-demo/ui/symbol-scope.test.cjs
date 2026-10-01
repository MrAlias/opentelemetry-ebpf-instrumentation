const assert = require('node:assert/strict');
const { classify } = require('./symbol-scope.js');

assert.equal(classify('main.applyCoupon', ['go']), 'application');
assert.equal(classify('runtime.mallocgc', ['go']), 'runtime');
assert.equal(classify('github.com/acme/library.Call', ['go']), 'dependency');

assert.equal(classify('demo.inventory.CatalogService.findProduct', ['java']), 'application');
assert.equal(classify('java.lang.String.valueOf', ['java']), 'runtime');
assert.equal(classify('org.springframework.web.Handler.handle', ['java']), 'dependency');
assert.equal(classify('okhttp3.internal.connection.RealCall.initExchange', ['java']), 'dependency');
assert.equal(classify('okio.Buffer.readByte', ['java']), 'dependency');
assert.equal(classify('org.objectweb.asm.ClassReader.accept', ['java']), 'dependency');
assert.equal(classify('org.jcp.xml.dsig.internal.dom.DOMReference.digest', ['java']), 'dependency');

assert.equal(classify('/app/catalog.cjs:exports.lookupStock', ['nodejs']), 'application');
assert.equal(classify('/app/node_modules/express/index.js:exports', ['nodejs']), 'dependency');
assert.equal(classify('node:fs.readFile', ['nodejs']), 'runtime');
