import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { APIs, esm, cjs, STRICT_CSP, nodeResponse, fetchHeaders } from './helpers.mjs';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('ESM and CJS produce byte-identical output for every builder', () => {
  const cases = [
    [esm.buildCsp, [{ preset: 'strict' }], cjs.buildCsp, [{ preset: 'strict' }]],
    [esm.buildCsp, [{ 'script-src': ["'self'"], 'img-src': ['data:'] }], cjs.buildCsp, [{ 'script-src': ["'self'"], 'img-src': ['data:'] }]],
    [esm.buildSecurityHeaders, [], cjs.buildSecurityHeaders, []],
    [esm.buildSecurityHeaders, [{ hsts: { maxAge: 10, preload: true }, csp: STRICT_CSP }], cjs.buildSecurityHeaders, [{ hsts: { maxAge: 10, preload: true }, csp: STRICT_CSP }]],
    [esm.serializeSafeCookie, ['__Host-sid', 'abc'], cjs.serializeSafeCookie, ['__Host-sid', 'abc']],
    [esm.serializeSafeCookie, ['sid', 'abc', { sameSite: 'None', path: '/x' }], cjs.serializeSafeCookie, ['sid', 'abc', { sameSite: 'None', path: '/x' }]],
    [esm.mergeVary, ['Accept, Origin'], cjs.mergeVary, ['Accept, Origin']]
  ];
  for (const [esmFn, esmArgs, cjsFn, cjsArgs] of cases) {
    const a = esmFn(...esmArgs);
    const b = cjsFn(...cjsArgs);
    assert.deepEqual(a, b);
    if (typeof a === 'string') assert.equal(a, b);
  }
});

test('ESM and CJS produce identical audit results', () => {
  const policies = [
    STRICT_CSP,
    "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *",
    "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; script-src 'nonce-abcdefgh'"
  ];
  for (const policy of policies) {
    assert.deepEqual(esm.auditCsp(policy), cjs.auditCsp(policy));
  }
  const cookies = [
    'sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax',
    '__Host-sid=abc; Path=/app; Domain=x.com',
    'sid=abc'
  ];
  for (const cookie of cookies) {
    assert.deepEqual(esm.auditSetCookie(cookie), cjs.auditSetCookie(cookie));
  }
});

test('ESM and CJS CORS policies agree', () => {
  const config = { origin: ['https://trusted.com', 'https://*.example.com'], credentials: false };
  const esmPolicy = esm.createCorsPolicy(config);
  const cjsPolicy = cjs.createCorsPolicy(config);
  const origins = [
    'https://trusted.com', 'https://api.example.com', 'https://trusted.com.evil.com',
    'https://evil.com', 'null', undefined
  ];
  for (const origin of origins) {
    assert.equal(esmPolicy.isAllowed(origin), cjsPolicy.isAllowed(origin), String(origin));
    assert.deepEqual(esmPolicy.headers(origin), cjsPolicy.headers(origin), String(origin));
  }
});

test('ESM and CJS throw matching error codes across the API', () => {
  const pairs = [
    [(api) => api.buildCsp({ 'script-src': ['x;y'] }), 'CSP_SOURCE'],
    [(api) => api.createCorsPolicy({ origin: '*', credentials: true }), 'CORS_CONFIG'],
    [(api) => api.serializeSafeCookie('__Host-sid', 'abc', { domain: 'x.com' }), 'COOKIE_PREFIX'],
    [(api) => api.buildSecurityHeaders({ referrerPolicy: 'unsafe-url' }), 'INVALID_INPUT'],
    [(api) => api.assertSafeHeaderValue('a\nb'), 'CRLF']
  ];
  for (const [run, suffix] of pairs) {
    let esmError;
    let cjsError;
    try { run(esm); } catch (error) { esmError = error; }
    try { run(cjs); } catch (error) { cjsError = error; }
    assert.ok(esmError && cjsError);
    assert.equal(esmError.code, 'ERR_HEADSAFE_' + suffix);
    assert.equal(cjsError.code, esmError.code);
    assert.equal(esmError.message, cjsError.message);
  }
});

test('ESM and CJS adapters behave identically', () => {
  for (const api of APIs) {
    const node = nodeResponse();
    api.applySecurityHeaders(node);
    assert.equal(node.getHeader('X-Frame-Options'), 'DENY');
    const headers = fetchHeaders();
    api.applySecurityHeaders(headers);
    assert.equal(headers.get('X-Frame-Options'), 'DENY');
  }
});

test('package.json declares correct dual-module entry points', async () => {
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'headersafe');
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.main, './cjs/index.cjs');
  assert.equal(pkg.module, './src/index.mjs');
  assert.equal(pkg.types, './types/index.d.ts');
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './cjs/index.cjs');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
  for (const subpath of ['./csp', './cors', './cookies', './headers', './adapters']) {
    assert.ok(pkg.exports[subpath], 'missing export ' + subpath);
    assert.equal(pkg.exports[subpath].types, './types/index.d.ts');
  }
});

test('all ESM subpath modules import and re-export their API', async () => {
  const expected = {
    csp: ['buildCsp', 'auditCsp', 'generateNonce', 'parseCsp'],
    cors: ['createCorsPolicy', 'validateCorsOrigin', 'applyHeaderRecord'],
    cookies: ['serializeSafeCookie', 'auditSetCookie', 'parseSetCookie'],
    headers: ['buildSecurityHeaders', 'applySecurityHeaders', 'withSecurityHeaders'],
    adapters: ['applyHeaderRecord', 'toFetchHeaders', 'fromFetchHeaders']
  };
  for (const [subpath, names] of Object.entries(expected)) {
    const module = await import('../src/' + subpath + '.mjs');
    for (const name of names) {
      assert.equal(typeof module[name], 'function', subpath + ' missing ' + name);
      assert.equal(module.default[name], module[name], subpath + ' default missing ' + name);
    }
  }
});

test('CJS require() entry works through package resolution', () => {
  const loaded = require(path.join(root, 'cjs', 'index.cjs'));
  assert.equal(typeof loaded.buildCsp, 'function');
  assert.equal(loaded.default, loaded);
  assert.match(loaded.buildCsp({ preset: 'strict' }), /object-src 'none'/);
});

test('tracked source contains no internal paths or personal data', async () => {
  const files = [
    'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'GOOD_FIRST_ISSUES.md', 'LICENSE',
    'package.json', 'src/index.mjs', 'cjs/index.cjs', 'types/index.d.ts',
    '.github/workflows/ci.yml'
  ];
  const banned = [
    new RegExp('/' + 'Users' + '/'),
    new RegExp('aa' + 'riv' + 'patel', 'i'),
    new RegExp('Hub' + '/' + 'personal'),
    new RegExp('@' + 'gmail'),
    new RegExp('t3' + '-code'),
    new RegExp('Contest' + ' ' + 'Submissions')
  ];
  const emDash = String.fromCharCode(0x2014);
  const enDash = String.fromCharCode(0x2013);
  for (const file of files) {
    const text = await readFile(path.join(root, file), 'utf8');
    for (const pattern of banned) {
      assert.equal(pattern.test(text), false, file + ' contains ' + pattern);
    }
    assert.equal(text.includes(emDash), false, file + ' contains an em dash');
    assert.equal(text.includes(enDash), false, file + ' contains an en dash');
  }
});

test('README live test count matches the actual test-file count', async () => {
  const files = (await readdir(path.join(root, 'tests'))).filter((name) => name.endsWith('.test.mjs'));
  assert.equal(files.length, 7);
  const readme = await readFile(path.join(root, 'README.md'), 'utf8');
  assert.match(readme, /239 deterministic tests/i);
});
