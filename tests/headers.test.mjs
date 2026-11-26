import assert from 'node:assert/strict';
import { test } from 'node:test';
import { APIs, esm, throwsCode, nodeResponse, fetchHeaders, STRICT_CSP } from './helpers.mjs';

for (const [label, api] of APIs.map((api, i) => [i === 0 ? 'ESM' : 'CJS', api])) {
  const {
    buildSecurityHeaders, applySecurityHeaders, applyHeaderRecord,
    toFetchHeaders, fromFetchHeaders, CODE
  } = api;

  test(label + ': default security headers cover every required family', () => {
    const headers = buildSecurityHeaders();
    assert.equal(headers['Strict-Transport-Security'], 'max-age=31536000');
    assert.equal(headers['X-Content-Type-Options'], 'nosniff');
    assert.equal(headers['Referrer-Policy'], 'no-referrer');
    assert.match(headers['Permissions-Policy'], /camera=\(\)/);
    assert.equal(headers['Cross-Origin-Opener-Policy'], 'same-origin');
    assert.equal(headers['Cross-Origin-Resource-Policy'], 'same-origin');
    assert.equal(headers['Cross-Origin-Embedder-Policy'], 'require-corp');
    assert.equal(headers['X-Frame-Options'], 'DENY');
    assert.match(headers['Content-Security-Policy'], /object-src 'none'/);
    assert.equal(Object.isFrozen(headers), true);
  });

  test(label + ': HSTS options serialize correctly', () => {
    const headers = buildSecurityHeaders({
      hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
    });
    assert.equal(headers['Strict-Transport-Security'], 'max-age=63072000; includeSubDomains; preload');
  });

  test(label + ': HSTS can be disabled and validated', () => {
    assert.equal('Strict-Transport-Security' in buildSecurityHeaders({ hsts: false }), false);
    throwsCode(() => buildSecurityHeaders({ hsts: { maxAge: -1 } }), CODE.INVALID_INPUT);
    throwsCode(() => buildSecurityHeaders({ hsts: { maxAge: 1.5 } }), CODE.INVALID_INPUT);
  });

  test(label + ': unsafe policy values are rejected', () => {
    throwsCode(() => buildSecurityHeaders({ referrerPolicy: 'unsafe-url' }), CODE.INVALID_INPUT);
    throwsCode(() => buildSecurityHeaders({ frameOptions: 'ALLOWALL' }), CODE.INVALID_INPUT);
    throwsCode(() => buildSecurityHeaders({ crossOriginOpenerPolicy: 'unsafe-none' }), CODE.INVALID_INPUT);
    throwsCode(() => buildSecurityHeaders({ crossOriginEmbedderPolicy: 'unsafe-none' }), CODE.INVALID_INPUT);
    assert.equal(buildSecurityHeaders({ crossOriginOpenerPolicy: 'unsafe-none', allowUnsafeNone: true })['Cross-Origin-Opener-Policy'], 'unsafe-none');
  });

  test(label + ': optional headers can be disabled', () => {
    const headers = buildSecurityHeaders({
      contentTypeOptions: false,
      referrerPolicy: false,
      permissionsPolicy: false,
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      crossOriginEmbedderPolicy: false,
      frameOptions: false,
      csp: false
    });
    assert.deepEqual(Object.keys(headers), ['Strict-Transport-Security']);
  });

  test(label + ': Permissions-Policy allowlists work', () => {
    const headers = buildSecurityHeaders({
      permissionsPolicy: {
        camera: [],
        geolocation: ['self'],
        payment: ['https://pay.example']
      }
    });
    assert.equal(headers['Permissions-Policy'], 'camera=(), geolocation=(self), payment=(https://pay.example)');
  });

  test(label + ': wildcard Permissions-Policy requires opt-in', () => {
    throwsCode(() => buildSecurityHeaders({ permissionsPolicy: { camera: ['*'] } }), CODE.INVALID_INPUT);
    const headers = buildSecurityHeaders({ permissionsPolicy: { camera: ['*'] }, allowWildcardPermissions: true });
    assert.equal(headers['Permissions-Policy'], 'camera=(*)');
  });

  test(label + ': report-only CSP option', () => {
    const headers = buildSecurityHeaders({ csp: { policy: STRICT_CSP, reportOnly: true } });
    assert.ok('Content-Security-Policy-Report-Only' in headers);
    assert.equal('Content-Security-Policy' in headers, false);
  });

  test(label + ': CSP nonce option flows into bundle', () => {
    const headers = buildSecurityHeaders({ csp: { preset: 'strict', nonces: 'abcdefgh1234' } });
    assert.match(headers['Content-Security-Policy'], /'nonce-abcdefgh1234'/);
    assert.match(headers['Content-Security-Policy'], /'strict-dynamic'/);
  });

  test(label + ': rejects header injection from any option', () => {
    throwsCode(() => buildSecurityHeaders({ referrerPolicy: 'no-referrer\r\nX-Evil: 1' }), CODE.INVALID_INPUT);
    throwsCode(() => buildSecurityHeaders({ csp: "default-src 'none'\r\nX-Evil: 1" }), CODE.CRLF);
  });

  test(label + ': applySecurityHeaders writes to Node response', () => {
    const res = nodeResponse();
    const result = applySecurityHeaders(res, { hsts: { maxAge: 100 } });
    assert.equal(result, res);
    assert.equal(res.getHeader('X-Content-Type-Options'), 'nosniff');
    assert.equal(res.getHeader('Strict-Transport-Security'), 'max-age=100');
  });

  test(label + ': applySecurityHeaders writes to Fetch Headers', () => {
    const headers = fetchHeaders();
    const result = applySecurityHeaders(headers);
    assert.equal(result, headers);
    assert.equal(headers.get('X-Frame-Options'), 'DENY');
    assert.match(headers.get('Content-Security-Policy'), /object-src 'none'/);
  });

  test(label + ': applyHeaderRecord merges Vary on both adapters', () => {
    const node = nodeResponse();
    node.setHeader('Vary', 'Accept-Encoding');
    applyHeaderRecord(node, { Vary: 'Origin', 'X-Test': 'ok' });
    assert.equal(node.getHeader('Vary'), 'Accept-Encoding, Origin');
    const fetch = fetchHeaders({ vary: 'Accept-Encoding' });
    applyHeaderRecord(fetch, { Vary: 'Origin' });
    assert.equal(fetch.get('Vary'), 'Accept-Encoding, Origin');
  });

  test(label + ': applyHeaderRecord rejects injected records', () => {
    const node = nodeResponse();
    throwsCode(() => applyHeaderRecord(node, { 'X-Evil\r\n': 'x' }), CODE.HEADER_NAME);
    throwsCode(() => applyHeaderRecord(node, { 'X-Evil': 'a\r\nb' }), CODE.CRLF);
    throwsCode(() => applyHeaderRecord(null, { 'X-Test': '1' }, { strict: true }), CODE.INVALID_INPUT);
  });

  test(label + ': plain object target works for non-strict calls', () => {
    const target = {};
    applyHeaderRecord(target, { 'X-Test': '1', Vary: 'Origin' });
    assert.equal(target['X-Test'], '1');
    assert.equal(target.Vary, 'Origin');
    throwsCode(() => applyHeaderRecord('not-an-object', { 'X-Test': '1' }), CODE.INVALID_INPUT);
  });

  test(label + ': toFetchHeaders and fromFetchHeaders round-trip', () => {
    const FetchHeaders = class {
      constructor() { this.map = fetchHeaders(); }
      set(name, value) { this.map.set(name, value); }
      get(name) { return this.map.get(name); }
      append(name, value) { this.map.append(name, value); }
      delete(name) { this.map.delete(name); }
      forEach(cb) { this.map.forEach(cb); }
    };
    const record = { 'X-Test': 'value', 'Content-Security-Policy': STRICT_CSP };
    const converted = toFetchHeaders(record, { Headers: FetchHeaders });
    assert.equal(converted.get('X-Test'), 'value');
    const roundTripped = fromFetchHeaders(converted);
    assert.equal(roundTripped['x-test'], 'value');
    assert.equal(roundTripped['content-security-policy'], STRICT_CSP);
    throwsCode(() => toFetchHeaders(record, { Headers: {} }), CODE.INVALID_INPUT);
  });

  test(label + ': fromFetchHeaders rejects non-Headers input', () => {
    throwsCode(() => fromFetchHeaders({}), CODE.INVALID_INPUT);
  });
}

test('bundle CSP audit is clean by default', () => {
  const headers = esm.buildSecurityHeaders();
  const result = esm.auditCsp(headers['Content-Security-Policy']);
  assert.equal(result.ok, true);
  assert.deepEqual(result.findings, []);
});
