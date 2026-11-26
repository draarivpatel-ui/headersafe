import assert from 'node:assert/strict';
import { test } from 'node:test';
import { APIs, esm, throwsCode, nodeResponse, fetchHeaders } from './helpers.mjs';

for (const [label, api] of APIs.map((api, i) => [i === 0 ? 'ESM' : 'CJS', api])) {
  const { createCorsPolicy, validateCorsOrigin, CODE } = api;

  test(label + ': exact origin allowlist works', () => {
    const policy = createCorsPolicy({ origin: ['https://trusted.com'] });
    assert.equal(policy.isAllowed('https://trusted.com'), true);
    assert.equal(policy.isAllowed('https://trusted.com:443'), false);
    assert.equal(policy.isAllowed('http://trusted.com'), false);
    assert.equal(policy.isAllowed('https://TRUSTED.COM'), true);
  });

  test(label + ': substring and prefix bypass origins are rejected', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com' });
    for (const origin of [
      'https://trusted.com.evil.com',
      'https://eviltrusted.com',
      'https://trusted.com@evil.com',
      'https://evil.com/?x=https://trusted.com',
      'https://trusted.com.evil.com:443',
      'https://trusted.com?x=1'
    ]) {
      assert.equal(policy.isAllowed(origin), false, label + ' bypass ' + origin);
    }
  });

  test(label + ': headers() omits ACAO for disallowed origins', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com' });
    const result = policy.headers('https://evil.com');
    assert.deepEqual(result, { Vary: 'Origin' });
    assert.equal('Access-Control-Allow-Origin' in result, false);
  });

  test(label + ': headers() always emits Vary: Origin', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com' });
    assert.equal(policy.headers('https://trusted.com').Vary, 'Origin');
    assert.equal(policy.headers('https://evil.com').Vary, 'Origin');
    assert.equal(policy.headers(undefined).Vary, 'Origin');
  });

  test(label + ': rejects wildcard origin with credentials', () => {
    throwsCode(() => createCorsPolicy({ origin: '*', credentials: true }), CODE.CORS_CONFIG);
    throwsCode(() => createCorsPolicy({ origin: ['https://a.com', '*'], credentials: true }), CODE.CORS_CONFIG);
  });

  test(label + ': wildcard origin without credentials is supported', () => {
    const policy = createCorsPolicy({ origin: '*' });
    assert.equal(policy.isAllowed('https://anything.example'), true);
    assert.equal(policy.headers('https://anything.example')['Access-Control-Allow-Origin'], '*');
    assert.equal('Access-Control-Allow-Credentials' in policy.headers('https://anything.example'), false);
  });

  test(label + ': null origin rejected by default', () => {
    const policy = createCorsPolicy({ origin: '*' });
    assert.equal(policy.isAllowed('null'), false);
    assert.deepEqual(policy.headers('null'), { Vary: 'Origin' });
  });

  test(label + ': null origin requires explicit opt-in', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com', allowNullOrigin: true });
    assert.equal(policy.isAllowed('null'), true);
    assert.equal(policy.headers('null')['Access-Control-Allow-Origin'], 'null');
  });

  test(label + ': assertAllowed throws for rejected origins', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com' });
    assert.equal(policy.assertAllowed('https://trusted.com'), 'https://trusted.com');
    throwsCode(() => policy.assertAllowed('https://trusted.com.evil.com'), CODE.CORS_ORIGIN);
    throwsCode(() => policy.assertAllowed('null'), CODE.CORS_ORIGIN);
  });

  test(label + ': strict header mode throws for rejected origins', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com' });
    throwsCode(() => policy.headers('https://evil.com', { strict: true }), CODE.CORS_ORIGIN);
  });

  test(label + ': preflight headers are complete and safe', () => {
    const policy = createCorsPolicy({
      origin: 'https://trusted.com',
      credentials: true,
      methods: ['GET', 'POST'],
      allowedHeaders: ['Content-Type', 'X-Trace'],
      exposedHeaders: ['X-Count'],
      maxAge: 120
    });
    const result = policy.headers('https://trusted.com', { preflight: true });
    assert.equal(result['Access-Control-Allow-Methods'], 'GET, POST');
    assert.equal(result['Access-Control-Allow-Headers'], 'Content-Type, X-Trace');
    assert.equal(result['Access-Control-Max-Age'], '120');
    assert.equal(result['Access-Control-Allow-Credentials'], 'true');
    assert.equal('Access-Control-Expose-Headers' in result, false);
    assert.equal(policy.headers('https://trusted.com')['Access-Control-Expose-Headers'], 'X-Count');
  });

  test(label + ': rejects CRLF in reflected origin', () => {
    const policy = createCorsPolicy({ origin: '*' });
    for (const origin of ['https://a.com\r\nX-Evil: 1', 'null\r\nX-Evil: 1', 'https://a.com\x00']) {
      assert.equal(policy.isAllowed(origin), false);
      throwsCode(() => policy.headers(origin, { strict: true }), CODE.CORS_ORIGIN, label + ' strict CRLF');
    }
  });

  test(label + ': rejects CRLF and semicolons in configuration', () => {
    throwsCode(() => createCorsPolicy({ origin: 'https://a.com\r\nX-Evil: 1' }), CODE.CRLF, label + ' CRLF origin');
    throwsCode(() => createCorsPolicy({ origin: 'https://a.com;x' }), CODE.CORS_CONFIG, label + ' semicolon origin');
    throwsCode(() => createCorsPolicy({ origin: 'https://a.com', methods: ['GET\r\nX-Evil: 1'] }), CODE.CRLF, label + ' CRLF method');
    throwsCode(() => createCorsPolicy({ origin: 'https://a.com', allowedHeaders: ['X;Break'] }), CODE.CORS_CONFIG, label + ' semicolon header');
  });

  test(label + ': rejects malformed origins and unsafe schemes', () => {
    throwsCode(() => validateCorsOrigin('trusted.com'), CODE.CORS_ORIGIN);
    throwsCode(() => validateCorsOrigin('javascript://evil.com'), CODE.CORS_ORIGIN);
    throwsCode(() => validateCorsOrigin('file:///etc/passwd'), CODE.CORS_ORIGIN);
    throwsCode(() => validateCorsOrigin('https://trusted.com#evil'), CODE.CORS_ORIGIN);
    throwsCode(() => validateCorsOrigin('https://user@trusted.com'), CODE.CORS_ORIGIN);
    throwsCode(() => validateCorsOrigin('https://trusted.com:99999'), CODE.CORS_ORIGIN);
    throwsCode(() => validateCorsOrigin('https://trusted.com/path'), CODE.CORS_ORIGIN);
    assert.equal(validateCorsOrigin('https://trusted.com'), 'https://trusted.com');
  });

  test(label + ': wildcard subdomain patterns are anchored', () => {
    const policy = createCorsPolicy({ origin: 'https://*.example.com' });
    assert.equal(policy.isAllowed('https://api.example.com'), true);
    assert.equal(policy.isAllowed('https://deep.api.example.com'), true);
    assert.equal(policy.isAllowed('https://example.com.evil.com'), false);
    assert.equal(policy.isAllowed('https://evil-example.com'), false);
    assert.equal(policy.isAllowed('http://api.example.com'), false);
    assert.equal(policy.isAllowed('https://api.example.com:8443'), false);
  });

  test(label + ': rejects malformed wildcard patterns', () => {
    for (const pattern of ['https://trusted*', 'http://*.example.com', '*evil.com', 'https://*.', 'https://*x.example.com', 'https://*.e*vil.com']) {
      throwsCode(() => createCorsPolicy({ origin: pattern }), CODE.CORS_CONFIG, label + ' pattern ' + pattern);
    }
  });

  test(label + ': custom validator requires explicit opt-in', () => {
    throwsCode(() => createCorsPolicy({ origin: () => true }), CODE.CORS_CONFIG);
    const policy = createCorsPolicy({ origin: (origin) => origin === 'https://ok.example', allowCustomValidator: true });
    assert.equal(policy.isAllowed('https://ok.example'), true);
    assert.equal(policy.isAllowed('https://bad.example'), false);
  });

  test(label + ': custom validator errors fail closed', () => {
    const policy = createCorsPolicy({ origin: () => { throw new Error('boom'); }, allowCustomValidator: true });
    assert.equal(policy.isAllowed('https://trusted.com'), false);
  });

  test(label + ': config validation', () => {
    throwsCode(() => createCorsPolicy({ maxAge: -1 }), CODE.CORS_CONFIG);
    throwsCode(() => createCorsPolicy({ maxAge: 999999 }), CODE.CORS_CONFIG);
    throwsCode(() => createCorsPolicy({ methods: 'GET' }), CODE.CORS_CONFIG);
    throwsCode(() => createCorsPolicy({ exposedHeaders: 'X-Count' }), CODE.CORS_CONFIG);
    throwsCode(() => createCorsPolicy({ origin: true }), CODE.CORS_CONFIG);
    throwsCode(() => createCorsPolicy(null), CODE.CORS_CONFIG);
  });

  test(label + ': apply() writes to Node response and merges Vary', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com' });
    const res = nodeResponse();
    res.setHeader('Vary', 'Accept-Encoding');
    policy.apply(res, 'https://trusted.com');
    assert.equal(res.getHeader('Access-Control-Allow-Origin'), 'https://trusted.com');
    assert.equal(res.getHeader('Vary'), 'Accept-Encoding, Origin');
  });

  test(label + ': apply() writes to Fetch Headers and merges Vary', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com' });
    const headers = fetchHeaders({ Vary: 'Accept-Encoding' });
    policy.apply(headers, 'https://trusted.com');
    assert.equal(headers.get('Access-Control-Allow-Origin'), 'https://trusted.com');
    assert.equal(headers.get('Vary'), 'Accept-Encoding, Origin');
  });

  test(label + ': policy config is frozen', () => {
    const policy = createCorsPolicy({ origin: 'https://trusted.com', methods: ['GET'] });
    assert.ok(Object.isFrozen(policy));
    assert.ok(Object.isFrozen(policy.config));
    assert.ok(Object.isFrozen(policy.config.methods));
  });
}

test('validateCorsOrigin supports explicit null opt-in', () => {
  throwsCode(() => esm.validateCorsOrigin('null'), esm.CODE.CORS_ORIGIN, 'null rejected by default');
  assert.equal(esm.validateCorsOrigin('null', { allowNullOrigin: true }), 'null');
});
