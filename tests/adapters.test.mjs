import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import { once } from 'node:events';
import { APIs, throwsCode, nodeResponse, fetchHeaders, fetchResponse } from './helpers.mjs';

for (const [label, api] of APIs.map((api, i) => [i === 0 ? 'ESM' : 'CJS', api])) {
  const { withSecurityHeaders, isNodeResponse, isFetchHeaders, applySecurityHeaders, CODE } = api;

  test(label + ': adapter detection', () => {
    assert.equal(isNodeResponse(nodeResponse()), true);
    assert.equal(isNodeResponse(fetchHeaders()), false);
    assert.equal(isFetchHeaders(fetchHeaders()), true);
    assert.equal(isFetchHeaders(nodeResponse()), false);
    assert.equal(isNodeResponse(null), false);
    assert.equal(isFetchHeaders(undefined), false);
  });

  test(label + ': withSecurityHeaders rejects non-functions', () => {
    throwsCode(() => withSecurityHeaders('handler'), CODE.INVALID_INPUT);
  });

  test(label + ': withSecurityHeaders wraps a Node handler', () => {
    const res = nodeResponse();
    const wrapped = withSecurityHeaders((req, response) => {
      response.setHeader('Content-Type', 'text/plain');
      return 'handled';
    });
    assert.equal(wrapped({}, res), 'handled');
    assert.equal(res.getHeader('X-Content-Type-Options'), 'nosniff');
    assert.equal(res.getHeader('Content-Type'), 'text/plain');
  });

  test(label + ': withSecurityHeaders wraps a sync Fetch handler', async () => {
    const wrapped = withSecurityHeaders(() => fetchResponse('ok'));
    const response = wrapped({});
    assert.equal(response.headers.get('X-Frame-Options'), 'DENY');
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'ok');
  });

  test(label + ': withSecurityHeaders wraps an async Fetch handler', async () => {
    const wrapped = withSecurityHeaders(async () => fetchResponse('async', { status: 201 }));
    const response = await wrapped({});
    assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.equal(response.status, 201);
    assert.equal(await response.text(), 'async');
  });

  test(label + ': withSecurityHeaders passes through non-Response values', () => {
    const wrapped = withSecurityHeaders(() => 42);
    assert.equal(wrapped({}), 42);
  });

  test(label + ': withSecurityHeaders preserves this binding and arguments', async () => {
    const context = { id: 'ctx' };
    let seen;
    const wrapped = withSecurityHeaders(function (...args) {
      seen = [this, ...args];
      return fetchResponse('ok');
    });
    wrapped.call(context, 'a', 'b');
    assert.equal(seen[0], context);
    assert.deepEqual(seen.slice(1), ['a', 'b']);
  });

  test(label + ': Node http.ServerResponse integration', async () => {
    const server = http.createServer((req, res) => {
      applySecurityHeaders(res, { hsts: { maxAge: 100 } });
      res.end('ok');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const { port } = server.address();
      const response = await fetch('http://127.0.0.1:' + port + '/');
      assert.equal(await response.text(), 'ok');
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('strict-transport-security'), 'max-age=100');
      assert.equal(response.headers.get('x-frame-options'), 'DENY');
      assert.match(response.headers.get('content-security-policy'), /object-src 'none'/);
    } finally {
      server.close();
      await once(server, 'close');
    }
  });

  test(label + ': Fetch Headers integration with real Headers class', () => {
    const headers = new Headers({ 'X-Existing': '1' });
    applySecurityHeaders(headers);
    assert.equal(headers.get('X-Existing'), '1');
    assert.equal(headers.get('X-Content-Type-Options'), 'nosniff');
    assert.equal(headers.get('Referrer-Policy'), 'no-referrer');
  });

  test(label + ': real Response integration', async () => {
    const wrapped = withSecurityHeaders(() => new Response('payload', { status: 202 }));
    const response = await wrapped({});
    assert.equal(response.status, 202);
    assert.equal(await response.text(), 'payload');
    assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.match(response.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/);
  });
}
