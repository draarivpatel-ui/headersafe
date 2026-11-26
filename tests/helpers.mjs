import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** CJS entry point (require()). */
export const cjs = require('../cjs/index.cjs');
/** ESM entry point (import()). */
export const esm = await import('../src/index.mjs');

export const APIs = [esm, cjs];

/** Assert fn throws a HeaderSafeError with the named code. */
export function throwsCode(fn, code, label) {
  let captured;
  assert.throws(fn, (error) => {
    captured = error;
    return true;
  }, label || 'expected HeaderSafeError ' + code);
  assert.equal(captured && captured.name, 'HeaderSafeError', label);
  assert.equal(captured && captured.code, code, label);
  assert.ok(typeof captured.reason === 'string' && captured.reason.length > 0, label);
  return captured;
}

/** Minimal Node http.ServerResponse stand-in with real getHeader/setHeader semantics. */
export function nodeResponse() {
  const store = new Map();
  return {
    store,
    setHeader(name, value) {
      store.set(name.toLowerCase(), value);
      return this;
    },
    getHeader(name) {
      return store.get(name.toLowerCase());
    },
    removeHeader(name) {
      store.delete(name.toLowerCase());
    },
    headers() {
      return Object.fromEntries(store);
    }
  };
}

/** Minimal Fetch Headers stand-in with case-insensitive semantics. */
export function fetchHeaders(initial = {}) {
  const store = new Map();
  for (const [name, value] of Object.entries(initial)) store.set(name.toLowerCase(), String(value));
  return {
    store,
    set(name, value) {
      store.set(String(name).toLowerCase(), String(value));
    },
    get(name) {
      const value = store.get(String(name).toLowerCase());
      return value === undefined ? null : value;
    },
    append(name, value) {
      const key = String(name).toLowerCase();
      const prior = store.get(key);
      store.set(key, prior ? prior + ', ' + String(value) : String(value));
    },
    delete(name) {
      store.delete(String(name).toLowerCase());
    },
    forEach(cb) {
      for (const [key, value] of store) cb(value, key);
    },
    entries() {
      return store.entries();
    }
  };
}

export function fetchResponse(body, init = {}) {
  const headers = fetchHeaders(init.headers || {});
  return {
    ok: init.status === undefined || (init.status >= 200 && init.status < 300),
    status: init.status === undefined ? 200 : init.status,
    statusText: init.statusText || '',
    body,
    headers,
    async arrayBuffer() {
      return new TextEncoder().encode(body).buffer;
    }
  };
}

export const STRICT_CSP =
  "default-src 'none'; base-uri 'none'; object-src 'none'; " +
  "frame-ancestors 'none'; form-action 'self'; script-src 'nonce-abcdefgh1234'";
