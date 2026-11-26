import assert from 'node:assert/strict';
import { test } from 'node:test';
import { APIs, throwsCode, cjs, esm } from './helpers.mjs';

for (const [label, api] of APIs.map((api, i) => [i === 0 ? 'ESM' : 'CJS', api])) {
  test(label + ': HeaderSafeError shape', () => {
    const error = new api.HeaderSafeError(api.CODE.CRLF, 'bad header', 'value', 'x');
    assert.equal(error.name, 'HeaderSafeError');
    assert.equal(error.code, 'ERR_HEADSAFE_CRLF');
    assert.equal(error.reason, 'bad header');
    assert.equal(error.field, 'value');
    assert.equal(error.value, 'x');
    assert.match(error.message, /ERR_HEADSAFE_CRLF/);
    assert.ok(error instanceof Error);
    const json = error.toJSON();
    assert.equal(json.code, 'ERR_HEADSAFE_CRLF');
    assert.equal(json.field, 'value');
  });

  test(label + ': CODE is frozen and complete', () => {
    assert.ok(Object.isFrozen(api.CODE));
    assert.equal(Object.keys(api.CODE).length, 14);
    for (const value of Object.values(api.CODE)) {
      assert.match(value, /^ERR_HEADSAFE_[A-Z_]+$/);
    }
  });

  test(label + ': rejects invalid header names', () => {
    for (const name of ['', 'Bad Name', 'Bad:Name', 'Bad\nName', 'Bad\rName', 'Bad\x00Name', 'Bad(Name)']) {
      throwsCode(() => api.assertSafeHeaderName(name), api.CODE.HEADER_NAME, label + ' name ' + JSON.stringify(name));
    }
    for (const name of ['X-Test', 'a', 'A_B', 'x.y', 'x+y', 'x|y']) {
      assert.equal(api.assertSafeHeaderName(name), name);
    }
  });

  test(label + ': rejects CRLF and control characters in header values', () => {
    for (const value of ['a\rb', 'a\nb', 'a\r\nX-Evil: 1', 'a\x00b']) {
      throwsCode(() => api.assertSafeHeaderValue(value), api.CODE.CRLF, label + ' CRLF ' + JSON.stringify(value));
    }
    for (const value of ['a\x1fb', 'a\x7fb']) {
      throwsCode(() => api.assertSafeHeaderValue(value), api.CODE.CONTROL_CHARACTER, label + ' control ' + JSON.stringify(value));
    }
    throwsCode(() => api.assertSafeHeaderValue('\u2028x'), api.CODE.CONTROL_CHARACTER, label + ' line separator');
    throwsCode(() => api.assertSafeHeaderValue(42), api.CODE.INVALID_INPUT, label + ' non-string');
  });

  test(label + ': forbidSemicolon and forbidComma options', () => {
    assert.equal(api.assertSafeHeaderValue('a;b'), 'a;b');
    throwsCode(() => api.assertSafeHeaderValue('a;b', 'x', { forbidSemicolon: true }), api.CODE.HEADER_VALUE);
    assert.equal(api.assertSafeHeaderValue('a,b'), 'a,b');
    throwsCode(() => api.assertSafeHeaderValue('a,b', 'x', { forbidComma: true }), api.CODE.HEADER_VALUE);
  });

  test(label + ': hasCrlf detector', () => {
    assert.equal(api.hasCrlf('ok'), false);
    assert.equal(api.hasCrlf('a\rb'), true);
    assert.equal(api.hasCrlf('a\nb'), true);
    assert.equal(api.hasCrlf('a\x00b'), true);
    assert.equal(api.hasCrlf(undefined), false);
  });

  test(label + ': rejects non-Latin-1 values that can truncate into CR or LF', () => {
    for (const value of ['ačb', 'aĊb', 'aȊb', 'a＊b', 'a\u{1F600}b']) {
      throwsCode(() => api.assertSafeHeaderValue(value), api.CODE.HEADER_VALUE, label + ' ' + JSON.stringify(value));
    }
    assert.equal(api.assertSafeHeaderValue('café'), 'café');
  });

  test(label + ': mergeVary is case-insensitive and idempotent', () => {
    assert.equal(api.mergeVary(undefined), 'Origin');
    assert.equal(api.mergeVary(''), 'Origin');
    assert.equal(api.mergeVary('Accept-Encoding'), 'Accept-Encoding, Origin');
    assert.equal(api.mergeVary('origin'), 'origin');
    assert.equal(api.mergeVary('Accept, Origin'), 'Accept, Origin');
    assert.equal(api.mergeVary('Accept,  Origin '), 'Accept, Origin');
    throwsCode(() => api.mergeVary('a;b'), api.CODE.HEADER_VALUE);
  });

  test(label + ': mergeVary accepts arrays and treats star as terminal', () => {
    assert.equal(api.mergeVary(['Accept-Encoding', 'Accept-Language']), 'Accept-Encoding, Accept-Language, Origin');
    assert.equal(api.mergeVary([]), 'Origin');
    assert.equal(api.mergeVary('*'), '*');
    assert.equal(api.mergeVary(['*']), '*');
    throwsCode(() => api.mergeVary(['Ok', 'a\r\nb']), api.CODE.CRLF);
  });
}

test('ESM and CJS expose identical API surface', () => {
  const esmKeys = Object.keys(esm).sort();
  const cjsKeys = Object.keys(cjs).filter((key) => key !== 'default').sort();
  assert.deepEqual(esmKeys, cjsKeys);
  for (const name of esmKeys) {
    assert.equal(typeof esm[name], typeof cjs[name], name);
  }
});

test('type declarations reference every runtime export', async () => {
  const { readFile } = await import('node:fs/promises');
  const dts = await readFile(new URL('../types/index.d.ts', import.meta.url), 'utf8');
  for (const name of Object.keys(esm)) {
    assert.ok(dts.includes(name + ':') || dts.includes('declare function ' + name) || dts.includes('declare const ' + name) || dts.includes('declare class ' + name), 'missing type for ' + name);
  }
});
