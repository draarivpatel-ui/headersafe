import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import {
  CODE,
  HeaderSafeError,
  assertSafeHeaderValue,
  hasCrlf,
  parseSetCookie,
  serializeSafeCookie
} from '../src/index.mjs';

function outcome(fn) {
  try {
    return { value: fn(), error: null };
  } catch (error) {
    return { value: null, error };
  }
}

const printable = fc.string({ unit: 'grapheme-ascii', minLength: 0, maxLength: 40 });
const hostileUnit = fc.constantFrom(
  '', 'a', 'x', '1', '=', ';', ',', ' ', '\\', '"', '\r', '\n', '\0', '\t', 'é', 'Ā', '\u010d', '\u010a'
);
const hostileText = fc.string({ unit: hostileUnit, minLength: 0, maxLength: 14 });

test('fast-check arbitrary header values either reject as HeaderSafeError or remain injection-free', () => {
  const arbitraryText = fc.string({ unit: 'binary', minLength: 0, maxLength: 80 });
  fc.assert(fc.property(arbitraryText, (input) => {
    const result = outcome(() => assertSafeHeaderValue(input, 'fuzz'));
    if (result.error) {
      assert.ok(result.error instanceof HeaderSafeError, 'unexpected error type');
      assert.match(result.error.code, /^ERR_HEADSAFE_/);
      return;
    }
    assert.equal(result.value, input);
    assert.equal(hasCrlf(result.value), false);
    assert.equal(/[\r\n\0\x00-\x1f\x7f\u2028\u2029]/.test(result.value), false);
    assert.equal(/[^\x20-\x7e\x80-\xff]/.test(result.value), false);
  }), { seed: 0xead115, numRuns: 240 });
});

test('fast-check CR LF and NUL insertion in header values always fails closed', () => {
  fc.assert(fc.property(
    printable,
    printable,
    fc.constantFrom('\r', '\n', '\0'),
    (left, right, marker) => {
      const input = left + marker + right;
      assert.throws(
        () => assertSafeHeaderValue(input, 'fuzz'),
        (error) => error instanceof HeaderSafeError && error.code === CODE.CRLF
      );
    }
  ), { seed: 0xc21f, numRuns: 160 });
});

test('fast-check cookie serialization never emits CR LF or NUL even for hostile inputs', () => {
  fc.assert(fc.property(hostileText, hostileText, (name, value) => {
    const result = outcome(() => serializeSafeCookie(name, value));
    if (result.error) {
      assert.ok(result.error instanceof HeaderSafeError, 'unexpected error type');
      assert.match(result.error.code, /^ERR_HEADSAFE_/);
      return;
    }
    assert.equal(hasCrlf(result.value), false);
    assert.equal(/[\r\n\0]/.test(result.value), false);
    const parsed = parseSetCookie(result.value);
    assert.equal(parsed.name, name);
    assert.equal(parsed.value, value);
  }), { seed: 0xc00c1e, numRuns: 180 });
});

test('fast-check CR LF and NUL insertion in valid cookie values is always rejected', () => {
  const cookieOctetUnit = fc.constantFrom('a', 'b', 'x', '1', '!', '#', '$', '%', '&', "'", '+', '-', '.', '^', '_', '`', '|', '~');
  const cookieText = fc.string({ unit: cookieOctetUnit, minLength: 0, maxLength: 24 });
  fc.assert(fc.property(cookieText, cookieText, fc.constantFrom('\r', '\n', '\0'), (left, right, marker) => {
    assert.throws(
      () => serializeSafeCookie('sid', left + marker + right),
      (error) => error instanceof HeaderSafeError && error.code === CODE.CRLF
    );
  }), { seed: 0x5eed, numRuns: 140 });
});
