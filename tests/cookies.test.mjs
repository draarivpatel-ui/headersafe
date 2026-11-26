import assert from 'node:assert/strict';
import { test } from 'node:test';
import { APIs, throwsCode } from './helpers.mjs';

for (const [label, api] of APIs.map((api, i) => [i === 0 ? 'ESM' : 'CJS', api])) {
  const { serializeSafeCookie, parseSetCookie, auditSetCookie, CODE } = api;

  test(label + ': secure cookie defaults', () => {
    const cookie = serializeSafeCookie('session', 'abc123DEF456');
    assert.equal(cookie, 'session=abc123DEF456; Path=/; HttpOnly; Secure; SameSite=Lax');
    assert.equal(cookie.includes('\n'), false);
  });

  test(label + ': all attributes serialize in order', () => {
    const cookie = serializeSafeCookie('sid', 'value123', {
      domain: 'example.com',
      path: '/app',
      maxAge: 3600,
      expires: new Date('2030-01-01T00:00:00Z'),
      sameSite: 'Strict',
      priority: 'High',
      partitioned: true
    });
    assert.match(cookie, /^sid=value123; Domain=example\.com; Path=\/app; Max-Age=3600; Expires=Tue, 01 Jan 2030 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict; Priority=High; Partitioned$/);
  });

  test(label + ': __Host- prefix invariants are enforced', () => {
    const cookie = serializeSafeCookie('__Host-session', 'abc123');
    assert.match(cookie, /^__Host-session=abc123; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
    throwsCode(() => serializeSafeCookie('__Host-session', 'abc', { secure: false }), CODE.COOKIE_PREFIX);
    throwsCode(() => serializeSafeCookie('__Host-session', 'abc', { path: '/app' }), CODE.COOKIE_PREFIX);
    throwsCode(() => serializeSafeCookie('__Host-session', 'abc', { domain: 'example.com' }), CODE.COOKIE_PREFIX);
  });

  test(label + ': __Secure- prefix requires Secure', () => {
    assert.match(serializeSafeCookie('__Secure-token', 'abc123'), /^__Secure-token=abc123; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
    throwsCode(() => serializeSafeCookie('__Secure-token', 'abc123', { secure: false }), CODE.COOKIE_PREFIX);
  });

  test(label + ': SameSite=None requires Secure', () => {
    assert.match(serializeSafeCookie('sid', 'abc123', { sameSite: 'None' }), /SameSite=None/);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { sameSite: 'None', secure: false }), CODE.COOKIE_ATTRIBUTE);
  });

  test(label + ': rejects CRLF and control characters in name', () => {
    for (const name of ['a\r\nX-Evil: 1', 'a\nb', 'a\x00b']) {
      throwsCode(() => serializeSafeCookie(name, 'abc123'), CODE.CRLF, label + ' name ' + JSON.stringify(name));
    }
    for (const name of ['', '$sid', 'a b', 'a=b']) {
      throwsCode(() => serializeSafeCookie(name, 'abc123'), CODE.COOKIE_NAME, label + ' name ' + JSON.stringify(name));
    }
    throwsCode(() => serializeSafeCookie('a;b', 'abc123'), CODE.COOKIE_NAME, label + ' name semicolon');
  });

  test(label + ': rejects CRLF and control characters in value', () => {
    for (const value of ['a\r\nX-Evil: 1', 'a\nb', 'a\x00b']) {
      throwsCode(() => serializeSafeCookie('sid', value), CODE.CRLF, label + ' value ' + JSON.stringify(value));
    }
    for (const value of ['a b', 'a,b', 'a\\b', 'a"b']) {
      throwsCode(() => serializeSafeCookie('sid', value), CODE.COOKIE_VALUE, label + ' value ' + JSON.stringify(value));
    }
    throwsCode(() => serializeSafeCookie('sid', 'a;b'), CODE.COOKIE_VALUE, label + ' value semicolon');
  });

  test(label + ': rejects unsafe Path and Domain', () => {
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { path: 'relative' }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { path: '/a;b' }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { domain: 'evil.com/path' }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { domain: 'evil.com:443' }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { domain: 'bad domain' }), CODE.COOKIE_ATTRIBUTE);
    assert.match(serializeSafeCookie('sid', 'abc123', { domain: '.example.com' }), /Domain=\.example\.com/);
  });

  test(label + ': rejects invalid SameSite, Priority and numeric attributes', () => {
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { sameSite: 'Lax;Secure' }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { priority: 'Urgent' }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { maxAge: -1 }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { maxAge: 1.5 }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { maxAge: NaN }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { maxAge: Infinity }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { expires: new Date('bad') }), CODE.COOKIE_ATTRIBUTE);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { expires: 'not-a-date' }), CODE.COOKIE_ATTRIBUTE);
    assert.match(serializeSafeCookie('sid', 'abc123', { expires: 'Wed, 21 Oct 2015 07:28:00 GMT' }), /Expires=Wed, 21 Oct 2015 07:28:00 GMT/);
    throwsCode(() => serializeSafeCookie('__Host-sid', 'abc123', { path: '//' }), CODE.COOKIE_PREFIX);
    throwsCode(() => serializeSafeCookie('sid', 'abc123', { partitioned: true, secure: false }), CODE.COOKIE_ATTRIBUTE);
  });

  test(label + ': empty cookie values support deletion cookies', () => {
    const cookie = serializeSafeCookie('sid', '', { maxAge: 0 });
    assert.equal(cookie, 'sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
    assert.deepEqual(auditSetCookie('sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax').findings, []);
  });

  test(label + ': parseSetCookie parses attributes', () => {
    const parsed = parseSetCookie('sid=abc123; Path=/; Domain=example.com; Max-Age=60; HttpOnly; Secure; SameSite=Strict');
    assert.equal(parsed.name, 'sid');
    assert.equal(parsed.value, 'abc123');
    assert.equal(parsed.attributes.path, '/');
    assert.equal(parsed.attributes.domain, 'example.com');
    assert.equal(parsed.attributes['max-age'], '60');
    assert.equal(parsed.attributes.httponly, true);
    assert.equal(parsed.attributes.secure, true);
    assert.equal(parsed.attributes.samesite, 'Strict');
  });

  test(label + ': parseSetCookie rejects malformed and injected headers', () => {
    throwsCode(() => parseSetCookie('noequals'), CODE.COOKIE_NAME);
    throwsCode(() => parseSetCookie('=abc'), CODE.COOKIE_NAME);
    throwsCode(() => parseSetCookie('sid=abc\r\nX-Evil: 1'), CODE.CRLF);
  });

  test(label + ': auditSetCookie approves hardened cookies', () => {
    const cookie = serializeSafeCookie('__Host-session', 'abc123');
    const audit = auditSetCookie(cookie);
    assert.equal(audit.ok, true);
    assert.equal(audit.score, 100);
    assert.deepEqual(audit.findings, []);
    assert.equal(audit.prefix, '__Host-');
    assert.equal(audit.name, '__Host-session');
  });

  test(label + ': auditSetCookie flags missing attributes', () => {
    const audit = auditSetCookie('sid=abc123');
    assert.equal(audit.ok, false);
    const ids = audit.findings.map((f) => f.id);
    assert.ok(ids.includes('MISSING_SECURE'));
    assert.ok(ids.includes('MISSING_HTTPONLY'));
    assert.ok(ids.includes('MISSING_SAMESITE'));
    assert.ok(audit.score < 100 && audit.score >= 0);
  });

  test(label + ': auditSetCookie flags SameSite=None without Secure', () => {
    const audit = auditSetCookie('sid=abc123; Path=/; SameSite=None; HttpOnly');
    assert.ok(audit.findings.some((f) => f.id === 'SAMESITE_NONE_WITHOUT_SECURE'));
  });

  test(label + ': auditSetCookie flags every __Host- violation', () => {
    const audit = auditSetCookie('__Host-sid=abc123; Path=/app; Domain=example.com; HttpOnly; SameSite=Lax');
    const ids = audit.findings.map((f) => f.id);
    assert.ok(ids.includes('__HOST_MISSING_SECURE'));
    assert.ok(ids.includes('__HOST_PATH_NOT_ROOT'));
    assert.ok(ids.includes('__HOST_HAS_DOMAIN'));
  });

  test(label + ': auditSetCookie flags __Secure- without Secure', () => {
    const audit = auditSetCookie('__Secure-sid=abc123; Path=/; HttpOnly; SameSite=Lax');
    assert.ok(audit.findings.some((f) => f.id === '__SECURE_MISSING_SECURE'));
  });

  test(label + ': auditSetCookie rejects injected cookies', () => {
    throwsCode(() => auditSetCookie('sid=abc\r\nX-Evil: 1'), CODE.CRLF);
  });
}
