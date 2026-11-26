/*
 * headersafe core.
 *
 * Pure Web Standards JavaScript with no static imports and no runtime
 * dependencies. Node 18's Web Crypto implementation is loaded conditionally
 * because it predates globalThis.crypto. The CommonJS build in cjs/index.cjs
 * is generated from this file by scripts/build-cjs.mjs so both module formats
 * have identical behavior.
 */

export const CODE = Object.freeze({
  INVALID_INPUT: 'ERR_HEADSAFE_INVALID_INPUT',
  HEADER_NAME: 'ERR_HEADSAFE_HEADER_NAME',
  HEADER_VALUE: 'ERR_HEADSAFE_HEADER_VALUE',
  CRLF: 'ERR_HEADSAFE_CRLF',
  CONTROL_CHARACTER: 'ERR_HEADSAFE_CONTROL_CHARACTER',
  CSP_DIRECTIVE: 'ERR_HEADSAFE_CSP_DIRECTIVE',
  CSP_SOURCE: 'ERR_HEADSAFE_CSP_SOURCE',
  CORS_CONFIG: 'ERR_HEADSAFE_CORS_CONFIG',
  CORS_ORIGIN: 'ERR_HEADSAFE_CORS_ORIGIN',
  COOKIE_NAME: 'ERR_HEADSAFE_COOKIE_NAME',
  COOKIE_VALUE: 'ERR_HEADSAFE_COOKIE_VALUE',
  COOKIE_ATTRIBUTE: 'ERR_HEADSAFE_COOKIE_ATTRIBUTE',
  COOKIE_PREFIX: 'ERR_HEADSAFE_COOKIE_PREFIX',
  RNG: 'ERR_HEADSAFE_RNG'
});

export class HeaderSafeError extends Error {
  constructor(code, reason, field, value) {
    super(code + ': ' + reason + (field ? ' (' + field + ')' : ''));
    this.name = 'HeaderSafeError';
    this.code = code;
    this.reason = reason;
    this.field = field;
    this.value = value;
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      reason: this.reason,
      field: this.field,
      value: this.value
    };
  }
}

function fail(code, reason, field, value) {
  throw new HeaderSafeError(code, reason, field, value);
}

const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const CSP_NAME_RE = /^[a-zA-Z0-9-]+$/;
const COOKIE_OCTET_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;
const CONTROL_RE = /[\x00-\x1F\x7F\u2028\u2029]/;
// Any code point above U+00FF can lose its high byte when a downstream
// serializer encodes the value as latin-1, turning U+010D into CR and U+010A
// into LF (the classic Node header-splitting primitive).
const NON_LATIN1_RE = /[^\t\x20-\x7E\x80-\xFF]/;

export function assertSafeHeaderName(name, field = 'headerName') {
  if (typeof name !== 'string' || name.length === 0) {
    fail(CODE.HEADER_NAME, 'header name must be a non-empty string', field, name);
  }
  if (!TOKEN_RE.test(name)) {
    fail(CODE.HEADER_NAME, 'header name contains invalid token characters', field, name);
  }
  return name;
}

export function assertSafeHeaderValue(value, field = 'headerValue', options = {}) {
  if (typeof value !== 'string') {
    fail(CODE.INVALID_INPUT, 'header value must be a string', field, value);
  }
  if (value.indexOf('\r') !== -1 || value.indexOf('\n') !== -1 || value.indexOf('\0') !== -1) {
    fail(CODE.CRLF, 'CR, LF or NUL is not allowed in a header value', field, value);
  }
  if (CONTROL_RE.test(value)) {
    fail(CODE.CONTROL_CHARACTER, 'control characters are not allowed in a header value', field, value);
  }
  if (NON_LATIN1_RE.test(value)) {
    fail(CODE.HEADER_VALUE, 'header value contains a character above U+00FF that can be truncated into CR or LF', field, value);
  }
  if (options.forbidSemicolon && value.indexOf(';') !== -1) {
    fail(CODE.HEADER_VALUE, 'semicolon is not allowed in this header value', field, value);
  }
  if (options.forbidComma && value.indexOf(',') !== -1) {
    fail(CODE.HEADER_VALUE, 'comma is not allowed in this header value', field, value);
  }
  return value;
}

export function hasCrlf(value) {
  return typeof value === 'string' && /[\r\n\0]/.test(value);
}

export function mergeVary(existing, addition = 'Origin') {
  assertSafeHeaderValue(addition, 'Vary', { forbidSemicolon: true });
  const parts = [];
  const collect = (value) => {
    if (value === undefined || value === null || value === '') return;
    if (Array.isArray(value)) {
      for (const item of value) collect(item);
      return;
    }
    assertSafeHeaderValue(value, 'Vary', { forbidSemicolon: true });
    for (const part of String(value).split(',')) {
      const trimmed = part.trim();
      if (trimmed !== '') parts.push(trimmed);
    }
  };
  collect(existing);
  if (parts.indexOf('*') !== -1) return '*';
  if (parts.length === 0) return addition;
  if (!parts.some((part) => part.toLowerCase() === addition.toLowerCase())) {
    parts.push(addition);
  }
  return parts.join(', ');
}

/* ------------------------------------------------------------------ CSP */

const CSP_ORDER = [
  'default-src', 'base-uri', 'object-src', 'frame-ancestors', 'form-action',
  'script-src', 'script-src-elem', 'script-src-attr', 'style-src',
  'style-src-elem', 'style-src-attr', 'img-src', 'font-src', 'connect-src',
  'media-src', 'manifest-src', 'worker-src', 'child-src', 'frame-src',
  'sandbox', 'report-uri', 'report-to', 'upgrade-insecure-requests',
  'block-all-mixed-content', 'require-trusted-types-for', 'trusted-types'
];

const CSP_BOOLEAN = new Set(['upgrade-insecure-requests', 'block-all-mixed-content']);

const CSP_PRESETS = Object.freeze({
  strict: Object.freeze({
    'default-src': ["'none'"],
    'base-uri': ["'none'"],
    'object-src': ["'none'"],
    'frame-ancestors': ["'none'"],
    'form-action': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'"],
    'img-src': ["'self'"],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'upgrade-insecure-requests': true
  }),
  balanced: Object.freeze({
    'default-src': ["'self'"],
    'base-uri': ["'self'"],
    'object-src': ["'none'"],
    'frame-ancestors': ["'self'"],
    'form-action': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:'],
    'connect-src': ["'self'"],
    'upgrade-insecure-requests': true
  })
});

function parseCspString(header, field = 'csp') {
  assertSafeHeaderValue(header, field);
  const directives = {};
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const pieces = trimmed.split(/\s+/);
    const name = pieces[0].toLowerCase();
    if (!CSP_NAME_RE.test(name)) {
      fail(CODE.CSP_DIRECTIVE, 'invalid CSP directive name', field, pieces[0]);
    }
    const values = pieces.slice(1);
    directives[name] = directives[name] ? directives[name].concat(values) : values.slice();
  }
  return directives;
}

function splitCspSources(value, field) {
  if (typeof value !== 'string') {
    fail(CODE.CSP_SOURCE, 'CSP sources must be strings', field, value);
  }
  if (value.indexOf(';') !== -1 || value.indexOf(',') !== -1) {
    fail(CODE.CSP_SOURCE, 'semicolon or comma is not allowed in a CSP source', field, value);
  }
  assertSafeHeaderValue(value, field);
  return value.split(/\s+/).filter((token) => token.length > 0);
}

function normalizeCspSources(name, input) {
  if (input === undefined || input === null || input === false) return [];
  if (CSP_BOOLEAN.has(name)) {
    if (input !== true && input !== '' && input !== 'true') {
      fail(CODE.CSP_SOURCE, 'this CSP directive takes no source values', name, input);
    }
    return [];
  }
  const raw = Array.isArray(input) ? input : [input];
  const tokens = [];
  for (const item of raw) {
    if (typeof item !== 'string') {
      fail(CODE.CSP_SOURCE, 'CSP sources must be strings', name, item);
    }
    for (const token of splitCspSources(item, name)) {
      tokens.push(token);
    }
  }
  if (tokens.indexOf("'none'") !== -1 && tokens.length > 1) {
    fail(CODE.CSP_SOURCE, "'none' cannot be combined with other sources", name, tokens);
  }
  for (const token of tokens) {
    if (token.indexOf(';') !== -1 || token.indexOf(',') !== -1 || CONTROL_RE.test(token)) {
      fail(CODE.CSP_SOURCE, 'unsafe characters in CSP source', name, token);
    }
  }
  return tokens;
}

const CSP_INLINE_OPTIONS = new Set(['preset', 'nonces', 'hashes', 'strictDynamic', 'reportOnly']);

function normalizeCspPolicy(policy, options = {}) {
  let source = policy;
  if (source === undefined || source === null) source = {};
  if (typeof source === 'string') {
    source = parseCspString(source, 'csp');
  } else if (Array.isArray(source)) {
    const merged = {};
    for (const item of source) {
      const parsed = typeof item === 'string' ? parseCspString(item, 'csp') : item;
      if (parsed === null || typeof parsed !== 'object') {
        fail(CODE.INVALID_INPUT, 'CSP policy must be an object, string or array', 'policy', item);
      }
      for (const key of Object.keys(parsed)) {
        if (CSP_INLINE_OPTIONS.has(key)) continue;
        const value = parsed[key];
        if (value === true || value === false) {
          merged[key] = value;
          continue;
        }
        const list = Array.isArray(value) ? value.slice() : [value];
        merged[key] = Array.isArray(merged[key]) ? merged[key].concat(list) : list;
      }
    }
    source = merged;
  } else if (typeof source !== 'object') {
    fail(CODE.INVALID_INPUT, 'CSP policy must be an object, string or array', 'policy', policy);
  }

  const pick = (name) => (options[name] !== undefined ? options[name] : source[name]);
  const preset = pick('preset');
  const directives = {};
  if (preset !== undefined && preset !== null) {
    if (preset !== 'strict' && preset !== 'balanced') {
      fail(CODE.INVALID_INPUT, 'unknown CSP preset', 'preset', preset);
    }
    const base = CSP_PRESETS[preset];
    for (const key of Object.keys(base)) directives[key] = Array.isArray(base[key]) ? base[key].slice() : base[key];
  }

  for (const key of Object.keys(source)) {
    if (CSP_INLINE_OPTIONS.has(key)) continue;
    const name = key.toLowerCase();
    if (!CSP_NAME_RE.test(name)) {
      fail(CODE.CSP_DIRECTIVE, 'invalid CSP directive name', 'policy', key);
    }
    if (source[key] === false) {
      delete directives[name];
      continue;
    }
    directives[name] = normalizeCspSources(name, source[key]);
  }

  const inlineNonces = pick('nonces');
  const nonces = inlineNonces === undefined ? [] : (Array.isArray(inlineNonces) ? inlineNonces : [inlineNonces]);
  for (const nonce of nonces) {
    assertNonce(nonce);
    const token = "'nonce-" + nonce + "'";
    for (const name of ['script-src', 'style-src']) {
      directives[name] = directives[name] || [];
      if (directives[name].indexOf(token) === -1) directives[name].push(token);
      const noneIndex = directives[name].indexOf("'none'");
      if (noneIndex !== -1) directives[name].splice(noneIndex, 1);
    }
  }

  const inlineHashes = pick('hashes');
  const hashes = inlineHashes === undefined ? [] : (Array.isArray(inlineHashes) ? inlineHashes : [inlineHashes]);
  for (const hash of hashes) {
    let token;
    if (typeof hash === 'string') {
      token = hash;
    } else if (hash && typeof hash === 'object' && typeof hash.algorithm === 'string' && typeof hash.value === 'string') {
      token = "'" + hash.algorithm + '-' + hash.value + "'";
    } else {
      fail(CODE.INVALID_INPUT, 'hash must be a string or an {algorithm, value} object', 'hashes', hash);
    }
    if (!/^'(sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+'$/.test(token)) {
      fail(CODE.CSP_SOURCE, 'invalid CSP hash source', 'hashes', hash);
    }
    directives['script-src'] = directives['script-src'] || [];
    directives['script-src'].push(token);
    const noneIndex = directives['script-src'].indexOf("'none'");
    if (noneIndex !== -1) directives['script-src'].splice(noneIndex, 1);
  }

  const hasCryptoSource = nonces.length > 0 || hashes.length > 0;
  const strictDynamicOption = pick('strictDynamic');
  const strictDynamic = strictDynamicOption === undefined ? hasCryptoSource : strictDynamicOption;
  if (strictDynamic) {
    directives['script-src'] = directives['script-src'] || [];
    if (directives['script-src'].indexOf("'strict-dynamic'") === -1 && directives['script-src'].indexOf("'none'") === -1) {
      directives['script-src'].push("'strict-dynamic'");
    }
  }

  return directives;
}

function assertNonce(nonce) {
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(nonce)) {
    fail(CODE.INVALID_INPUT, 'nonce must be at least 8 base64 characters', 'nonce', nonce);
  }
  return nonce;
}

export function buildCsp(policy = {}, options = {}) {
  if (options === null || typeof options !== 'object') {
    fail(CODE.INVALID_INPUT, 'CSP options must be an object', 'options', options);
  }
  const directives = normalizeCspPolicy(policy, options);
  const names = Object.keys(directives);
  names.sort((a, b) => {
    const ai = CSP_ORDER.indexOf(a);
    const bi = CSP_ORDER.indexOf(b);
    if (ai === -1 && bi === -1) return a < b ? -1 : (a > b ? 1 : 0);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });
  const parts = [];
  for (const name of names) {
    const values = directives[name];
    if (CSP_BOOLEAN.has(name)) {
      if (values !== false) parts.push(name);
      continue;
    }
    if (!Array.isArray(values) || values.length === 0) continue;
    parts.push(name + ' ' + values.join(' '));
  }
  return parts.join('; ');
}

export function parseCsp(header, field = 'csp') {
  return parseCspString(header, field);
}

function cspValues(directives, name) {
  return directives[name] || [];
}

function findCsp(directives, id, severity, directive, message, recommendation) {
  return { id, severity, directive, message, recommendation };
}

/** A bare scheme source such as https: or data: allows every host on that scheme. */
function isSchemeSource(value) {
  return /^[a-z][a-z0-9+.-]*:$/.test(value);
}

function isBroadCspSource(value) {
  return value === '*' || isSchemeSource(value);
}

function normalizeAuditValues(value) {
  if (Array.isArray(value)) return value.filter((item) => typeof item === 'string');
  if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
  return [];
}

export function auditCsp(input, options = {}) {
  const isPolicyObject = input && typeof input === 'object' && !Array.isArray(input) && !(input instanceof String);
  const buildOptionKeys = ['preset', 'nonces', 'hashes', 'strictDynamic', 'reportOnly'];
  const needsBuild = isPolicyObject && Object.keys(input).some((key) => buildOptionKeys.indexOf(key) !== -1);
  const directives = needsBuild
    ? parseCsp(buildCsp(input, options))
    : (isPolicyObject
        ? input
        : parseCsp(typeof input === 'string' ? input : buildCsp(input === undefined ? {} : input, options)));
  const normalized = {};
  for (const key of Object.keys(directives)) {
    const name = key.toLowerCase();
    const values = normalizeAuditValues(directives[key]);
    normalized[name] = normalized[name] ? normalized[name].concat(values) : values;
  }

  const script = cspValues(normalized, 'script-src').concat(cspValues(normalized, 'script-src-elem'));
  const fallback = cspValues(normalized, 'default-src');
  const effectiveScript = script.length > 0 ? script : fallback;
  const scriptAttr = cspValues(normalized, 'script-src-attr');
  const findings = [];

  if (cspValues(normalized, 'default-src').length === 0) {
    findings.push(findCsp(normalized, 'MISSING_DEFAULT_SRC', 'warning', 'default-src', 'No default-src fallback is defined.', "Add default-src 'none' to deny unlisted resource types."));
  }
  const objectSrc = cspValues(normalized, 'object-src');
  if (objectSrc.length === 0 || objectSrc[0] !== "'none'" || objectSrc.length > 1) {
    findings.push(findCsp(normalized, 'MISSING_OBJECT_SRC_NONE', 'critical', 'object-src', "object-src is missing or not exactly 'none'.", "Set object-src 'none' to block plugin content."));
  }
  const baseUri = cspValues(normalized, 'base-uri');
  if (baseUri.length === 0) {
    findings.push(findCsp(normalized, 'MISSING_BASE_URI', 'critical', 'base-uri', 'base-uri is missing, allowing base tag hijacking.', "Set base-uri 'none' or 'self'."));
  } else if (baseUri.some(isBroadCspSource)) {
    findings.push(findCsp(normalized, 'UNSAFE_BASE_URI', 'critical', 'base-uri', 'base-uri allows an unsafe source.', "Set base-uri 'none' or 'self'."));
  }
  const frameAncestors = cspValues(normalized, 'frame-ancestors');
  if (frameAncestors.length === 0) {
    findings.push(findCsp(normalized, 'MISSING_FRAME_ANCESTORS', 'critical', 'frame-ancestors', 'frame-ancestors is missing, allowing clickjacking.', "Set frame-ancestors 'none' or 'self'."));
  } else if (frameAncestors.some(isBroadCspSource)) {
    findings.push(findCsp(normalized, 'WILDCARD_FRAME_ANCESTORS', 'critical', 'frame-ancestors', 'frame-ancestors allows any embedding page.', "Set frame-ancestors 'none' or 'self'."));
  }
  if (effectiveScript.length === 0) {
    findings.push(findCsp(normalized, 'MISSING_SCRIPT_SRC', 'critical', 'script-src', 'No script source policy is defined.', "Set script-src to a nonce or hash policy."));
  }
  if (effectiveScript.indexOf("'unsafe-eval'") !== -1 || fallback.indexOf("'unsafe-eval'") !== -1) {
    findings.push(findCsp(normalized, 'UNSAFE_EVAL', 'critical', 'script-src', "'unsafe-eval' permits eval() and string-to-code execution.", 'Remove unsafe-eval and refactor code that needs it.'));
  }
  const hasCryptoSource = effectiveScript.some((v) => v.indexOf("'nonce-") === 0 || /^'(sha256|sha384|sha512)-/.test(v));
  if (effectiveScript.indexOf("'unsafe-inline'") !== -1 || fallback.indexOf("'unsafe-inline'") !== -1) {
    findings.push(findCsp(normalized, 'UNSAFE_INLINE', hasCryptoSource ? 'warning' : 'critical', 'script-src', "'unsafe-inline' permits inline script execution.", 'Use a nonce or hash instead of unsafe-inline.'));
  }
  if (effectiveScript.indexOf('*') !== -1 || (fallback.indexOf('*') !== -1 && script.length === 0)) {
    findings.push(findCsp(normalized, 'WILDCARD_SCRIPT_SRC', 'critical', 'script-src', 'Wildcard script source allows scripts from any host.', 'Use an explicit allowlist, nonce or hash policy.'));
  }
  if (effectiveScript.some((v) => v !== 'data:' && isSchemeSource(v))) {
    findings.push(findCsp(normalized, 'SCHEME_WILDCARD_SCRIPT_SRC', 'critical', 'script-src', 'A bare scheme source allows scripts from any host on that scheme.', 'Use an explicit allowlist, nonce or hash policy.'));
  }
  if (scriptAttr.some((v) => v === "'unsafe-inline'" || isBroadCspSource(v))) {
    findings.push(findCsp(normalized, 'UNSAFE_SCRIPT_SRC_ATTR', 'critical', 'script-src-attr', 'script-src-attr permits inline event handlers or any host.', "Set script-src-attr 'none' and bind events with addEventListener."));
  }
  if (effectiveScript.indexOf('data:') !== -1 || fallback.indexOf('data:') !== -1) {
    findings.push(findCsp(normalized, 'DATA_URI_SCRIPT', 'critical', 'script-src', 'data: URLs can execute script.', 'Remove data: from script sources.'));
  }
  if (effectiveScript.some((v) => /^'sha1-/.test(v))) {
    findings.push(findCsp(normalized, 'WEAK_HASH_ALGORITHM', 'warning', 'script-src', 'SHA-1 hashes are collision prone.', 'Use sha256, sha384 or sha512 hashes.'));
  }
  if (effectiveScript.indexOf("'unsafe-hashes'") !== -1) {
    findings.push(findCsp(normalized, 'UNSAFE_HASHES', 'warning', 'script-src', "'unsafe-hashes' re-enables inline event handler hashes.", 'Avoid inline handlers entirely.'));
  }
  const allSources = Object.keys(normalized).reduce((acc, key) => acc.concat(normalized[key]), []);
  if (allSources.some((v) => v === 'http:' || v.indexOf('http://') === 0)) {
    findings.push(findCsp(normalized, 'INSECURE_SCHEME', 'warning', 'policy', 'A plain HTTP source is present.', 'Use https: sources or upgrade-insecure-requests.'));
  }
  const formAction = cspValues(normalized, 'form-action');
  if (formAction.length === 0 || formAction.some(isBroadCspSource)) {
    findings.push(findCsp(normalized, 'WEAK_FORM_ACTION', 'warning', 'form-action', 'form-action is missing or allows any target.', "Set form-action 'self'."));
  }

  const weights = { critical: 25, warning: 10, info: 3 };
  let score = 100;
  for (const finding of findings) score -= weights[finding.severity];
  if (score < 0) score = 0;
  return {
    ok: !findings.some((f) => f.severity === 'critical'),
    score,
    findings,
    directives: normalized
  };
}

let runtimeCrypto = globalThis.crypto;
if ((!runtimeCrypto || typeof runtimeCrypto.getRandomValues !== 'function') && typeof process !== 'undefined' && process.versions && process.versions.node) {
  runtimeCrypto = (await import('node:crypto')).webcrypto;
}

function getCrypto() {
  const candidate = globalThis && globalThis.crypto;
  if (candidate && typeof candidate.getRandomValues === 'function') return candidate;
  if (runtimeCrypto && typeof runtimeCrypto.getRandomValues === 'function') return runtimeCrypto;
  return null;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? B64[b2 & 63] : '=';
  }
  return out;
}

export function generateNonce(size = 16) {
  if (!Number.isInteger(size) || size < 8 || size > 64) {
    fail(CODE.INVALID_INPUT, 'nonce size must be an integer between 8 and 64', 'size', size);
  }
  const cryptoObject = getCrypto();
  if (!cryptoObject) {
    fail(CODE.RNG, 'no cryptographically secure random source is available', 'crypto', 'getRandomValues');
  }
  const bytes = new Uint8Array(size);
  cryptoObject.getRandomValues(bytes);
  return base64Encode(bytes).replace(/=+$/, '');
}

/* ----------------------------------------------------------------- CORS */

function validateOriginString(origin, field = 'origin', allowNull = false) {
  if (typeof origin !== 'string' || origin.length === 0) {
    fail(CODE.CORS_ORIGIN, 'origin must be a non-empty string', field, origin);
  }
  assertSafeHeaderValue(origin, field, { forbidSemicolon: true, forbidComma: true });
  if (origin === 'null') {
    if (!allowNull) fail(CODE.CORS_ORIGIN, 'the null origin is not allowed by default', field, origin);
    return origin;
  }
  if (origin === '*') return origin;
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#@]+)$/.exec(origin);
  if (!match) {
    fail(CODE.CORS_ORIGIN, 'origin must be a scheme and host only', field, origin);
  }
  const scheme = match[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    fail(CODE.CORS_ORIGIN, 'origin scheme must be http or https', field, origin);
  }
  const authority = match[2];
  if (authority.indexOf('@') !== -1) {
    fail(CODE.CORS_ORIGIN, 'userinfo is not allowed in an origin', field, origin);
  }
  const hostMatch = /^(\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9.-]+)(?::([0-9]+))?$/.exec(authority);
  if (!hostMatch) {
    fail(CODE.CORS_ORIGIN, 'invalid origin authority', field, origin);
  }
  if (hostMatch[2] !== undefined) {
    const port = Number(hostMatch[2]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      fail(CODE.CORS_ORIGIN, 'invalid origin port', field, origin);
    }
  }
  return scheme + '://' + authority.toLowerCase();
}

function validateAllowedOriginPattern(pattern, allowWildcard) {
  if (typeof pattern !== 'string') {
    fail(CODE.CORS_CONFIG, 'allowed origins must be strings', 'origin', pattern);
  }
  try {
    assertSafeHeaderValue(pattern, 'origin', { forbidSemicolon: true, forbidComma: true });
  } catch (error) {
    if (error.code === CODE.CRLF || error.code === CODE.CONTROL_CHARACTER) throw error;
    fail(CODE.CORS_CONFIG, 'allowed origin contains unsafe characters', 'origin', pattern);
  }
  if (pattern === '*') {
    if (!allowWildcard) {
      fail(CODE.CORS_CONFIG, 'wildcard origin must be configured with origin: "*"', 'origin', pattern);
    }
    return pattern;
  }
  if (pattern.indexOf('[') !== -1 || pattern.indexOf(']') !== -1) {
    fail(CODE.CORS_CONFIG, 'IP literal patterns are not supported', 'origin', pattern);
  }
  const prefix = 'https://*.';
  if (!pattern.startsWith(prefix)) {
    try {
      return validateOriginString(pattern, 'origin', false);
    } catch (error) {
      fail(CODE.CORS_CONFIG, 'invalid allowed origin pattern', 'origin', pattern);
    }
  }
  const normalized = pattern;
  const star = normalized.indexOf('*');
  if (star !== prefix.indexOf('*')) {
    fail(CODE.CORS_CONFIG, 'wildcard patterns must use https://*.example.com form', 'origin', pattern);
  }
  const suffix = normalized.slice(prefix.length);
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(suffix) || suffix.indexOf('..') !== -1) {
    fail(CODE.CORS_CONFIG, 'invalid wildcard pattern suffix', 'origin', pattern);
  }
  return normalized;
}

function matchesOriginPattern(pattern, origin) {
  if (pattern === '*') return true;
  if (pattern.indexOf('*') === -1) return pattern === origin;
  const suffix = pattern.slice('https://*.'.length);
  if (!origin.startsWith('https://')) return false;
  const host = origin.slice('https://'.length);
  if (host.indexOf(':') !== -1 || host.indexOf('.') === -1) return false;
  return host.endsWith('.' + suffix);
}

export function createCorsPolicy(config = {}) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    fail(CODE.CORS_CONFIG, 'CORS config must be an object', 'config', config);
  }
  const credentials = config.credentials === true;
  const allowNullOrigin = config.allowNullOrigin === true;
  const rawOrigin = config.origin === undefined ? [] : config.origin;
  const allowWildcard = rawOrigin === '*' || (Array.isArray(rawOrigin) && rawOrigin.indexOf('*') !== -1);
  if (credentials && allowWildcard) {
    fail(CODE.CORS_CONFIG, 'wildcard origin cannot be combined with credentials', 'origin', rawOrigin);
  }
  if (typeof rawOrigin === 'function') {
    if (config.allowCustomValidator !== true) {
      fail(CODE.CORS_CONFIG, 'custom origin validators require allowCustomValidator: true', 'origin', rawOrigin);
    }
  } else if (typeof rawOrigin === 'boolean') {
    fail(CODE.CORS_CONFIG, 'origin must be a string, array, function or omitted', 'origin', rawOrigin);
  }

  const patterns = typeof rawOrigin === 'function' ? [] : (Array.isArray(rawOrigin) ? rawOrigin : [rawOrigin]).map((p) => validateAllowedOriginPattern(p, true));
  const methods = config.methods === undefined ? ['GET', 'HEAD', 'POST'] : config.methods;
  const allowedHeaders = config.allowedHeaders === undefined ? ['Content-Type'] : config.allowedHeaders;
  const exposedHeaders = config.exposedHeaders === undefined ? [] : config.exposedHeaders;
  const maxAge = config.maxAge === undefined ? 600 : config.maxAge;

  for (const [field, list] of [['methods', methods], ['allowedHeaders', allowedHeaders], ['exposedHeaders', exposedHeaders]]) {
    if (!Array.isArray(list)) fail(CODE.CORS_CONFIG, field + ' must be an array of strings', field, list);
    for (const item of list) {
      try {
        assertSafeHeaderValue(item, field, { forbidSemicolon: true });
      } catch (error) {
        if (error.code === CODE.CRLF || error.code === CODE.CONTROL_CHARACTER) throw error;
        fail(CODE.CORS_CONFIG, 'unsafe character in ' + field, field, item);
      }
      if (!TOKEN_RE.test(item) && item !== '*') {
        fail(CODE.CORS_CONFIG, 'invalid token in ' + field, field, item);
      }
    }
  }
  if (!Number.isInteger(maxAge) || maxAge < 0 || maxAge > 86400) {
    fail(CODE.CORS_CONFIG, 'maxAge must be an integer between 0 and 86400', 'maxAge', maxAge);
  }

  function isAllowed(input) {
    if (input === undefined || input === null) return false;
    let origin;
    try {
      origin = validateOriginString(input, 'origin', allowNullOrigin);
    } catch (error) {
      return false;
    }
    if (origin === 'null') return allowNullOrigin;
    if (origin === '*') return patterns.indexOf('*') !== -1;
    if (typeof rawOrigin === 'function') {
      let decision;
      try {
        decision = rawOrigin(origin);
      } catch (error) {
        return false;
      }
      return decision === true;
    }
    return patterns.some((pattern) => matchesOriginPattern(pattern, origin));
  }

  function assertAllowed(origin) {
    if (!isAllowed(origin)) {
      fail(CODE.CORS_ORIGIN, 'origin is not allowed by this CORS policy', 'origin', origin);
    }
    return validateOriginString(origin, 'origin', allowNullOrigin);
  }

  function headers(origin, options = {}) {
    const result = { Vary: 'Origin' };
    const allowed = isAllowed(origin);
    if (allowed) {
      const effective = validateOriginString(origin, 'origin', allowNullOrigin);
      result['Access-Control-Allow-Origin'] = patterns.indexOf('*') !== -1 && effective !== '*' && origin !== 'null' ? '*' : effective;
      if (credentials) result['Access-Control-Allow-Credentials'] = 'true';
      if (options.preflight === true) {
        result['Access-Control-Allow-Methods'] = methods.join(', ');
        result['Access-Control-Allow-Headers'] = allowedHeaders.join(', ');
        result['Access-Control-Max-Age'] = String(maxAge);
      }
      if (exposedHeaders.length > 0 && options.preflight !== true) {
        result['Access-Control-Expose-Headers'] = exposedHeaders.join(', ');
      }
    }
    if (options.strict === true && !allowed) {
      fail(CODE.CORS_ORIGIN, 'origin is not allowed by this CORS policy', 'origin', origin);
    }
    for (const name of Object.keys(result)) {
      assertSafeHeaderName(name, 'corsHeaderName');
      assertSafeHeaderValue(result[name], name, { forbidSemicolon: true });
    }
    return result;
  }

  function apply(target, origin, options = {}) {
    const result = headers(origin, options);
    return applyHeaderRecord(target, result);
  }

  return Object.freeze({
    config: Object.freeze({
      credentials,
      allowNullOrigin,
      wildcard: allowWildcard,
      patterns: Object.freeze(patterns.slice()),
      methods: Object.freeze(methods.slice()),
      allowedHeaders: Object.freeze(allowedHeaders.slice()),
      exposedHeaders: Object.freeze(exposedHeaders.slice()),
      maxAge
    }),
    isAllowed,
    assertAllowed,
    headers,
    apply
  });
}

export function validateCorsOrigin(origin, options = {}) {
  const allowNull = options.allowNullOrigin === true;
  return validateOriginString(origin, 'origin', allowNull);
}

/* --------------------------------------------------------------- COOKIES */

function assertCookieName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.startsWith('$')) {
    fail(CODE.COOKIE_NAME, 'cookie name must be a non-empty string not starting with ' + '$', 'name', name);
  }
  try {
    assertSafeHeaderValue(name, 'name', { forbidSemicolon: true });
  } catch (error) {
    if (error.code === CODE.CRLF || error.code === CODE.CONTROL_CHARACTER) throw error;
    fail(CODE.COOKIE_NAME, 'cookie name contains unsafe characters', 'name', name);
  }
  if (!TOKEN_RE.test(name)) {
    fail(CODE.COOKIE_NAME, 'cookie name contains invalid token characters', 'name', name);
  }
  return name;
}

function assertCookieValue(value) {
  if (typeof value !== 'string') {
    fail(CODE.COOKIE_VALUE, 'cookie value must be a string', 'value', value);
  }
  try {
    assertSafeHeaderValue(value, 'value', { forbidSemicolon: true });
  } catch (error) {
    if (error.code === CODE.CRLF || error.code === CODE.CONTROL_CHARACTER) throw error;
    fail(CODE.COOKIE_VALUE, 'cookie value contains unsafe characters', 'value', value);
  }
  if (!COOKIE_OCTET_RE.test(value)) {
    fail(CODE.COOKIE_VALUE, 'cookie value contains characters that need encoding', 'value', value);
  }
  return value;
}

function assertCookiePath(path) {
  if (typeof path !== 'string' || path.length === 0 || path[0] !== '/') {
    fail(CODE.COOKIE_ATTRIBUTE, 'cookie Path must start with /', 'path', path);
  }
  try {
    assertSafeHeaderValue(path, 'path', { forbidSemicolon: true });
  } catch (error) {
    if (error.code === CODE.CRLF || error.code === CODE.CONTROL_CHARACTER) throw error;
    fail(CODE.COOKIE_ATTRIBUTE, 'cookie Path contains unsafe characters', 'path', path);
  }
  return path;
}

function assertCookieDomain(domain) {
  if (typeof domain !== 'string' || domain.length === 0) {
    fail(CODE.COOKIE_ATTRIBUTE, 'cookie Domain must be a non-empty string', 'domain', domain);
  }
  try {
    assertSafeHeaderValue(domain, 'domain', { forbidSemicolon: true });
  } catch (error) {
    if (error.code === CODE.CRLF || error.code === CODE.CONTROL_CHARACTER) throw error;
    fail(CODE.COOKIE_ATTRIBUTE, 'cookie Domain contains unsafe characters', 'domain', domain);
  }
  if (domain.indexOf(':') !== -1 || domain.indexOf('/') !== -1 || domain.indexOf('@') !== -1 || domain.indexOf(' ') !== -1) {
    fail(CODE.COOKIE_ATTRIBUTE, 'cookie Domain must be a bare hostname', 'domain', domain);
  }
  const candidate = domain[0] === '.' ? domain.slice(1) : domain;
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(candidate) && candidate !== 'localhost') {
    fail(CODE.COOKIE_ATTRIBUTE, 'invalid cookie Domain', 'domain', domain);
  }
  return domain;
}

export function serializeSafeCookie(name, value, options = {}) {
  assertCookieName(name);
  assertCookieValue(value);
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    fail(CODE.INVALID_INPUT, 'cookie options must be an object', 'options', options);
  }
  const secure = options.secure !== false;
  const httpOnly = options.httpOnly !== false;
  const sameSite = options.sameSite === undefined ? 'Lax' : options.sameSite;
  if (sameSite !== 'Lax' && sameSite !== 'Strict' && sameSite !== 'None') {
    fail(CODE.COOKIE_ATTRIBUTE, 'SameSite must be Lax, Strict or None', 'sameSite', sameSite);
  }
  if (sameSite === 'None' && !secure) {
    fail(CODE.COOKIE_ATTRIBUTE, 'SameSite=None requires Secure', 'sameSite', sameSite);
  }
  const path = options.path === undefined ? '/' : assertCookiePath(options.path);
  const domain = options.domain === undefined ? undefined : assertCookieDomain(options.domain);

  if (name.startsWith('__Host-')) {
    if (!secure) fail(CODE.COOKIE_PREFIX, '__Host- cookies require Secure', 'name', name);
    if (path !== '/') fail(CODE.COOKIE_PREFIX, '__Host- cookies require Path=/', 'path', path);
    if (domain !== undefined) fail(CODE.COOKIE_PREFIX, '__Host- cookies must not set Domain', 'domain', domain);
  }
  if (name.startsWith('__Secure-') && !secure) {
    fail(CODE.COOKIE_PREFIX, '__Secure- cookies require Secure', 'name', name);
  }
  if (options.partitioned === true && !secure) {
    fail(CODE.COOKIE_ATTRIBUTE, 'Partitioned cookies require Secure', 'partitioned', options.partitioned);
  }

  const parts = [name + '=' + value];
  if (domain !== undefined) parts.push('Domain=' + domain);
  parts.push('Path=' + path);
  if (options.maxAge !== undefined) {
    if (!Number.isInteger(options.maxAge) || options.maxAge < 0) {
      fail(CODE.COOKIE_ATTRIBUTE, 'Max-Age must be a non-negative integer', 'maxAge', options.maxAge);
    }
    parts.push('Max-Age=' + String(options.maxAge));
  }
  if (options.expires !== undefined) {
    let expires;
    if (options.expires instanceof Date) {
      if (Number.isNaN(options.expires.getTime())) {
        fail(CODE.COOKIE_ATTRIBUTE, 'Expires date is invalid', 'expires', options.expires);
      }
      expires = options.expires.toUTCString();
    } else {
      expires = assertSafeHeaderValue(options.expires, 'expires', { forbidSemicolon: true });
      if (Number.isNaN(new Date(expires).getTime())) {
        fail(CODE.COOKIE_ATTRIBUTE, 'Expires must be a valid date', 'expires', options.expires);
      }
    }
    parts.push('Expires=' + expires);
  }
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  parts.push('SameSite=' + sameSite);
  if (options.priority !== undefined) {
    if (options.priority !== 'Low' && options.priority !== 'Medium' && options.priority !== 'High') {
      fail(CODE.COOKIE_ATTRIBUTE, 'Priority must be Low, Medium or High', 'priority', options.priority);
    }
    parts.push('Priority=' + options.priority);
  }
  if (options.partitioned === true) parts.push('Partitioned');
  const serialized = parts.join('; ');
  assertSafeHeaderValue(serialized, 'Set-Cookie');
  return serialized;
}

export function parseSetCookie(header, field = 'setCookie') {
  assertSafeHeaderValue(header, field);
  const pieces = header.split(';');
  const pair = (pieces[0] || '').trim();
  const equals = pair.indexOf('=');
  if (equals <= 0) {
    fail(CODE.COOKIE_NAME, 'Set-Cookie is missing a name=value pair', field, header);
  }
  const name = pair.slice(0, equals).trim();
  const value = pair.slice(equals + 1).trim();
  const attributes = {};
  for (const piece of pieces.slice(1)) {
    const trimmed = piece.trim();
    if (trimmed === '') continue;
    const split = trimmed.indexOf('=');
    const key = (split === -1 ? trimmed : trimmed.slice(0, split)).trim().toLowerCase();
    const val = split === -1 ? true : trimmed.slice(split + 1).trim();
    attributes[key] = val;
  }
  return { name, value, attributes };
}

export function auditSetCookie(header) {
  const parsed = parseSetCookie(header);
  const findings = [];
  function add(id, severity, message, recommendation) {
    findings.push({ id, severity, message, recommendation });
  }
  if (!TOKEN_RE.test(parsed.name)) {
    add('INVALID_NAME', 'critical', 'Cookie name is not a valid token.', 'Use an ASCII token without separators or control characters.');
  }
  if (!COOKIE_OCTET_RE.test(parsed.value)) {
    add('INVALID_VALUE', 'critical', 'Cookie value contains unsafe characters.', 'Percent encode the value before serialization.');
  }
  if (parsed.attributes.secure !== true) {
    add('MISSING_SECURE', 'critical', 'Secure attribute is missing.', 'Always set Secure on cookies sent over HTTPS.');
  }
  if (parsed.attributes.httponly !== true) {
    add('MISSING_HTTPONLY', 'warning', 'HttpOnly attribute is missing.', 'Set HttpOnly to keep the cookie away from scripts.');
  }
  const sameSite = typeof parsed.attributes.samesite === 'string' ? parsed.attributes.samesite.toLowerCase() : undefined;
  if (sameSite === undefined) {
    add('MISSING_SAMESITE', 'warning', 'SameSite attribute is missing.', 'Set SameSite=Lax or SameSite=Strict.');
  } else if (sameSite === 'none' && parsed.attributes.secure !== true) {
    add('SAMESITE_NONE_WITHOUT_SECURE', 'critical', 'SameSite=None requires Secure.', 'Add the Secure attribute or use SameSite=Lax.');
  } else if (sameSite !== 'lax' && sameSite !== 'strict' && sameSite !== 'none') {
    add('INVALID_SAMESITE', 'warning', 'SameSite value is not recognized.', 'Use Lax, Strict or None.');
  }
  const path = parsed.attributes.path;
  if (parsed.name.startsWith('__Host-')) {
    if (parsed.attributes.secure !== true) {
      add('__HOST_MISSING_SECURE', 'critical', '__Host- prefix requires Secure.', 'Add the Secure attribute.');
    }
    if (path !== '/') {
      add('__HOST_PATH_NOT_ROOT', 'critical', '__Host- prefix requires Path=/.', 'Set Path=/ on this cookie.');
    }
    if (parsed.attributes.domain !== undefined) {
      add('__HOST_HAS_DOMAIN', 'critical', '__Host- prefix forbids Domain.', 'Remove the Domain attribute.');
    }
  }
  if (parsed.name.startsWith('__Secure-') && parsed.attributes.secure !== true) {
    add('__SECURE_MISSING_SECURE', 'critical', '__Secure- prefix requires Secure.', 'Add the Secure attribute.');
  }
  if (parsed.attributes.domain !== undefined && typeof parsed.attributes.domain === 'string') {
    try {
      assertCookieDomain(parsed.attributes.domain);
    } catch (error) {
      add('INVALID_DOMAIN', 'warning', 'Domain attribute is not a bare hostname.', 'Use a hostname without scheme, port or path.');
    }
  }
  const weights = { critical: 25, warning: 10, info: 3 };
  let score = 100;
  for (const finding of findings) score -= weights[finding.severity];
  if (score < 0) score = 0;
  return {
    name: parsed.name,
    value: parsed.value,
    attributes: parsed.attributes,
    prefix: parsed.name.startsWith('__Host-') ? '__Host-' : (parsed.name.startsWith('__Secure-') ? '__Secure-' : null),
    ok: !findings.some((f) => f.severity === 'critical'),
    score,
    findings
  };
}

/* --------------------------------------------------------------- HEADERS */

const REFERRER_POLICIES = new Set([
  'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
  'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'
]);

const DEFAULT_PERMISSIONS = Object.freeze({
  camera: [], microphone: [], geolocation: [], payment: [], usb: [],
  accelerometer: [], gyroscope: [], magnetometer: [], autoplay: []
});

function serializePermissionsPolicy(policy, allowWildcard) {
  if (policy === false) return undefined;
  const source = policy === undefined || policy === true ? DEFAULT_PERMISSIONS : policy;
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    fail(CODE.INVALID_INPUT, 'permissionsPolicy must be an object', 'permissionsPolicy', policy);
  }
  const parts = [];
  for (const feature of Object.keys(source).sort()) {
    if (!TOKEN_RE.test(feature)) {
      fail(CODE.INVALID_INPUT, 'invalid Permissions-Policy feature name', 'permissionsPolicy', feature);
    }
    const raw = source[feature];
    if (raw === undefined) continue;
    const allowlist = typeof raw === 'string' ? [raw] : (Array.isArray(raw) ? raw : []);
    const tokens = [];
    for (const entry of allowlist) {
      assertSafeHeaderValue(entry, 'permissionsPolicy', { forbidSemicolon: true });
      if (entry === '*') {
        if (!allowWildcard) {
          fail(CODE.INVALID_INPUT, 'wildcard Permissions-Policy allowlist requires allowWildcardPermissions: true', 'permissionsPolicy', feature);
        }
        tokens.push('*');
      } else if (entry === 'self') {
        tokens.push('self');
      } else {
        const normalized = validateOriginString(entry, 'permissionsPolicy', false);
        tokens.push('"' + normalized + '"');
      }
    }
    parts.push(feature + '=(' + tokens.join(' ') + ')');
  }
  return parts.join(', ');
}

export function buildSecurityHeaders(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    fail(CODE.INVALID_INPUT, 'security header options must be an object', 'options', options);
  }
  const result = {};

  if (options.hsts !== false) {
    const hsts = options.hsts === undefined || options.hsts === true ? {} : options.hsts;
    if (typeof hsts !== 'object' || hsts === null || Array.isArray(hsts)) {
      fail(CODE.INVALID_INPUT, 'hsts must be an object or false', 'hsts', hsts);
    }
    const maxAge = hsts.maxAge === undefined ? 31536000 : hsts.maxAge;
    if (!Number.isInteger(maxAge) || maxAge < 0) {
      fail(CODE.INVALID_INPUT, 'HSTS maxAge must be a non-negative integer', 'hsts.maxAge', maxAge);
    }
    let value = 'max-age=' + String(maxAge);
    if (hsts.includeSubDomains === true) value += '; includeSubDomains';
    if (hsts.preload === true) value += '; preload';
    assertSafeHeaderValue(value, 'Strict-Transport-Security');
    result['Strict-Transport-Security'] = value;
  }

  if (options.contentTypeOptions !== false) {
    result['X-Content-Type-Options'] = 'nosniff';
  }

  const referrerPolicy = options.referrerPolicy === undefined ? 'no-referrer' : options.referrerPolicy;
  if (referrerPolicy !== false) {
    if (typeof referrerPolicy !== 'string' || !REFERRER_POLICIES.has(referrerPolicy)) {
      fail(CODE.INVALID_INPUT, 'unsupported or unsafe Referrer-Policy', 'referrerPolicy', referrerPolicy);
    }
    result['Referrer-Policy'] = referrerPolicy;
  }

  const permissions = serializePermissionsPolicy(options.permissionsPolicy, options.allowWildcardPermissions === true);
  if (permissions !== undefined) result['Permissions-Policy'] = permissions;

  const coop = options.crossOriginOpenerPolicy === undefined ? 'same-origin' : options.crossOriginOpenerPolicy;
  if (coop !== false) {
    if (coop !== 'same-origin' && coop !== 'same-origin-allow-popups' && !(coop === 'unsafe-none' && options.allowUnsafeNone === true)) {
      fail(CODE.INVALID_INPUT, 'unsupported Cross-Origin-Opener-Policy', 'crossOriginOpenerPolicy', coop);
    }
    result['Cross-Origin-Opener-Policy'] = coop;
  }

  const corp = options.crossOriginResourcePolicy === undefined ? 'same-origin' : options.crossOriginResourcePolicy;
  if (corp !== false) {
    if (corp !== 'same-origin' && corp !== 'same-site' && corp !== 'cross-origin') {
      fail(CODE.INVALID_INPUT, 'unsupported Cross-Origin-Resource-Policy', 'crossOriginResourcePolicy', corp);
    }
    result['Cross-Origin-Resource-Policy'] = corp;
  }

  const coep = options.crossOriginEmbedderPolicy === undefined ? 'require-corp' : options.crossOriginEmbedderPolicy;
  if (coep !== false) {
    if (coep !== 'require-corp' && coep !== 'credentialless' && !(coep === 'unsafe-none' && options.allowUnsafeNone === true)) {
      fail(CODE.INVALID_INPUT, 'unsupported Cross-Origin-Embedder-Policy', 'crossOriginEmbedderPolicy', coep);
    }
    result['Cross-Origin-Embedder-Policy'] = coep;
  }

  const frameOptions = options.frameOptions === undefined ? 'DENY' : options.frameOptions;
  if (frameOptions !== false) {
    if (frameOptions !== 'DENY' && frameOptions !== 'SAMEORIGIN') {
      fail(CODE.INVALID_INPUT, 'X-Frame-Options must be DENY or SAMEORIGIN', 'frameOptions', frameOptions);
    }
    result['X-Frame-Options'] = frameOptions;
  }

  const csp = options.csp === undefined ? { preset: 'strict' } : options.csp;
  if (csp !== false && csp !== null) {
    let built;
    if (typeof csp === 'string') {
      built = buildCsp(csp);
    } else if (csp.policy !== undefined) {
      built = buildCsp(csp.policy, csp);
    } else {
      const policy = {};
      for (const key of Object.keys(csp)) {
        if (key !== 'reportOnly' && key !== 'nonces' && key !== 'hashes' && key !== 'strictDynamic' && key !== 'preset') policy[key] = csp[key];
      }
      built = buildCsp(policy, csp);
    }
    result[csp.reportOnly === true ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy'] = built;
  }

  for (const name of Object.keys(result)) {
    assertSafeHeaderName(name, 'headerName');
    assertSafeHeaderValue(result[name], name);
  }
  return Object.freeze(result);
}

export function isNodeResponse(target) {
  return !!target && typeof target.setHeader === 'function' && typeof target.getHeader === 'function';
}

export function isFetchHeaders(target) {
  return !!target && typeof target.set === 'function' && typeof target.get === 'function' &&
    typeof target.append === 'function' && typeof target.forEach === 'function' &&
    typeof target.delete === 'function';
}

export function applyHeaderRecord(target, record, options = {}) {
  if (record === null || typeof record !== 'object') {
    fail(CODE.INVALID_INPUT, 'header record must be an object', 'headers', record);
  }
  const entries = Object.keys(record);
  for (const name of entries) {
    assertSafeHeaderName(name, 'headerName');
    assertSafeHeaderValue(record[name], name);
  }
  if (isNodeResponse(target)) {
    for (const name of entries) {
      if (name.toLowerCase() === 'vary') {
        target.setHeader(name, mergeVary(target.getHeader('Vary'), record[name]));
      } else {
        target.setHeader(name, record[name]);
      }
    }
    return target;
  }
  if (isFetchHeaders(target)) {
    for (const name of entries) {
      if (name.toLowerCase() === 'vary') {
        target.set(name, mergeVary(target.get(name), record[name]));
      } else {
        target.set(name, record[name]);
      }
    }
    return target;
  }
  if (options.strict === true) {
    fail(CODE.INVALID_INPUT, 'target is neither a Node response nor Fetch Headers', 'target', target);
  }
  if (target && typeof target === 'object') {
    for (const name of entries) {
      if (name.toLowerCase() === 'vary') {
        target[name] = mergeVary(target[name], record[name]);
      } else {
        target[name] = record[name];
      }
    }
    return target;
  }
  fail(CODE.INVALID_INPUT, 'target must be a Node response, Fetch Headers or plain object', 'target', target);
}

export function applySecurityHeaders(target, options = {}) {
  return applyHeaderRecord(target, buildSecurityHeaders(options));
}

export function toFetchHeaders(record, options = {}) {
  const HeadersCtor = options.Headers || (typeof Headers !== 'undefined' ? Headers : undefined);
  if (typeof HeadersCtor !== 'function') {
    fail(CODE.INVALID_INPUT, 'Fetch Headers constructor is not available', 'Headers', undefined);
  }
  const headers = new HeadersCtor();
  return applyHeaderRecord(headers, record, { strict: true });
}

export function fromFetchHeaders(headers) {
  if (!isFetchHeaders(headers)) {
    fail(CODE.INVALID_INPUT, 'expected Fetch Headers', 'headers', headers);
  }
  const result = {};
  if (typeof headers.forEach === 'function') {
    headers.forEach((value, name) => { result[name] = value; });
  }
  return result;
}

export function withSecurityHeaders(handler, options = {}) {
  if (typeof handler !== 'function') {
    fail(CODE.INVALID_INPUT, 'handler must be a function', 'handler', handler);
  }
  const headers = buildSecurityHeaders(options);
  return function headersafeHandler(...args) {
    const res = args.length >= 2 && isNodeResponse(args[1]) ? args[1] : null;
    if (res) applyHeaderRecord(res, headers);
    const outcome = handler.apply(this, args);
    if (res) return outcome;
    if (outcome && typeof outcome.then === 'function') {
      return outcome.then((value) => wrapFetchResponse(value, headers));
    }
    return wrapFetchResponse(outcome, headers);
  };
}

function seedFetchHeaders(source) {
  const merged = new Headers();
  let copiedSetCookie = false;
  if (source && typeof source.getSetCookie === 'function') {
    const cookies = source.getSetCookie();
    if (Array.isArray(cookies) && cookies.length > 0) {
      for (const cookie of cookies) merged.append('set-cookie', cookie);
      copiedSetCookie = true;
    }
  }
  if (source && typeof source.forEach === 'function') {
    source.forEach((value, name) => {
      if (copiedSetCookie && String(name).toLowerCase() === 'set-cookie') return;
      merged.append(name, value);
    });
  }
  return merged;
}

function wrapFetchResponse(response, headers) {
  if (!response || typeof response.headers === 'undefined' || typeof response.arrayBuffer !== 'function') {
    return response;
  }
  const merged = seedFetchHeaders(response.headers);
  applyHeaderRecord(merged, headers, { strict: true });
  const init = {
    status: response.status,
    statusText: response.statusText,
    headers: merged
  };
  return new Response(response.body, init);
}
