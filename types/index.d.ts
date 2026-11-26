/** Error codes thrown by every headersafe API. */
export declare const CODE: Readonly<{
  INVALID_INPUT: 'ERR_HEADSAFE_INVALID_INPUT';
  HEADER_NAME: 'ERR_HEADSAFE_HEADER_NAME';
  HEADER_VALUE: 'ERR_HEADSAFE_HEADER_VALUE';
  CRLF: 'ERR_HEADSAFE_CRLF';
  CONTROL_CHARACTER: 'ERR_HEADSAFE_CONTROL_CHARACTER';
  CSP_DIRECTIVE: 'ERR_HEADSAFE_CSP_DIRECTIVE';
  CSP_SOURCE: 'ERR_HEADSAFE_CSP_SOURCE';
  CORS_CONFIG: 'ERR_HEADSAFE_CORS_CONFIG';
  CORS_ORIGIN: 'ERR_HEADSAFE_CORS_ORIGIN';
  COOKIE_NAME: 'ERR_HEADSAFE_COOKIE_NAME';
  COOKIE_VALUE: 'ERR_HEADSAFE_COOKIE_VALUE';
  COOKIE_ATTRIBUTE: 'ERR_HEADSAFE_COOKIE_ATTRIBUTE';
  COOKIE_PREFIX: 'ERR_HEADSAFE_COOKIE_PREFIX';
  RNG: 'ERR_HEADSAFE_RNG';
}>;

export type HeaderSafeCode = (typeof CODE)[keyof typeof CODE];

/** Typed error for every rejection made by this package. */
export declare class HeaderSafeError extends Error {
  readonly name: 'HeaderSafeError';
  readonly code: HeaderSafeCode;
  readonly reason: string;
  readonly field: string | undefined;
  readonly value: unknown;
  constructor(code: HeaderSafeCode, reason: string, field?: string, value?: unknown);
  toJSON(): {
    name: 'HeaderSafeError';
    code: HeaderSafeCode;
    reason: string;
    field: string | undefined;
    value: unknown;
  };
}

export declare function assertSafeHeaderName(name: string, field?: string): string;
export declare function assertSafeHeaderValue(
  value: string,
  field?: string,
  options?: { forbidSemicolon?: boolean; forbidComma?: boolean }
): string;
export declare function hasCrlf(value: string): boolean;
export declare function mergeVary(existing: string | readonly string[] | null | undefined, addition?: string): string;

/* ------------------------------------------------------------------ CSP */

export type CspSeverity = 'critical' | 'warning' | 'info';
export type CspPreset = 'strict' | 'balanced';

export interface CspHashSource {
  algorithm: 'sha256' | 'sha384' | 'sha512';
  value: string;
}

export interface CspBuildOptions {
  preset?: CspPreset;
  nonces?: string | string[];
  hashes?: (string | CspHashSource)[] | string | CspHashSource;
  strictDynamic?: boolean;
}

export type CspDirectiveValue = string | boolean | readonly (string | boolean)[];
export type CspPolicy = Readonly<Record<string, CspDirectiveValue>> | string | readonly (Readonly<Record<string, CspDirectiveValue>> | string)[];

export interface CspFinding {
  id: string;
  severity: CspSeverity;
  directive: string;
  message: string;
  recommendation: string;
}

export interface CspAudit {
  ok: boolean;
  score: number;
  findings: CspFinding[];
  directives: Record<string, string[]>;
}

export declare function buildCsp(policy?: CspPolicy, options?: CspBuildOptions): string;
export declare function parseCsp(header: string, field?: string): Record<string, string[]>;
export declare function auditCsp(input: string | CspPolicy, options?: CspBuildOptions): CspAudit;
export declare function generateNonce(size?: number): string;

/* ----------------------------------------------------------------- CORS */

export type CorsOriginValidator = (origin: string) => boolean;

export interface CorsPolicyConfig {
  /** Exact origin, https://*.example.com subdomain pattern, array of these, "*", or a validator. */
  origin?: string | readonly string[] | CorsOriginValidator;
  credentials?: boolean;
  allowNullOrigin?: boolean;
  allowCustomValidator?: boolean;
  methods?: readonly string[];
  allowedHeaders?: readonly string[];
  exposedHeaders?: readonly string[];
  maxAge?: number;
}

export interface CorsPolicyOptions {
  preflight?: boolean;
  strict?: boolean;
}

export interface CorsPolicy {
  readonly config: Readonly<{
    credentials: boolean;
    allowNullOrigin: boolean;
    wildcard: boolean;
    patterns: readonly string[];
    methods: readonly string[];
    allowedHeaders: readonly string[];
    exposedHeaders: readonly string[];
    maxAge: number;
  }>;
  isAllowed(origin: string | null | undefined): boolean;
  assertAllowed(origin: string): string;
  headers(origin: string | null | undefined, options?: CorsPolicyOptions): Record<string, string>;
  apply(target: HeaderTarget, origin: string | null | undefined, options?: CorsPolicyOptions): HeaderTarget;
}

export declare function createCorsPolicy(config?: CorsPolicyConfig): CorsPolicy;
export declare function validateCorsOrigin(origin: string, options?: { allowNullOrigin?: boolean }): string;

/* --------------------------------------------------------------- COOKIES */

export interface SafeCookieOptions {
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
  path?: string;
  domain?: string;
  maxAge?: number;
  expires?: Date | string;
  priority?: 'Low' | 'Medium' | 'High';
  partitioned?: boolean;
}

export interface ParsedCookie {
  name: string;
  value: string;
  attributes: Record<string, string | true>;
}

export interface CookieFinding {
  id: string;
  severity: CspSeverity;
  message: string;
  recommendation: string;
}

export interface CookieAudit extends ParsedCookie {
  prefix: '__Host-' | '__Secure-' | null;
  ok: boolean;
  score: number;
  findings: CookieFinding[];
}

export declare function serializeSafeCookie(name: string, value: string, options?: SafeCookieOptions): string;
export declare function parseSetCookie(header: string, field?: string): ParsedCookie;
export declare function auditSetCookie(header: string): CookieAudit;

/* --------------------------------------------------------------- HEADERS */

export interface HstsOptions {
  maxAge?: number;
  includeSubDomains?: boolean;
  preload?: boolean;
}

export interface SecurityHeaderOptions {
  hsts?: HstsOptions | false;
  contentTypeOptions?: false;
  referrerPolicy?: string | false;
  permissionsPolicy?: Record<string, string | readonly string[]> | true | false;
  allowWildcardPermissions?: boolean;
  crossOriginOpenerPolicy?: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none' | false;
  crossOriginResourcePolicy?: 'same-origin' | 'same-site' | 'cross-origin' | false;
  crossOriginEmbedderPolicy?: 'require-corp' | 'credentialless' | 'unsafe-none' | false;
  allowUnsafeNone?: boolean;
  frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  csp?: CspPolicy | (CspBuildOptions & { policy?: CspPolicy; reportOnly?: boolean }) | false;
}

/** Node http.ServerResponse, Fetch Headers, or a plain record. */
export type HeaderTarget =
  | { setHeader(name: string, value: string): unknown; getHeader(name: string): unknown }
  | { set(name: string, value: string): unknown; get(name: string): string | null; append(name: string, value: string): unknown }
  | Record<string, string>;

export declare function buildSecurityHeaders(options?: SecurityHeaderOptions): Readonly<Record<string, string>>;
export declare function applyHeaderRecord(target: HeaderTarget, record: Record<string, string>, options?: { strict?: boolean }): HeaderTarget;
export declare function applySecurityHeaders(target: HeaderTarget, options?: SecurityHeaderOptions): HeaderTarget;
export declare function toFetchHeaders(record: Record<string, string>, options?: { Headers?: new () => any }): any;
export declare function fromFetchHeaders(headers: any): Record<string, string>;
export declare function isNodeResponse(target: unknown): boolean;
export declare function isFetchHeaders(target: unknown): boolean;
export declare function withSecurityHeaders<T extends (...args: any[]) => any>(handler: T, options?: SecurityHeaderOptions): T;

declare const headersafe: {
  CODE: typeof CODE;
  HeaderSafeError: typeof HeaderSafeError;
  assertSafeHeaderName: typeof assertSafeHeaderName;
  assertSafeHeaderValue: typeof assertSafeHeaderValue;
  hasCrlf: typeof hasCrlf;
  mergeVary: typeof mergeVary;
  buildCsp: typeof buildCsp;
  parseCsp: typeof parseCsp;
  auditCsp: typeof auditCsp;
  generateNonce: typeof generateNonce;
  createCorsPolicy: typeof createCorsPolicy;
  validateCorsOrigin: typeof validateCorsOrigin;
  serializeSafeCookie: typeof serializeSafeCookie;
  parseSetCookie: typeof parseSetCookie;
  auditSetCookie: typeof auditSetCookie;
  buildSecurityHeaders: typeof buildSecurityHeaders;
  applyHeaderRecord: typeof applyHeaderRecord;
  applySecurityHeaders: typeof applySecurityHeaders;
  toFetchHeaders: typeof toFetchHeaders;
  fromFetchHeaders: typeof fromFetchHeaders;
  isNodeResponse: typeof isNodeResponse;
  isFetchHeaders: typeof isFetchHeaders;
  withSecurityHeaders: typeof withSecurityHeaders;
};

export default headersafe;
