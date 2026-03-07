import type { SessionHandle, StringFieldRef } from '../providers/types.js';
import { isSecretTypeEnabled, type DetectionOptions } from './options.js';
import type { DetectionSpan, SessionFinding } from './types.js';
import {
  AUTHORIZATION_HEADER_PATTERN,
  BARE_BEARER_TOKEN_PATTERN,
  BASE64_SECRET_PATTERN,
  BASIC_AUTH_PATTERN,
  COOKIE_PATTERN,
  EMAIL_PATTERN,
  JSON_LIKE_PREFIX,
  JWT_PATTERN,
  PATH_USERNAME_PATTERNS,
  PRIVATE_KEY_PATTERN,
  RAW_TOKEN_PATTERN,
  SENSITIVE_ASSIGNMENT_PATTERN,
  SIGNED_QUERY_PATTERN,
  URL_CREDENTIALS_PATTERN,
} from './patterns.js';
import { applyReplacements, fingerprintSecret, maskEmail, maskPrivateKey, maskToken, maskUsername } from './mask.js';

function cloneRegex(pattern: RegExp): RegExp {
  return new RegExp(pattern.source, pattern.flags);
}

function addSpan(
  spans: DetectionSpan[],
  options: {
    type: DetectionSpan['type'];
    start: number;
    end: number;
    rawValue: string;
    replacement: string;
    confidence: number;
  },
): void {
  if (options.rawValue.trim().length === 0) {
    return;
  }

  spans.push({
    ...options,
    preview: options.replacement,
    fingerprint: fingerprintSecret(options.rawValue),
  });
}

function collectPatternMatches(
  text: string,
  pattern: RegExp,
  visitor: (match: RegExpExecArray, spans: DetectionSpan[]) => void,
  spans: DetectionSpan[],
): void {
  const regex = cloneRegex(pattern);
  let match = regex.exec(text);

  while (match !== null) {
    visitor(match, spans);
    match = regex.exec(text);
  }
}

function dedupeSpans(spans: DetectionSpan[]): DetectionSpan[] {
  const sorted = [...spans].sort((left, right) => {
    if (left.start !== right.start) {
      return left.start - right.start;
    }

    if (left.confidence !== right.confidence) {
      return right.confidence - left.confidence;
    }

    return right.end - right.start - (left.end - left.start);
  });

  const accepted: DetectionSpan[] = [];

  for (const candidate of sorted) {
    const overlappingIndex = accepted.findIndex(
      (current) => candidate.start < current.end && current.start < candidate.end,
    );

    if (overlappingIndex === -1) {
      accepted.push(candidate);
      continue;
    }

    const current = accepted[overlappingIndex];

    if (current === undefined) {
      accepted.push(candidate);
      continue;
    }

    const candidateScore = candidate.confidence * 1000 + (candidate.end - candidate.start);
    const currentScore = current.confidence * 1000 + (current.end - current.start);

    if (candidateScore > currentScore) {
      accepted[overlappingIndex] = candidate;
    }
  }

  return accepted.sort((left, right) => left.start - right.start);
}

function detectNestedJsonSpans(text: string, detectionOptions?: DetectionOptions): DetectionSpan[] {
  const trimmed = text.trim();

  if (!JSON_LIKE_PREFIX.test(trimmed)) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    const nestedStrings: Array<{ value: string }> = [];

    const walk = (value: unknown): void => {
      if (typeof value === 'string') {
        nestedStrings.push({ value });
        return;
      }

      if (Array.isArray(value)) {
        value.forEach((item) => walk(item));
        return;
      }

      if (typeof value === 'object' && value !== null) {
        Object.values(value).forEach((item) => walk(item));
      }
    };

    walk(parsed);

    const spans: DetectionSpan[] = [];

    for (const nestedString of nestedStrings) {
      for (const nestedSpan of detectSpans(nestedString.value, undefined, detectionOptions)) {
        const index = text.indexOf(nestedSpan.rawValue);

        if (index === -1) {
          continue;
        }

        addSpan(spans, {
          type: nestedSpan.type,
          start: index,
          end: index + nestedSpan.rawValue.length,
          rawValue: nestedSpan.rawValue,
          replacement: nestedSpan.replacement,
          confidence: nestedSpan.confidence,
        });
      }
    }

    return spans;
  } catch {
    return [];
  }
}

function decodeBase64Utf8(value: string): string | undefined {
  if (value.length < 12 || value.length % 4 !== 0) {
    return undefined;
  }

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return undefined;
  }

  try {
    const decoded = Buffer.from(value, 'base64').toString('utf8');
    return decoded.includes('\uFFFD') ? undefined : decoded;
  } catch {
    return undefined;
  }
}

const RESERVED_EMAIL_DOMAINS = new Set(['example.com', 'example.net', 'example.org']);
const RESERVED_EMAIL_SUFFIXES = ['.test', '.invalid', '.localhost'];
const SIMPLE_TYPE_PATTERN = /^(?:true|false|null|undefined|boolean|string|number)$/i;
const HUMAN_PLACEHOLDER_PATTERN =
  /^(?:your(?:[_-][\p{L}\d]+){0,6}|example(?:[_-][\p{L}\d]+){0,6}|sample(?:[_-][\p{L}\d]+){0,6}|dummy(?:[_-][\p{L}\d]+){0,6}|placeholder(?:[_-][\p{L}\d]+){0,6}|changeme|replace(?:[_-]?me)?|long-lived|short-lived|activation-token(?:[-_][\p{L}\d]+){0,6}|noemail|ваш(?:[_-][\p{L}\d]+){0,6})$/iu;
const GENERIC_TOKEN_LABEL_PATTERN = /^(?:header|authorization|auth|bearer|token|secret|password|passwd|credential|credentials|extraction)$/i;
const ENV_VAR_NAME_PATTERN = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const GENERIC_URL_PASSWORDS = new Set([
  'admin',
  'apikey',
  'api_key',
  'changeme',
  'default',
  'pass',
  'password',
  'postgres',
  'root',
  'secret',
  'test',
  'token',
  'user',
  'username',
]);

function stripTrailingSyntax(value: string): string {
  return value.trim().replace(/[;),!]+$/g, '');
}

function stripWrappingQuotes(value: string): string {
  return stripTrailingSyntax(value).replace(/^["'`]+|["'`]+$/g, '');
}

function looksLikeEnvVarName(value: string): boolean {
  return ENV_VAR_NAME_PATTERN.test(value);
}

function getWordLikeSegments(value: string): string[] {
  return value.toLowerCase().split(/[^0-9\p{L}]+/u).filter((segment) => segment.length > 0);
}

function looksLikePlaceholderSegment(segment: string): boolean {
  return (
    /^(?:x{3,}|y{3,}|z{3,})$/i.test(segment) ||
    /^(?:abc123|def456|ghi789|jkl012|mno345|token123)$/i.test(segment) ||
    /^(?:test\d*|demo\d*|sample\d*|example\d*|placeholder\d*|dummy\d*|mock\d*|fake\d*|changeme|replaceme|snapshot|usagebatch|refreshed|rotation|rotate|revoke|revoked|wrong|invalid|ban|watch)$/i.test(
      segment,
    ) ||
    /^(?:your|yours|ваш)$/iu.test(segment)
  );
}

function looksLikeTypeExpression(value: string): boolean {
  return /^(?:Option|Vec|Result|String|str|bytes?|Buffer|Array|Record|Map|Set|HashMap|HashSet|Promise)(?:<|\b|&|\[)/.test(value);
}

function hasLongRandomSegment(value: string): boolean {
  return value.split(/[^A-Za-z0-9]+/).some((segment) => {
    if (segment.length < 8) {
      return false;
    }

    if (/^[a-f0-9]{12,}$/i.test(segment)) {
      return true;
    }

    if (segment.length >= 10 && /[A-Za-z]/.test(segment) && /\d/.test(segment)) {
      return true;
    }

    return segment.length >= 16 && /[A-Z]/.test(segment) && /[a-z]/.test(segment) && /\d/.test(segment);
  });
}

function looksLikeLabelOnlyValue(value: string): boolean {
  const segments = getWordLikeSegments(value);

  if (segments.length === 0) {
    return false;
  }

  return segments.every(
    (segment) =>
      looksLikePlaceholderSegment(segment) ||
      /^(?:\d{1,6}|access|admin|ant|api\d*|apikey|authorization|auth|ban|bearer|cookie|cpk|credential|credentials|example|extraction|header|key|kimi|omni|or|password|pass|placeholder|polza|postgres|prx|proxy|refresh|replicate|root|sample|secret|session|sk|test|token|upstream|usagebatch|user|username|value|v\d+|ваш)$/iu.test(
        segment,
      ),
  );
}

function looksLikePlaceholder(value: string): boolean {
  const normalized = stripWrappingQuotes(value);

  if (normalized.length === 0) {
    return true;
  }

  if (/^\*{3,}(?::\*{3,})?$/.test(normalized)) {
    return true;
  }

  if (normalized.includes('${') || normalized.includes('{{')) {
    return true;
  }

  if (/^<[^>\n`]*>?`?$/.test(normalized) || normalized.toLowerCase().startsWith('<same')) {
    return true;
  }

  if (normalized.startsWith('...')) {
    return true;
  }

  if (HUMAN_PLACEHOLDER_PATTERN.test(normalized)) {
    return true;
  }

  const segments = getWordLikeSegments(normalized);
  if (segments.length > 0 && segments.every((segment) => looksLikePlaceholderSegment(segment))) {
    return true;
  }

  return /^[a-z]+(?:[-_][a-z]+){1,6}$/i.test(normalized) && /(secret|token|password|webhook|proxy|rotation|same)/i.test(normalized);
}

function looksLikeCodeReference(value: string): boolean {
  const normalized = stripWrappingQuotes(value);

  if (normalized.length === 0) {
    return false;
  }

  if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(normalized)) {
    return true;
  }

  if (/^(?:process\.env|import\.meta\.env)\.[A-Za-z_][A-Za-z0-9_]*(?:\??\.[A-Za-z_$][\w$]*)*$/.test(normalized)) {
    return true;
  }

  if (/^(?:[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)+$/.test(normalized)) {
    return true;
  }

  if (/^[A-Za-z_$][\w$]*\(/.test(normalized)) {
    return true;
  }

  return /(?:\?\.|===|!==|&&|\|\||=>|[(){}\[\]`])/.test(value);
}

function looksLikeMarkupContent(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return /^(?:<|<!doctype|<\?xml)/.test(normalized) || /<(?:svg|html|body|div|path|span|script|style)\b/.test(normalized) || normalized.includes('xmlns=');
}

function looksLikeReservedExampleEmail(value: string): boolean {
  const [localPart = '', domainPart = ''] = value.trim().toLowerCase().split('@');

  if (localPart.length === 0 || domainPart.length === 0) {
    return true;
  }

  return (
    RESERVED_EMAIL_DOMAINS.has(domainPart) ||
    RESERVED_EMAIL_SUFFIXES.some((suffix) => domainPart.endsWith(suffix)) ||
    /^cli-invalid(?:$|[-_.])/.test(localPart) ||
    localPart === 'noemail'
  );
}

function looksLikeSyntheticTokenValue(value: string): boolean {
  const normalized = stripWrappingQuotes(value);
  const compact = normalized.replace(/[^A-Za-z0-9]+/g, '');

  if (normalized.length === 0) {
    return true;
  }

  if (
    looksLikePlaceholder(normalized) ||
    looksLikeCodeReference(normalized) ||
    looksLikeEnvVarName(normalized) ||
    GENERIC_TOKEN_LABEL_PATTERN.test(normalized)
  ) {
    return true;
  }

  if (/^<[^>]+>$/.test(normalized) || looksLikeTypeExpression(normalized)) {
    return true;
  }

  if (getWordLikeSegments(normalized).some((segment) => looksLikePlaceholderSegment(segment))) {
    return true;
  }

  if (/^[A-Za-z]+$/.test(compact) && compact.length < 20) {
    return true;
  }

  return looksLikeLabelOnlyValue(normalized) && !hasLongRandomSegment(normalized);
}

function looksLikeSensitiveAssignmentValue(value: string): boolean {
  const normalized = stripWrappingQuotes(value);

  if (normalized.length < 6) {
    return false;
  }

  if (
    SIMPLE_TYPE_PATTERN.test(normalized) ||
    looksLikePlaceholder(normalized) ||
    looksLikeCodeReference(normalized) ||
    looksLikeEnvVarName(normalized) ||
    looksLikeTypeExpression(normalized)
  ) {
    return false;
  }

  if (/^(?:sk-|prx_|omni_|cpk_|gh[pousr]_)/i.test(normalized) && looksLikeSyntheticTokenValue(normalized)) {
    return false;
  }

  return !/^[A-Za-z]+$/.test(normalized) || normalized.length >= 12;
}

function looksLikeSensitiveAuthorizationValue(value: string): boolean {
  const normalized = stripWrappingQuotes(value);
  const compact = normalized.replace(/[^A-Za-z0-9]+/g, '');

  if (normalized.length < 10) {
    return false;
  }

  if (looksLikeSyntheticTokenValue(normalized)) {
    return false;
  }

  return hasLongRandomSegment(normalized) || (compact.length >= 12 && /[A-Za-z]/.test(compact) && /\d/.test(compact));
}

function looksLikeSensitiveCookieValue(value: string): boolean {
  const normalized = stripWrappingQuotes(value);

  if (normalized.length < 8) {
    return false;
  }

  if (looksLikePlaceholder(normalized) || looksLikeCodeReference(normalized)) {
    return false;
  }

  return normalized.includes('=');
}

function looksLikeSensitiveUrlCredential(value: string): boolean {
  const normalized = stripWrappingQuotes(value);
  const separatorIndex = normalized.indexOf(':');

  if (separatorIndex <= 0 || separatorIndex === normalized.length - 1) {
    return false;
  }

  const username = normalized.slice(0, separatorIndex);
  const password = normalized.slice(separatorIndex + 1);
  const usernameLower = username.toLowerCase();
  const passwordLower = password.toLowerCase();

  if (password.length < 6) {
    return false;
  }

  if (
    looksLikePlaceholder(normalized) ||
    looksLikeCodeReference(normalized) ||
    looksLikePlaceholder(username) ||
    looksLikePlaceholder(password) ||
    looksLikeCodeReference(username) ||
    looksLikeCodeReference(password) ||
    looksLikeEnvVarName(username) ||
    looksLikeEnvVarName(password)
  ) {
    return false;
  }

  if (/^\*+$/.test(username) || /^\*+$/.test(password) || /^<[^>]+>$/.test(username) || /^<[^>]+>$/.test(password)) {
    return false;
  }

  if (GENERIC_URL_PASSWORDS.has(passwordLower) || GENERIC_URL_PASSWORDS.has(usernameLower)) {
    return false;
  }

  if (usernameLower === passwordLower && looksLikeLabelOnlyValue(passwordLower)) {
    return false;
  }

  return !looksLikeSyntheticTokenValue(password);
}

function looksLikeSensitiveSignedQueryValue(value: string): boolean {
  const normalized = stripWrappingQuotes(value);
  const compact = normalized.replace(/[^A-Za-z0-9]+/g, '');

  if (normalized.length < 8) {
    return false;
  }

  if (looksLikeSyntheticTokenValue(normalized) || looksLikePlaceholder(normalized) || looksLikeCodeReference(normalized)) {
    return false;
  }

  if (['admin', 'password', 'secret', 'token'].includes(normalized.toLowerCase())) {
    return false;
  }

  return hasLongRandomSegment(normalized) || (compact.length >= 16 && /[A-Za-z]/.test(compact) && /\d/.test(compact));
}

function looksLikeSensitiveRawTokenValue(value: string): boolean {
  const normalized = stripWrappingQuotes(value);
  const compact = normalized.replace(/[^A-Za-z0-9]+/g, '');

  if (normalized.length < 12) {
    return false;
  }

  if (looksLikeSyntheticTokenValue(normalized)) {
    return false;
  }

  return hasLongRandomSegment(normalized) || compact.length >= 24;
}

function looksLikeSensitiveBase64(decoded: string): boolean {
  const trimmed = decoded.trim();

  if (trimmed.length < 8) {
    return false;
  }

  if (looksLikeMarkupContent(trimmed) || looksLikePlaceholder(trimmed) || looksLikeCodeReference(trimmed)) {
    return false;
  }

  return (
    /(token|secret|pass(?:word)?|auth|bearer|basic|api[_-]?key|client[_-]?secret|cookie)/i.test(trimmed) ||
    /(?:^|[\s,{])(token|secret|pass(?:word)?|auth|bearer|basic|api[_-]?key|client[_-]?secret|cookie)\s*[:=]\s*\S{6,}/i.test(trimmed)
  );
}

export function detectSpans(text: string, contextKey?: string, detectionOptions?: DetectionOptions): DetectionSpan[] {
  if (detectionOptions?.enabledTypes?.size === 0) {
    return [];
  }

  const spans: DetectionSpan[] = [];

  if (isSecretTypeEnabled('secret_assignment', detectionOptions)) {
    collectPatternMatches(
      text,
      SENSITIVE_ASSIGNMENT_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const value = match[2] ?? '';

        if (!looksLikeSensitiveAssignmentValue(value)) {
          return;
        }

        const start = (match.index ?? 0) + prefix.length;

        addSpan(spans, {
          type: 'secret_assignment',
          start,
          end: start + value.length,
          rawValue: value,
          replacement: maskToken(value),
          confidence: 10,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('authorization_header', detectionOptions)) {
    collectPatternMatches(
      text,
      AUTHORIZATION_HEADER_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const credential = match[2] ?? '';
        if (!looksLikeSensitiveAuthorizationValue(credential)) {
          return;
        }

        const start = (match.index ?? 0) + prefix.length;

        addSpan(spans, {
          type: 'authorization_header',
          start,
          end: start + credential.length,
          rawValue: credential,
          replacement: maskToken(credential),
          confidence: 10,
        });
      },
      spans,
    );

    collectPatternMatches(
      text,
      BARE_BEARER_TOKEN_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const credential = match[2] ?? '';
        if (!looksLikeSensitiveAuthorizationValue(credential)) {
          return;
        }

        const start = (match.index ?? 0) + prefix.length;

        addSpan(spans, {
          type: 'authorization_header',
          start,
          end: start + credential.length,
          rawValue: credential,
          replacement: maskToken(credential),
          confidence: 9,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('cookie', detectionOptions)) {
    collectPatternMatches(
      text,
      COOKIE_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const value = match[2] ?? '';

        if (!looksLikeSensitiveCookieValue(value)) {
          return;
        }

        const start = (match.index ?? 0) + prefix.length;

        addSpan(spans, {
          type: 'cookie',
          start,
          end: start + value.length,
          rawValue: value,
          replacement: maskToken(value),
          confidence: 9,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('url_credentials', detectionOptions)) {
    collectPatternMatches(
      text,
      URL_CREDENTIALS_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const userInfo = match[2] ?? '';

        if (!looksLikeSensitiveUrlCredential(userInfo)) {
          return;
        }

        const start = (match.index ?? 0) + prefix.length;

        addSpan(spans, {
          type: 'url_credentials',
          start,
          end: start + userInfo.length,
          rawValue: userInfo,
          replacement: maskToken(userInfo),
          confidence: 10,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('signed_query', detectionOptions)) {
    collectPatternMatches(
      text,
      SIGNED_QUERY_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const value = match[2] ?? '';

        if (!looksLikeSensitiveSignedQueryValue(value)) {
          return;
        }

        const start = (match.index ?? 0) + prefix.length;

        addSpan(spans, {
          type: 'signed_query',
          start,
          end: start + value.length,
          rawValue: value,
          replacement: maskToken(value),
          confidence: 9,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('basic_auth', detectionOptions)) {
    collectPatternMatches(
      text,
      BASIC_AUTH_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const value = match[2] ?? '';
        const start = (match.index ?? 0) + prefix.length;

        addSpan(spans, {
          type: 'basic_auth',
          start,
          end: start + value.length,
          rawValue: value,
          replacement: maskToken(value),
          confidence: 9,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('base64_secret', detectionOptions)) {
    collectPatternMatches(
      text,
      BASE64_SECRET_PATTERN,
      (match) => {
        const prefix = match[1] ?? '';
        const value = match[2] ?? '';
        const decoded = decodeBase64Utf8(value);

        if (decoded === undefined || !looksLikeSensitiveBase64(decoded)) {
          return;
        }

        const start = (match.index ?? 0) + prefix.length;
        addSpan(spans, {
          type: 'base64_secret',
          start,
          end: start + value.length,
          rawValue: value,
          replacement: maskToken(value),
          confidence: 7,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('private_key', detectionOptions)) {
    collectPatternMatches(
      text,
      PRIVATE_KEY_PATTERN,
      (match) => {
        const rawValue = match[0] ?? '';
        const start = match.index ?? 0;

        addSpan(spans, {
          type: 'private_key',
          start,
          end: start + rawValue.length,
          rawValue,
          replacement: maskPrivateKey(rawValue),
          confidence: 10,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('jwt', detectionOptions)) {
    collectPatternMatches(
      text,
      JWT_PATTERN,
      (match) => {
        const rawValue = match[0] ?? '';
        const start = match.index ?? 0;
        addSpan(spans, {
          type: 'jwt',
          start,
          end: start + rawValue.length,
          rawValue,
          replacement: maskToken(rawValue),
          confidence: 8,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('raw_token', detectionOptions)) {
    collectPatternMatches(
      text,
      RAW_TOKEN_PATTERN,
      (match) => {
        const rawValue = match[0] ?? '';

        if (!looksLikeSensitiveRawTokenValue(rawValue)) {
          return;
        }

        const start = match.index ?? 0;
        addSpan(spans, {
          type: 'raw_token',
          start,
          end: start + rawValue.length,
          rawValue,
          replacement: maskToken(rawValue),
          confidence: 7,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('email', detectionOptions)) {
    collectPatternMatches(
      text,
      EMAIL_PATTERN,
      (match) => {
        const rawValue = match[0] ?? '';

        if (looksLikeReservedExampleEmail(rawValue)) {
          return;
        }

        const start = match.index ?? 0;
        addSpan(spans, {
          type: 'email',
          start,
          end: start + rawValue.length,
          rawValue,
          replacement: maskEmail(rawValue),
          confidence: 4,
        });
      },
      spans,
    );
  }

  if (isSecretTypeEnabled('path_username', detectionOptions)) {
    for (const pattern of PATH_USERNAME_PATTERNS) {
      collectPatternMatches(
        text,
        pattern,
        (match) => {
          const user = match[1] ?? '';

          if (user.length === 0) {
            return;
          }

          const fullMatch = match[0] ?? '';
          const userOffset = fullMatch.indexOf(user);

          if (userOffset === -1) {
            return;
          }

          const start = (match.index ?? 0) + userOffset;
          addSpan(spans, {
            type: 'path_username',
            start,
            end: start + user.length,
            rawValue: user,
            replacement: maskUsername(user),
            confidence: 5,
          });
        },
        spans,
      );
    }
  }

  if (
    spans.length === 0 &&
    contextKey !== undefined &&
    isSecretTypeEnabled('secret_assignment', detectionOptions) &&
    /(api[_-]?key|token|secret|access[_-]?token|refresh[_-]?token|password|passwd|pwd|authorization|cookie)/i.test(
      contextKey,
    )
  ) {
    const trimmed = text.trim();

    if (trimmed.length >= 6 && !trimmed.includes(' ') && looksLikeSensitiveAssignmentValue(trimmed)) {
      addSpan(spans, {
        type: 'secret_assignment',
        start: text.indexOf(trimmed),
        end: text.indexOf(trimmed) + trimmed.length,
        rawValue: trimmed,
        replacement: maskToken(trimmed),
        confidence: 8,
      });
    }
  }

  return dedupeSpans([...spans, ...detectNestedJsonSpans(text, detectionOptions)]);
}

export function buildMaskedValue(
  field: StringFieldRef,
  detectionOptions?: DetectionOptions,
): { nextValue: string; findings: DetectionSpan[] } {
  const findings = detectSpans(field.value, field.contextKey, detectionOptions);

  if (findings.length === 0) {
    return { nextValue: field.value, findings };
  }

  return {
    nextValue: applyReplacements(
      field.value,
      findings.map((finding) => ({ start: finding.start, end: finding.end, replacement: finding.replacement })),
    ),
    findings,
  };
}

export function findingsForField(
  handle: SessionHandle,
  field: StringFieldRef,
  detectionOptions?: DetectionOptions,
): SessionFinding[] {
  return detectSpans(field.value, field.contextKey, detectionOptions).map((span) => ({
    provider: handle.provider,
    sessionId: handle.sessionId,
    type: span.type,
    fieldId: field.id,
    fieldPath: field.path,
    sourceLabel: field.sourceLabel,
    preview: span.preview,
    rawSample: span.rawValue,
    fingerprint: span.fingerprint,
    maskPolicy: field.maskPolicy,
  }));
}
