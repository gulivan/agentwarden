import type { SessionHandle, StringFieldRef } from '../providers/types.js';
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

function detectNestedJsonSpans(text: string): DetectionSpan[] {
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
      for (const nestedSpan of detectSpans(nestedString.value)) {
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

function looksLikeSensitiveBase64(decoded: string): boolean {
  const trimmed = decoded.trim();

  if (trimmed.length < 8) {
    return false;
  }

  return /[:=]/.test(trimmed) || /(token|secret|pass(?:word)?|auth|bearer|basic|api[_-]?key|client[_-]?secret|cookie)/i.test(trimmed);
}

export function detectSpans(text: string, contextKey?: string): DetectionSpan[] {
  const spans: DetectionSpan[] = [];

  collectPatternMatches(
    text,
    SENSITIVE_ASSIGNMENT_PATTERN,
    (match) => {
      const prefix = match[1] ?? '';
      const value = match[2] ?? '';
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

  collectPatternMatches(
    text,
    AUTHORIZATION_HEADER_PATTERN,
    (match) => {
      const prefix = match[1] ?? '';
      const credential = match[2] ?? '';
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

  collectPatternMatches(
    text,
    COOKIE_PATTERN,
    (match) => {
      const prefix = match[1] ?? '';
      const value = match[2] ?? '';
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

  collectPatternMatches(
    text,
    URL_CREDENTIALS_PATTERN,
    (match) => {
      const prefix = match[1] ?? '';
      const userInfo = match[2] ?? '';
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

  collectPatternMatches(
    text,
    SIGNED_QUERY_PATTERN,
    (match) => {
      const prefix = match[1] ?? '';
      const value = match[2] ?? '';
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

  collectPatternMatches(
    text,
    RAW_TOKEN_PATTERN,
    (match) => {
      const rawValue = match[0] ?? '';
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

  collectPatternMatches(
    text,
    EMAIL_PATTERN,
    (match) => {
      const rawValue = match[0] ?? '';
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

  if (
    spans.length === 0 &&
    contextKey !== undefined &&
    /(api[_-]?key|token|secret|access[_-]?token|refresh[_-]?token|password|passwd|pwd|authorization|cookie)/i.test(
      contextKey,
    )
  ) {
    const trimmed = text.trim();

    if (trimmed.length >= 6 && !trimmed.includes(' ')) {
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

  return dedupeSpans([...spans, ...detectNestedJsonSpans(text)]);
}

export function buildMaskedValue(field: StringFieldRef): { nextValue: string; findings: DetectionSpan[] } {
  const findings = detectSpans(field.value, field.contextKey);

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

export function findingsForField(handle: SessionHandle, field: StringFieldRef): SessionFinding[] {
  return detectSpans(field.value, field.contextKey).map((span) => ({
    provider: handle.provider,
    sessionId: handle.sessionId,
    type: span.type,
    fieldId: field.id,
    fieldPath: field.path,
    sourceLabel: field.sourceLabel,
    preview: span.preview,
    fingerprint: span.fingerprint,
    maskPolicy: field.maskPolicy,
  }));
}
