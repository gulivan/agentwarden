import { createHash } from 'node:crypto';

export function fingerprintSecret(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

export function maskToken(value: string): string {
  if (value.length <= 8) {
    return '*'.repeat(Math.max(4, value.length));
  }

  const prefixLength = value.length > 20 ? 6 : 3;
  const suffixLength = value.length > 12 ? 4 : 2;
  return `${value.slice(0, prefixLength)}****${value.slice(-suffixLength)}`;
}

export function maskEmail(value: string): string {
  const localPart = value.split('@')[0] ?? '';
  const domainPart = value.split('@')[1];

  if (domainPart === undefined) {
    return maskToken(value);
  }

  const safeLocal = localPart.length <= 2 ? `${localPart[0] ?? '*'}*` : `${localPart.slice(0, 2)}***`;
  return `${safeLocal}@${domainPart}`;
}

export function maskUsername(value: string): string {
  if (value.length <= 2) {
    return `${value[0] ?? '*'}*`;
  }

  return `${value[0] ?? '*'}***${value.slice(-1)}`;
}

export function maskPrivateKey(value: string): string {
  const lines = value.split(/\r?\n/);

  if (lines.length < 2) {
    return '[PRIVATE KEY REDACTED]';
  }

  const firstLine = lines[0] ?? '-----BEGIN PRIVATE KEY-----';
  const lastLine = lines[lines.length - 1] ?? '-----END PRIVATE KEY-----';
  return `${firstLine}\n[PRIVATE KEY REDACTED]\n${lastLine}`;
}

export function applyReplacements(source: string, replacements: Array<{ start: number; end: number; replacement: string }>): string {
  let output = source;

  for (const replacement of [...replacements].sort((left, right) => right.start - left.start)) {
    output = `${output.slice(0, replacement.start)}${replacement.replacement}${output.slice(replacement.end)}`;
  }

  return output;
}
