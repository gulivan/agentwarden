import type { ProviderNotice } from '../providers/types.js';
import type { AnalysisResult } from '../secrets/types.js';

function pad(value: string, size: number): string {
  return value.padEnd(size, ' ');
}

function formatNotice(notice: ProviderNotice): string {
  const sessionSuffix = notice.sessionId === undefined ? '' : ` (${notice.sessionId})`;
  return `- ${notice.provider}${sessionSuffix}: ${notice.message}`;
}

export function formatScanTable(result: AnalysisResult, warnings: ProviderNotice[], errors: ProviderNotice[]): string {
  if (result.summary.sessions === 0) {
    const lines = ['no sessions found'];

    if (warnings.length > 0) {
      lines.push('', 'warnings:');
      warnings.forEach((warning) => lines.push(formatNotice(warning)));
    }

    if (errors.length > 0) {
      lines.push('', 'errors:');
      errors.forEach((error) => lines.push(formatNotice(error)));
    }

    return lines.join('\n');
  }

  const rows = result.findingGroups.map((group) => ({
    provider: group.provider,
    session: group.sessionId,
    type: group.type,
    count: String(group.count),
  }));

  const widths = {
    provider: Math.max('provider'.length, ...rows.map((row) => row.provider.length), 8),
    session: Math.max('session'.length, ...rows.map((row) => row.session.length), 7),
    type: Math.max('type'.length, ...rows.map((row) => row.type.length), 4),
    count: Math.max('count'.length, ...rows.map((row) => row.count.length), 5),
  };

  const lines = [
    `${pad('provider', widths.provider)} | ${pad('session', widths.session)} | ${pad('type', widths.type)} | ${pad('count', widths.count)}`,
    `${'-'.repeat(widths.provider)}-+-${'-'.repeat(widths.session)}-+-${'-'.repeat(widths.type)}-+-${'-'.repeat(widths.count)}`,
  ];

  if (rows.length === 0) {
    lines.push('no secrets detected');
  } else {
    rows.forEach((row) => {
      lines.push(
        `${pad(row.provider, widths.provider)} | ${pad(row.session, widths.session)} | ${pad(row.type, widths.type)} | ${pad(row.count, widths.count)}`,
      );
    });
  }

  lines.push('');
  lines.push(`sessions: ${result.summary.sessions}`);
  lines.push(`findings: ${result.summary.findings}`);
  lines.push(`sessions with findings: ${result.summary.sessionsWithFindings}`);
  lines.push(`sessions with changes: ${result.summary.sessionsWithChanges}`);

  if (warnings.length > 0) {
    lines.push('', 'warnings:');
    warnings.forEach((warning) => lines.push(formatNotice(warning)));
  }

  if (errors.length > 0) {
    lines.push('', 'errors:');
    errors.forEach((error) => lines.push(formatNotice(error)));
  }

  return lines.join('\n');
}
