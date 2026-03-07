import type { ProviderNotice } from '../providers/types.js';
import { formatSecretTypes } from '../secrets/options.js';
import type { AnalysisResult, FindingGroup } from '../secrets/types.js';
import { includesSamples, type SampleDisplayMode } from './sample_display.js';
import type { ScanEntrySummary, ScanReport } from './scan_report.js';

export interface ScanTableOptions {
  report: ScanReport;
  sampleDisplayMode?: SampleDisplayMode;
  showDetails?: boolean;
}

function pad(value: string, size: number): string {
  return value.padEnd(size, ' ');
}

function formatNotice(notice: ProviderNotice): string {
  const sessionSuffix = notice.sessionId === undefined ? '' : ` (${notice.sessionId})`;
  return `- ${notice.provider}${sessionSuffix}: ${notice.message}`;
}

function formatTable(headers: string[], rows: string[][]): string[] {
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));

  return [
    headers.map((header, index) => pad(header, widths[index] ?? header.length)).join(' | '),
    widths.map((width) => '-'.repeat(width)).join('-+-'),
    ...rows.map((row) => row.map((value, index) => pad(value, widths[index] ?? value.length)).join(' | ')),
  ];
}

function normalizeSample(sample: string): string {
  const compact = sample.replace(/\s+/g, ' ');
  return compact.length > 96 ? `${compact.slice(0, 93)}...` : compact;
}

function formatSample(group: FindingGroup, sampleDisplayMode: SampleDisplayMode): string {
  const samples = sampleDisplayMode === 'raw' ? group.rawSamples : group.previews;
  const sample = samples[0];
  return sample === undefined ? '-' : normalizeSample(sample);
}

function formatEntrySample(entry: ScanEntrySummary, sampleDisplayMode: SampleDisplayMode): string {
  const samples = sampleDisplayMode === 'raw' ? entry.rawSamples : entry.previews;
  const sample = samples[0];
  return sample === undefined ? '-' : normalizeSample(sample);
}

export function formatSpottedEntryTable(
  report: ScanReport,
  sampleDisplayMode: SampleDisplayMode,
  options: { limit?: number } = {},
): string {
  const entries = options.limit === undefined ? report.byEntry : report.byEntry.slice(0, options.limit);
  const lines = ['spotted entries:'];

  if (report.byEntry.length === 0) {
    lines.push('no secrets detected');
    return lines.join('\n');
  }

  lines.push(
    ...formatTable(
      ['fingerprint', 'findings', 'sessions', 'providers', 'types', sampleDisplayMode === 'raw' ? 'value' : 'sample'],
      entries.map((entry) => [
        entry.fingerprint,
        String(entry.findings),
        String(entry.sessions),
        entry.providers.join(', '),
        entry.types.join(', '),
        formatEntrySample(entry, sampleDisplayMode),
      ]),
    ),
  );

  if (options.limit !== undefined && report.byEntry.length > options.limit) {
    lines.push('', `more hidden: ${report.byEntry.length - options.limit} entries`);
  }

  return lines.join('\n');
}

export function formatScanTable(
  result: AnalysisResult,
  warnings: ProviderNotice[],
  errors: ProviderNotice[],
  options: ScanTableOptions,
): string {
  const sampleDisplayMode = options.sampleDisplayMode ?? 'none';
  const showSamples = includesSamples(sampleDisplayMode);
  const lines = [
    'summary:',
    `sessions: ${result.summary.sessions}`,
    `findings: ${result.summary.findings}`,
    `sessions with findings: ${result.summary.sessionsWithFindings}`,
    `sessions with changes: ${result.summary.sessionsWithChanges}`,
    `checked types: ${options.report.filters.allTypesEnabled ? 'all' : formatSecretTypes(options.report.filters.checkedTypes)}`,
  ];

  if (options.report.filters.includeTypes.length > 0) {
    lines.push(`included types: ${formatSecretTypes(options.report.filters.includeTypes)}`);
  }

  if (options.report.filters.excludeTypes.length > 0) {
    lines.push(`excluded types: ${formatSecretTypes(options.report.filters.excludeTypes)}`);
  }

  if (sampleDisplayMode === 'raw') {
    lines.push('sample values: raw');
  } else if (sampleDisplayMode === 'masked') {
    lines.push('sample values: masked');
  }

  if (result.summary.sessions === 0) {
    lines.push('', 'no sessions found');
  } else {
    lines.push('', 'providers:');
    lines.push(
      ...formatTable(
        ['provider', 'sessions', 'findings', 'with findings', 'changes'],
        options.report.byProvider.map((provider) => [
          provider.provider,
          String(provider.sessions),
          String(provider.findings),
          String(provider.sessionsWithFindings),
          String(provider.changes),
        ]),
      ),
    );

    lines.push('', 'findings by type:');

    if (options.report.byType.length === 0) {
      lines.push('no secrets detected');
    } else {
      lines.push(
        ...formatTable(
          ['type', 'findings', 'sessions'],
          options.report.byType.map((typeSummary) => [
            typeSummary.type,
            String(typeSummary.findings),
            String(typeSummary.sessions),
          ]),
        ),
      );
    }

    lines.push('', 'top sessions:');

    if (options.report.bySession.length === 0) {
      lines.push('no sessions with findings');
    } else {
      lines.push(
        ...formatTable(
          ['provider', 'session', 'findings', 'types'],
          options.report.bySession.slice(0, 10).map((session) => [
            session.provider,
            session.sessionId,
            String(session.findings),
            session.types.join(', '),
          ]),
        ),
      );
    }

    if (showSamples && result.findingGroups.length > 0 && !options.showDetails) {
      lines.push('', sampleDisplayMode === 'raw' ? 'raw values:' : 'samples:');
      lines.push(
        ...formatTable(
          ['provider', 'session', 'type', sampleDisplayMode === 'raw' ? 'value' : 'sample'],
          result.findingGroups.slice(0, 10).map((group) => [
            group.provider,
            group.sessionId,
            group.type,
            formatSample(group, sampleDisplayMode),
          ]),
        ),
      );
    }

    if (options.showDetails) {
      lines.push('', 'details:');

      if (result.findingGroups.length === 0) {
        lines.push('no secrets detected');
      } else {
        lines.push(
          ...formatTable(
            showSamples
              ? ['provider', 'session', 'type', 'count', sampleDisplayMode === 'raw' ? 'value' : 'sample']
              : ['provider', 'session', 'type', 'count'],
            result.findingGroups.map((group) =>
              showSamples
                ? [group.provider, group.sessionId, group.type, String(group.count), formatSample(group, sampleDisplayMode)]
                : [group.provider, group.sessionId, group.type, String(group.count)],
            ),
          ),
        );
      }
    } else if (result.findingGroups.length > 0) {
      const hints = ['--details'];

      if (!showSamples) {
        hints.push('--samples', '--raw-samples');
      }

      lines.push('', `details hidden: ${result.findingGroups.length} rows (rerun with ${hints.join(' or ')})`);
    }
  }

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
