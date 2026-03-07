import type { AgentProvider, ProviderNotice } from '../providers/types.js';
import type { AnalysisResult } from '../secrets/types.js';
import type { ScanReport } from './scan_report.js';

export interface ScanJsonOptions {
  includeRawSamples?: boolean;
}

export function buildScanJson(
  result: AnalysisResult,
  warnings: ProviderNotice[],
  errors: ProviderNotice[],
  providers: AgentProvider[],
  report: ScanReport,
  options: ScanJsonOptions = {},
): Record<string, unknown> {
  const includeRawSamples = options.includeRawSamples ?? false;

  return {
    schemaVersion: 3,
    generatedAt: new Date().toISOString(),
    providers,
    filters: report.filters,
    summary: result.summary,
    report: {
      byProvider: report.byProvider,
      byType: report.byType,
      bySession: report.bySession,
      byEntry: report.byEntry.map((entry) => ({
        fingerprint: entry.fingerprint,
        findings: entry.findings,
        previews: [...entry.previews],
        providers: [...entry.providers],
        sessions: entry.sessions,
        types: [...entry.types],
        ...(includeRawSamples ? { rawSamples: [...entry.rawSamples] } : {}),
      })),
    },
    findingGroups: result.findingGroups.map((group) => ({
      provider: group.provider,
      sessionId: group.sessionId,
      type: group.type,
      count: group.count,
      previews: [...group.previews],
      fingerprints: [...group.fingerprints],
      ...(includeRawSamples ? { rawSamples: [...group.rawSamples] } : {}),
    })),
    warnings,
    errors,
  };
}
