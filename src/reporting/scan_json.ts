import type { AgentProvider, ProviderNotice } from '../providers/types.js';
import type { AnalysisResult } from '../secrets/types.js';

export function buildScanJson(
  result: AnalysisResult,
  warnings: ProviderNotice[],
  errors: ProviderNotice[],
  providers: AgentProvider[],
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    providers,
    summary: result.summary,
    findingGroups: result.findingGroups,
    warnings,
    errors,
  };
}
