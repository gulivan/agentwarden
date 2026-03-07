import { buildScanJson } from '../reporting/scan_json.js';
import { formatScanTable } from '../reporting/scan_table.js';
import { analyzeArtifacts } from '../secrets/plan.js';
import type { AgentProvider } from '../providers/types.js';
import { loadArtifacts, shouldFailRequestedProvider } from './helpers.js';

export interface ScanCommandOptions {
  agent?: AgentProvider;
  json?: boolean;
}

export async function scanCommand(options: ScanCommandOptions): Promise<void> {
  const loaded = await loadArtifacts(options.agent);
  const analysis = analyzeArtifacts(loaded.artifacts);
  const shouldFail = shouldFailRequestedProvider(options.agent, loaded);

  if (options.json) {
    console.log(JSON.stringify(buildScanJson(analysis, loaded.warnings, loaded.errors, loaded.providers), null, 2));
    if (shouldFail) {
      process.exitCode = 1;
    }
    return;
  }

  console.log(formatScanTable(analysis, loaded.warnings, loaded.errors));

  if (shouldFail) {
    process.exitCode = 1;
  }
}
