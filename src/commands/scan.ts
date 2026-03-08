import { resolve } from 'node:path';
import { maskSecretsCommand } from './mask_secrets.js';
import {
  canPromptInteractively,
  promptForInteractiveScan,
  promptPostScanAction,
  promptToMaskDetectedSecrets,
} from './interactive_scan.js';
import { buildScanJson } from '../reporting/scan_json.js';
import { buildScanReport } from '../reporting/scan_report.js';
import { formatScanTable, formatSpottedEntryTable } from '../reporting/scan_table.js';
import { resolveSampleDisplayMode, usesRawSamples, type SampleDisplayMode } from '../reporting/sample_display.js';
import { resolveSecretTypeSelection } from '../secrets/options.js';
import { analyzeArtifactForScan, createAnalysisAccumulator } from '../secrets/plan.js';
import type { SecretType } from '../secrets/types.js';
import type { AgentProvider } from '../providers/types.js';
import { loadArtifacts, resolveProviderSelection, shouldFailRequestedProvider } from './helpers.js';
import { ScanCache } from '../io/scan_cache.js';
import { ensurePrivateDir, expandHomeDir, writePrivateFile } from '../io/paths.js';

export interface ScanCommandOptions {
  agent?: AgentProvider;
  agents?: AgentProvider[];
  details?: boolean;
  direct?: boolean;
  excludeTypes?: SecretType[];
  interactive?: boolean;
  json?: boolean;
  rawSamples?: boolean;
  sampleDisplay?: SampleDisplayMode;
  samples?: boolean;
  types?: SecretType[];
}

interface ExecutedScan {
  analysis: ReturnType<ReturnType<typeof createAnalysisAccumulator>['build']>;
  loaded: Awaited<ReturnType<typeof loadArtifacts>>;
  report: ReturnType<typeof buildScanReport>;
  shouldFail: boolean;
}

function getSampleDisplayMode(options: ScanCommandOptions): SampleDisplayMode {
  return resolveSampleDisplayMode(options);
}

async function executeScan(options: ScanCommandOptions): Promise<ExecutedScan> {
  const requestedProviders = resolveProviderSelection(options);
  const sampleDisplayMode = getSampleDisplayMode(options);
  const detectionOptions = resolveSecretTypeSelection({
    includeTypes: options.types,
    excludeTypes: options.excludeTypes,
  });
  const accumulator = createAnalysisAccumulator({ retainSessions: false, detectionOptions });
  const scanCache = usesRawSamples(sampleDisplayMode) ? undefined : await ScanCache.load(detectionOptions);
  const loaded = await loadArtifacts({
    agent: options.agent,
    agents: options.agents,
    collectArtifacts: false,
    progressLabel: 'scanning',
    onArtifactLoaded: async (artifact) => {
      const cached = scanCache === undefined ? undefined : await scanCache.get(artifact.handle);

      if (cached !== undefined) {
        accumulator.addSessionAnalysis({
          provider: artifact.handle.provider,
          sessionId: artifact.handle.sessionId,
          findings: cached.findings,
          hasChanges: cached.hasChanges,
        });
        return;
      }

      const analysis = analyzeArtifactForScan(artifact, detectionOptions);
      accumulator.addSessionAnalysis(analysis);
      await scanCache?.set(artifact.handle, {
        findings: analysis.findings,
        hasChanges: analysis.hasChanges,
      });
    },
  });
  await scanCache?.persist();
  const analysis = accumulator.build();
  const report = buildScanReport(analysis, loaded.providers, detectionOptions);

  return {
    analysis,
    loaded,
    report,
    shouldFail: shouldFailRequestedProvider(requestedProviders, loaded),
  };
}

function formatScanOutput(result: ExecutedScan, options: ScanCommandOptions): string {
  const sampleDisplayMode = getSampleDisplayMode(options);

  if (options.json) {
    return JSON.stringify(
      buildScanJson(result.analysis, result.loaded.warnings, result.loaded.errors, result.loaded.providers, result.report, {
        includeRawSamples: usesRawSamples(sampleDisplayMode),
      }),
      null,
      2,
    );
  }

  return formatScanTable(result.analysis, result.loaded.warnings, result.loaded.errors, {
    report: result.report,
    sampleDisplayMode,
    showDetails: options.details,
  });
}

function formatSavedScanOutput(result: ExecutedScan, options: ScanCommandOptions): string {
  const baseOutput = formatScanOutput(result, options);

  if (options.json || result.report.byEntry.length === 0) {
    return baseOutput;
  }

  const sampleDisplayMode = getSampleDisplayMode(options);
  return `${baseOutput}\n\n${formatSpottedEntryTable(result.report, sampleDisplayMode)}`;
}

function printScanOutput(result: ExecutedScan, options: ScanCommandOptions): void {
  console.log(formatScanOutput(result, options));
}

async function saveScanOutput(result: ExecutedScan, options: ScanCommandOptions): Promise<string> {
  const directory = expandHomeDir('~/.agentwarden/reports');
  const timestamp = new Date().toISOString().replace(/[:]/g, '-');
  const extension = options.json ? 'json' : 'txt';
  const filePath = resolve(directory, `scan-${timestamp}.${extension}`);

  await ensurePrivateDir(directory);
  await writePrivateFile(filePath, `${formatSavedScanOutput(result, options)}\n`);

  return filePath;
}

function shouldUseInteractiveWizard(options: ScanCommandOptions): boolean {
  if (options.json || options.direct || !canPromptInteractively()) {
    return false;
  }

  if (options.interactive) {
    return true;
  }

  const hasExplicitFilters =
    options.agent !== undefined ||
    (options.agents?.length ?? 0) > 0 ||
    (options.types?.length ?? 0) > 0 ||
    (options.excludeTypes?.length ?? 0) > 0 ||
    options.details === true ||
    options.samples === true ||
    options.rawSamples === true ||
    options.sampleDisplay !== undefined;

  return !hasExplicitFilters;
}

export async function scanCommand(options: ScanCommandOptions): Promise<void> {
  const interactive = shouldUseInteractiveWizard(options);

  if (interactive) {
    const selection = await promptForInteractiveScan({
      agents: resolveProviderSelection(options),
      sampleDisplayMode: getSampleDisplayMode(options),
      types: options.types,
    });

    if (selection === undefined) {
      return;
    }

    const interactiveOptions: ScanCommandOptions = {
      ...options,
      agent: undefined,
      agents: selection.agents,
      rawSamples: false,
      sampleDisplay: selection.sampleDisplayMode,
      samples: false,
      types: selection.types,
    };
    const result = await executeScan(interactiveOptions);
    printScanOutput(result, interactiveOptions);

    if (result.shouldFail) {
      process.exitCode = 1;
    }

    if (result.analysis.summary.findings > 0) {
      while (true) {
        console.log('');
        const action = await promptPostScanAction();

        if (action === 'skip') {
          break;
        }

        if (action === 'show_spotted_stats') {
          console.log('');
          console.log(formatSpottedEntryTable(result.report, getSampleDisplayMode(interactiveOptions), { limit: 25 }));
          continue;
        }

        const savedPath = await saveScanOutput(result, interactiveOptions);
        console.log('');
        console.log(`saved report: ${savedPath}`);
      }
    }

    if (result.analysis.summary.sessionsWithChanges === 0) {
      return;
    }

    console.log('');

    const maskDecision = await promptToMaskDetectedSecrets();

    if (maskDecision !== 'skip') {
      const backup = maskDecision === 'with_backups';
      console.log('');
      console.log(backup ? 'Applying masks with backups enabled...' : 'Applying masks without creating backups...');
      await maskSecretsCommand({
        agent: undefined,
        agents: interactiveOptions.agents,
        backup,
        excludeTypes: interactiveOptions.excludeTypes,
        types: interactiveOptions.types,
      });
    }

    return;
  }

  const result = await executeScan(options);
  printScanOutput(result, options);

  if (result.shouldFail) {
    process.exitCode = 1;
  }
}
