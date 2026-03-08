import { availableParallelism } from 'node:os';
import { getProviderReaders } from '../providers/index.js';
import { AGENT_PROVIDERS, type AgentProvider, type ProviderNotice, type SessionArtifact } from '../providers/types.js';

const DEFAULT_MAX_LOAD_CONCURRENCY = 12;

export interface ProviderSelectionOptions {
  agent?: AgentProvider;
  agents?: AgentProvider[];
}

export interface LoadArtifactsOptions extends ProviderSelectionOptions {
  collectArtifacts?: boolean;
  progressLabel?: string;
  onArtifactLoaded?: (artifact: SessionArtifact) => void | Promise<void>;
}

export interface LoadedArtifactsResult {
  providers: AgentProvider[];
  artifacts: SessionArtifact[];
  warnings: ProviderNotice[];
  errors: ProviderNotice[];
  loadedSessions: number;
}

export function resolveProviderSelection(options: ProviderSelectionOptions = {}): AgentProvider[] | undefined {
  const selected = new Set<AgentProvider>();

  if (options.agent !== undefined) {
    selected.add(options.agent);
  }

  options.agents?.forEach((agent) => selected.add(agent));

  if (selected.size === 0) {
    return undefined;
  }

  return AGENT_PROVIDERS.filter((provider) => selected.has(provider));
}

export function formatProviderSelection(providers?: readonly AgentProvider[]): string {
  return providers === undefined || providers.length === 0 ? 'all' : providers.join(', ');
}

export function shouldFailRequestedProvider(
  requestedProviders: readonly AgentProvider[] | undefined,
  loaded: LoadedArtifactsResult,
): boolean {
  if (requestedProviders === undefined || requestedProviders.length === 0) {
    return false;
  }

  if (loaded.errors.length > 0) {
    return true;
  }

  return loaded.loadedSessions === 0 && loaded.warnings.length > 0;
}

class ProgressReporter {
  private activeWidth = 0;
  private readonly interactive = process.stderr.isTTY === true;

  isInteractive(): boolean {
    return this.interactive;
  }

  log(message: string): void {
    this.clear();
    process.stderr.write(`${message}\n`);
  }

  update(message: string): void {
    if (!this.interactive) {
      this.log(message);
      return;
    }

    const padded = message.padEnd(this.activeWidth, ' ');
    process.stderr.write(`\r${padded}`);
    this.activeWidth = message.length;
  }

  complete(message: string): void {
    if (this.interactive) {
      const padded = message.padEnd(this.activeWidth, ' ');
      process.stderr.write(`\r${padded}\n`);
      this.activeWidth = 0;
      return;
    }

    this.log(message);
  }

  private clear(): void {
    if (!this.interactive || this.activeWidth === 0) {
      return;
    }

    process.stderr.write(`\r${''.padEnd(this.activeWidth, ' ')}\r`);
    this.activeWidth = 0;
  }
}

function formatProgressBar(current: number, total: number, width = 24): string {
  const safeTotal = Math.max(total, 1);
  const ratio = Math.min(current / safeTotal, 1);
  const filled = Math.round(ratio * width);
  return `[${'='.repeat(filled)}${'-'.repeat(width - filled)}] ${current}/${total} ${Math.round(ratio * 100)}%`;
}

function shouldEmitProgress(
  processed: number,
  total: number,
  previousProcessed: number,
  lastUpdateAt: number,
  interactive: boolean,
): boolean {
  if (processed === 1 || processed === total) {
    return true;
  }

  if (interactive) {
    if (processed - previousProcessed >= 25) {
      return true;
    }

    return Date.now() - lastUpdateAt >= 125;
  }

  const stepSize = Math.max(25, Math.ceil(total / 20));

  if (processed - previousProcessed >= stepSize) {
    return true;
  }

  return Date.now() - lastUpdateAt >= 1000;
}

function parseConfiguredConcurrency(): number | undefined {
  const rawValue = process.env.AGENTWARDEN_LOAD_CONCURRENCY?.trim();

  if (rawValue === undefined || rawValue.length === 0) {
    return undefined;
  }

  const parsed = Number(rawValue);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function getLoadConcurrency(total: number): number {
  if (total <= 0) {
    return 0;
  }

  const configuredConcurrency = parseConfiguredConcurrency();

  if (configuredConcurrency !== undefined) {
    return Math.min(total, configuredConcurrency);
  }

  const parallelism = availableParallelism();
  return Math.min(total, Math.max(2, Math.min(parallelism * 2, DEFAULT_MAX_LOAD_CONCURRENCY)));
}

export async function loadArtifacts(options: LoadArtifactsOptions = {}): Promise<LoadedArtifactsResult> {
  const readers = getProviderReaders(resolveProviderSelection(options));
  const artifacts: SessionArtifact[] = [];
  const warnings: ProviderNotice[] = [];
  const errors: ProviderNotice[] = [];
  const collectArtifacts = options.collectArtifacts ?? true;
  const progressLabel = options.progressLabel ?? 'loading';
  const reporter = new ProgressReporter();
  let loadedSessions = 0;

  for (const reader of readers) {
    reporter.log(`[${reader.provider}] discovering sessions...`);

    try {
      const discovery = await reader.discoverSessions();
      warnings.push(...discovery.warnings);
      errors.push(...discovery.errors);

      const total = discovery.sessions.length;
      const concurrency = getLoadConcurrency(total);
      const providerArtifacts = collectArtifacts ? new Array<SessionArtifact | undefined>(total) : undefined;

      reporter.log(`[${reader.provider}] found ${total} sessions`);

      let nextIndex = 0;
      let completedSessions = 0;
      let previousProgressCount = 0;
      let lastProgressUpdateAt = 0;

      const loadNextSession = async (): Promise<void> => {
        while (true) {
          const currentIndex = nextIndex;
          nextIndex += 1;

          if (currentIndex >= total) {
            return;
          }

          const session = discovery.sessions[currentIndex];

          if (session === undefined) {
            completedSessions += 1;
            continue;
          }

          try {
            const artifact = await reader.loadSession(session);
            loadedSessions += 1;

            if (providerArtifacts !== undefined) {
              providerArtifacts[currentIndex] = artifact;
            }

            await options.onArtifactLoaded?.(artifact);
            warnings.push(...artifact.warnings);
          } catch (error) {
            errors.push({
              provider: reader.provider,
              level: 'error',
              sessionId: session.sessionId,
              message: error instanceof Error ? error.message : String(error),
            });
          }

          completedSessions += 1;

          if (
            shouldEmitProgress(
              completedSessions,
              total,
              previousProgressCount,
              lastProgressUpdateAt,
              reporter.isInteractive(),
            )
          ) {
            reporter.update(`[${reader.provider}] ${progressLabel} ${formatProgressBar(completedSessions, total)}`);
            previousProgressCount = completedSessions;
            lastProgressUpdateAt = Date.now();
          }
        }
      };

      if (concurrency > 0) {
        await Promise.all(Array.from({ length: concurrency }, () => loadNextSession()));
      }

      if (providerArtifacts !== undefined) {
        artifacts.push(...providerArtifacts.filter((artifact): artifact is SessionArtifact => artifact !== undefined));
      }

      if (total > 0) {
        reporter.complete(`[${reader.provider}] ${progressLabel} complete (${total} sessions)`);
      }
    } catch (error) {
      errors.push({
        provider: reader.provider,
        level: 'error',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  reporter.log(`${progressLabel === 'scanning' ? 'scanned' : 'loaded'} ${loadedSessions} sessions`);

  return {
    providers: readers.map((reader) => reader.provider),
    artifacts,
    warnings,
    errors,
    loadedSessions,
  };
}
