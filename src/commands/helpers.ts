import { getProviderReaders } from '../providers/index.js';
import type { AgentProvider, ProviderNotice, SessionArtifact } from '../providers/types.js';

export interface LoadedArtifactsResult {
  providers: AgentProvider[];
  artifacts: SessionArtifact[];
  warnings: ProviderNotice[];
  errors: ProviderNotice[];
}

export function shouldFailRequestedProvider(agent: AgentProvider | undefined, loaded: LoadedArtifactsResult): boolean {
  if (agent === undefined) {
    return false;
  }

  if (loaded.errors.length > 0) {
    return true;
  }

  return loaded.artifacts.length === 0 && loaded.warnings.length > 0;
}

export async function loadArtifacts(agent?: AgentProvider): Promise<LoadedArtifactsResult> {
  const readers = getProviderReaders(agent);
  const artifacts: SessionArtifact[] = [];
  const warnings: ProviderNotice[] = [];
  const errors: ProviderNotice[] = [];

  for (const reader of readers) {
    try {
      const discovery = await reader.discoverSessions();
      warnings.push(...discovery.warnings);
      errors.push(...discovery.errors);

      for (const session of discovery.sessions) {
        try {
          const artifact = await reader.loadSession(session);
          artifacts.push(artifact);
          warnings.push(...artifact.warnings);
        } catch (error) {
          errors.push({
            provider: reader.provider,
            level: 'error',
            sessionId: session.sessionId,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      }
    } catch (error) {
      errors.push({
        provider: reader.provider,
        level: 'error',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return {
    providers: readers.map((reader) => reader.provider),
    artifacts,
    warnings,
    errors,
  };
}
