import { AGENT_PROVIDERS, type AgentProvider } from '../providers/types.js';
import type { ResolvedSecretTypeSelection } from '../secrets/options.js';
import type { AnalysisResult, SecretType } from '../secrets/types.js';

export interface ScanTypeSummary {
  type: SecretType;
  findings: number;
  sessions: number;
}

export interface ScanProviderSummary {
  provider: AgentProvider;
  sessions: number;
  findings: number;
  sessionsWithFindings: number;
  changes: number;
}

export interface ScanSessionSummary {
  provider: AgentProvider;
  sessionId: string;
  findings: number;
  types: SecretType[];
}

export interface ScanEntrySummary {
  fingerprint: string;
  findings: number;
  previews: string[];
  rawSamples: string[];
  providers: AgentProvider[];
  sessions: number;
  types: SecretType[];
}

export interface ScanReport {
  filters: {
    includeTypes: SecretType[];
    excludeTypes: SecretType[];
    checkedTypes: SecretType[];
    allTypesEnabled: boolean;
  };
  byType: ScanTypeSummary[];
  byProvider: ScanProviderSummary[];
  bySession: ScanSessionSummary[];
  byEntry: ScanEntrySummary[];
}

export function buildScanReport(
  result: AnalysisResult,
  providers: AgentProvider[],
  filters: ResolvedSecretTypeSelection,
): ScanReport {
  const byType = new Map<SecretType, ScanTypeSummary>();
  const bySession = new Map<string, { provider: AgentProvider; sessionId: string; findings: number; types: Set<SecretType> }>();
  const sessionsWithFindingsByProvider = new Map<AgentProvider, Set<string>>();

  for (const group of result.findingGroups) {
    const typeSummary = byType.get(group.type);

    if (typeSummary === undefined) {
      byType.set(group.type, {
        type: group.type,
        findings: group.count,
        sessions: 1,
      });
    } else {
      typeSummary.findings += group.count;
      typeSummary.sessions += 1;
    }

    const sessionKey = `${group.provider}:${group.sessionId}`;
    const sessionSummary = bySession.get(sessionKey);

    if (sessionSummary === undefined) {
      bySession.set(sessionKey, {
        provider: group.provider,
        sessionId: group.sessionId,
        findings: group.count,
        types: new Set([group.type]),
      });
    } else {
      sessionSummary.findings += group.count;
      sessionSummary.types.add(group.type);
    }

    const currentSessions = sessionsWithFindingsByProvider.get(group.provider);

    if (currentSessions === undefined) {
      sessionsWithFindingsByProvider.set(group.provider, new Set([group.sessionId]));
    } else {
      currentSessions.add(group.sessionId);
    }
  }

  const scannedProviders = AGENT_PROVIDERS.filter(
    (provider) => providers.includes(provider) || result.summary.providers[provider].sessions > 0,
  );

  return {
    filters: {
      includeTypes: [...filters.includeTypes],
      excludeTypes: [...filters.excludeTypes],
      checkedTypes: [...filters.checkedTypes],
      allTypesEnabled: filters.allTypesEnabled,
    },
    byType: [...byType.values()].sort((left, right) => {
      if (left.findings !== right.findings) {
        return right.findings - left.findings;
      }

      return left.type.localeCompare(right.type);
    }),
    byProvider: scannedProviders
      .map((provider) => ({
        provider,
        sessions: result.summary.providers[provider].sessions,
        findings: result.summary.providers[provider].findings,
        sessionsWithFindings: sessionsWithFindingsByProvider.get(provider)?.size ?? 0,
        changes: result.summary.providers[provider].changes,
      }))
      .sort((left, right) => {
        if (left.findings !== right.findings) {
          return right.findings - left.findings;
        }

        return left.provider.localeCompare(right.provider);
      }),
    bySession: [...bySession.values()]
      .map((session) => ({
        provider: session.provider,
        sessionId: session.sessionId,
        findings: session.findings,
        types: [...session.types].sort((left, right) => left.localeCompare(right)),
      }))
      .sort((left, right) => {
        if (left.findings !== right.findings) {
          return right.findings - left.findings;
        }

        if (left.provider !== right.provider) {
          return left.provider.localeCompare(right.provider);
        }

        return left.sessionId.localeCompare(right.sessionId);
      }),
    byEntry: result.spottedEntries.map((entry) => ({
      fingerprint: entry.fingerprint,
      findings: entry.findings,
      previews: [...entry.previews],
      rawSamples: [...entry.rawSamples],
      providers: [...entry.providers],
      sessions: entry.sessions,
      types: [...entry.types],
    })),
  };
}
