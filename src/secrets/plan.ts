import type { SessionArtifact } from '../providers/types.js';
import { buildMaskedValue, findingsForField } from './detector.js';
import type { AnalysisResult, AnalyzedSession, FindingGroup } from './types.js';

export function analyzeArtifacts(artifacts: SessionArtifact[]): AnalysisResult {
  const analyzedSessions: AnalyzedSession[] = artifacts.map((artifact) => {
    const findings = artifact.fields.flatMap((field) => findingsForField(artifact.handle, field));
    const fieldPlans = artifact.fields.flatMap((field) => {
      const fieldFindings = findings.filter((finding) => finding.fieldId === field.id);

      if (fieldFindings.length === 0 || field.maskPolicy === 'report_only') {
        return [];
      }

      const { nextValue } = buildMaskedValue(field);

      if (nextValue === field.value) {
        return [];
      }

      return [{ field, findings: fieldFindings, nextValue }];
    });

    return { artifact, findings, fieldPlans };
  });

  const groupMap = new Map<string, FindingGroup>();

  for (const analyzedSession of analyzedSessions) {
    for (const finding of analyzedSession.findings) {
      const key = `${finding.provider}:${finding.sessionId}:${finding.type}`;
      const current = groupMap.get(key);

      if (current === undefined) {
        groupMap.set(key, {
          provider: finding.provider,
          sessionId: finding.sessionId,
          type: finding.type,
          count: 1,
          previews: [finding.preview],
          fingerprints: [finding.fingerprint],
        });
        continue;
      }

      current.count += 1;

      if (!current.previews.includes(finding.preview) && current.previews.length < 3) {
        current.previews.push(finding.preview);
      }

      if (!current.fingerprints.includes(finding.fingerprint)) {
        current.fingerprints.push(finding.fingerprint);
      }
    }
  }

  const providers = {
    codex: { sessions: 0, findings: 0, changes: 0 },
    claude: { sessions: 0, findings: 0, changes: 0 },
    gemini: { sessions: 0, findings: 0, changes: 0 },
    opencode: { sessions: 0, findings: 0, changes: 0 },
  };

  analyzedSessions.forEach((session) => {
    providers[session.artifact.handle.provider].sessions += 1;
    providers[session.artifact.handle.provider].findings += session.findings.length;

    if (session.fieldPlans.length > 0) {
      providers[session.artifact.handle.provider].changes += 1;
    }
  });

  return {
    analyzedSessions,
    findingGroups: [...groupMap.values()].sort((left, right) => {
      if (left.provider !== right.provider) {
        return left.provider.localeCompare(right.provider);
      }

      if (left.sessionId !== right.sessionId) {
        return left.sessionId.localeCompare(right.sessionId);
      }

      return left.type.localeCompare(right.type);
    }),
    summary: {
      sessions: analyzedSessions.length,
      findings: analyzedSessions.reduce((total, session) => total + session.findings.length, 0),
      sessionsWithFindings: analyzedSessions.filter((session) => session.findings.length > 0).length,
      sessionsWithChanges: analyzedSessions.filter((session) => session.fieldPlans.length > 0).length,
      providers,
    },
  };
}
