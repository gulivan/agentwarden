import type { SessionArtifact, StringFieldRef } from '../providers/types.js';
import { buildMaskedValue } from './detector.js';
import type { DetectionOptions } from './options.js';
import type { DetectionSpan } from './types.js';
import type { AnalysisResult, AnalyzedSession, FindingGroup, SessionFinding, SpottedEntry } from './types.js';

export interface AnalysisAccumulatorOptions {
  retainSessions?: boolean;
  detectionOptions?: DetectionOptions;
}

export interface AnalysisAccumulator {
  addArtifact(artifact: SessionArtifact): void;
  build(): AnalysisResult;
}

interface MutableSpottedEntry {
  fingerprint: string;
  findings: number;
  previews: string[];
  rawSamples: string[];
  providers: Set<SessionFinding['provider']>;
  sessions: Set<string>;
  types: Set<SessionFinding['type']>;
}

function createProviderSummary(): AnalysisResult['summary']['providers'] {
  return {
    codex: { sessions: 0, findings: 0, changes: 0 },
    claude: { sessions: 0, findings: 0, changes: 0 },
    gemini: { sessions: 0, findings: 0, changes: 0 },
    opencode: { sessions: 0, findings: 0, changes: 0 },
  };
}

function toSessionFindings(
  artifact: SessionArtifact,
  field: StringFieldRef,
  spans: readonly DetectionSpan[],
): SessionFinding[] {
  return spans.map((span) => ({
    provider: artifact.handle.provider,
    sessionId: artifact.handle.sessionId,
    type: span.type,
    fieldId: field.id,
    fieldPath: field.path,
    sourceLabel: field.sourceLabel,
    preview: span.preview,
    rawSample: span.rawValue,
    fingerprint: span.fingerprint,
    maskPolicy: field.maskPolicy,
  }));
}

function canConditionallyMask(fieldValue: string, spans: readonly DetectionSpan[]): boolean {
  if (spans.length !== 1) {
    return false;
  }

  const span = spans[0];

  if (span === undefined) {
    return false;
  }

  const remainder = `${fieldValue.slice(0, span.start)}${fieldValue.slice(span.end)}`;
  return /^[\s"'`]*$/.test(remainder);
}

function shouldCreateFieldPlan(field: StringFieldRef, spans: readonly DetectionSpan[]): boolean {
  if (spans.length === 0 || field.maskPolicy === 'report_only') {
    return false;
  }

  if (field.maskPolicy === 'conditional') {
    return canConditionallyMask(field.value, spans);
  }

  return true;
}

function analyzeArtifact(artifact: SessionArtifact, detectionOptions?: DetectionOptions): AnalyzedSession {
  const findings: SessionFinding[] = [];
  const fieldPlans = artifact.fields.flatMap((field) => {
    const maskedField = buildMaskedValue(field, detectionOptions);
    const fieldFindings = toSessionFindings(artifact, field, maskedField.findings);
    findings.push(...fieldFindings);

    if (!shouldCreateFieldPlan(field, maskedField.findings) || maskedField.nextValue === field.value) {
      return [];
    }

    return [{ field, findings: fieldFindings, nextValue: maskedField.nextValue }];
  });

  return { artifact, findings, fieldPlans };
}

function sortFindingGroups(groups: Iterable<FindingGroup>): FindingGroup[] {
  return [...groups].sort((left, right) => {
    if (left.provider !== right.provider) {
      return left.provider.localeCompare(right.provider);
    }

    if (left.sessionId !== right.sessionId) {
      return left.sessionId.localeCompare(right.sessionId);
    }

    return left.type.localeCompare(right.type);
  });
}

function sortSpottedEntries(entries: Iterable<SpottedEntry>): SpottedEntry[] {
  return [...entries].sort((left, right) => {
    if (left.findings !== right.findings) {
      return right.findings - left.findings;
    }

    if (left.sessions !== right.sessions) {
      return right.sessions - left.sessions;
    }

    return left.fingerprint.localeCompare(right.fingerprint);
  });
}

export function createAnalysisAccumulator(options: AnalysisAccumulatorOptions = {}): AnalysisAccumulator {
  const analyzedSessions: AnalyzedSession[] = [];
  const retainSessions = options.retainSessions ?? true;
  const groupMap = new Map<string, FindingGroup>();
  const spottedEntryMap = new Map<string, MutableSpottedEntry>();
  const summary: AnalysisResult['summary'] = {
    sessions: 0,
    findings: 0,
    sessionsWithFindings: 0,
    sessionsWithChanges: 0,
    providers: createProviderSummary(),
  };

  return {
    addArtifact(artifact) {
      const analyzedSession = analyzeArtifact(artifact, options.detectionOptions);

      if (retainSessions) {
        analyzedSessions.push(analyzedSession);
      }

      const providerSummary = summary.providers[artifact.handle.provider];
      providerSummary.sessions += 1;
      providerSummary.findings += analyzedSession.findings.length;

      if (analyzedSession.findings.length > 0) {
        summary.sessionsWithFindings += 1;
      }

      if (analyzedSession.fieldPlans.length > 0) {
        providerSummary.changes += 1;
        summary.sessionsWithChanges += 1;
      }

      summary.sessions += 1;
      summary.findings += analyzedSession.findings.length;

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
            rawSamples: [finding.rawSample],
            fingerprints: [finding.fingerprint],
          });
        } else {
          current.count += 1;

          if (!current.previews.includes(finding.preview) && current.previews.length < 3) {
            current.previews.push(finding.preview);
          }

          if (!current.rawSamples.includes(finding.rawSample) && current.rawSamples.length < 3) {
            current.rawSamples.push(finding.rawSample);
          }

          if (!current.fingerprints.includes(finding.fingerprint)) {
            current.fingerprints.push(finding.fingerprint);
          }
        }

        const entry = spottedEntryMap.get(finding.fingerprint);

        if (entry === undefined) {
          spottedEntryMap.set(finding.fingerprint, {
            fingerprint: finding.fingerprint,
            findings: 1,
            previews: [finding.preview],
            rawSamples: [finding.rawSample],
            providers: new Set([finding.provider]),
            sessions: new Set([`${finding.provider}:${finding.sessionId}`]),
            types: new Set([finding.type]),
          });
          continue;
        }

        entry.findings += 1;

        if (!entry.previews.includes(finding.preview) && entry.previews.length < 3) {
          entry.previews.push(finding.preview);
        }

        if (!entry.rawSamples.includes(finding.rawSample) && entry.rawSamples.length < 3) {
          entry.rawSamples.push(finding.rawSample);
        }

        entry.providers.add(finding.provider);
        entry.sessions.add(`${finding.provider}:${finding.sessionId}`);
        entry.types.add(finding.type);
      }
    },
    build() {
      return {
        analyzedSessions,
        findingGroups: sortFindingGroups(groupMap.values()),
        spottedEntries: sortSpottedEntries(
          [...spottedEntryMap.values()].map((entry) => ({
            fingerprint: entry.fingerprint,
            findings: entry.findings,
            previews: [...entry.previews],
            rawSamples: [...entry.rawSamples],
            providers: [...entry.providers].sort((left, right) => left.localeCompare(right)),
            sessions: entry.sessions.size,
            types: [...entry.types].sort((left, right) => left.localeCompare(right)),
          })),
        ),
        summary: {
          sessions: summary.sessions,
          findings: summary.findings,
          sessionsWithFindings: summary.sessionsWithFindings,
          sessionsWithChanges: summary.sessionsWithChanges,
          providers: {
            codex: { ...summary.providers.codex },
            claude: { ...summary.providers.claude },
            gemini: { ...summary.providers.gemini },
            opencode: { ...summary.providers.opencode },
          },
        },
      };
    },
  };
}

export function analyzeArtifacts(artifacts: SessionArtifact[], detectionOptions?: DetectionOptions): AnalysisResult {
  const accumulator = createAnalysisAccumulator({ detectionOptions });
  artifacts.forEach((artifact) => accumulator.addArtifact(artifact));
  return accumulator.build();
}
