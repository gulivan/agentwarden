import type { SessionArtifact, StringFieldRef } from '../providers/types.js';
import { buildMaskedValuesBatch } from './native.js';
import type { DetectionOptions } from './options.js';
import type { DetectionSpan } from './types.js';
import type { AnalysisResult, AnalyzedSession, FindingGroup, SessionFinding, SpottedEntry } from './types.js';

export interface AnalysisAccumulatorOptions {
  retainSessions?: boolean;
  detectionOptions?: DetectionOptions;
}

export interface ScanFinding {
  fingerprint: string;
  preview: string;
  rawSample?: string;
  type: SessionFinding['type'];
}

export interface ScanSessionAnalysis {
  findings: ScanFinding[];
  hasChanges: boolean;
  provider: SessionFinding['provider'];
  sessionId: string;
}

export interface AnalysisAccumulator {
  addArtifact(artifact: SessionArtifact): void;
  addSessionAnalysis(analysis: ScanSessionAnalysis): void;
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

function toScanFinding(finding: Pick<SessionFinding, 'fingerprint' | 'preview' | 'rawSample' | 'type'>): ScanFinding {
  return {
    fingerprint: finding.fingerprint,
    preview: finding.preview,
    ...(finding.rawSample === undefined ? {} : { rawSample: finding.rawSample }),
    type: finding.type,
  };
}

function pushUniqueRawSample(samples: string[], rawSample?: string): void {
  if (rawSample === undefined || samples.length >= 3 || samples.includes(rawSample)) {
    return;
  }

  samples.push(rawSample);
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

export function analyzeArtifact(artifact: SessionArtifact, detectionOptions?: DetectionOptions): AnalyzedSession {
  const findings: SessionFinding[] = [];
  const maskedFields = buildMaskedValuesBatch(artifact.fields, detectionOptions);
  const fieldPlans = artifact.fields.flatMap((field, index) => {
    const maskedField = maskedFields[index];

    if (maskedField === undefined) {
      return [];
    }

    const fieldFindings = toSessionFindings(artifact, field, maskedField.findings);
    findings.push(...fieldFindings);

    if (!shouldCreateFieldPlan(field, maskedField.findings) || maskedField.nextValue === field.value) {
      return [];
    }

    return [{ field, findings: fieldFindings, nextValue: maskedField.nextValue }];
  });

  return { artifact, findings, fieldPlans };
}


export function analyzeArtifactForScan(artifact: SessionArtifact, detectionOptions?: DetectionOptions): ScanSessionAnalysis {
  const analyzedSession = analyzeArtifact(artifact, detectionOptions);

  return {
    provider: artifact.handle.provider,
    sessionId: artifact.handle.sessionId,
    findings: analyzedSession.findings.map(toScanFinding),
    hasChanges: analyzedSession.fieldPlans.length > 0,
  };
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

  const addSessionAnalysis = (analysis: ScanSessionAnalysis): void => {
    const providerSummary = summary.providers[analysis.provider];
    providerSummary.sessions += 1;
    providerSummary.findings += analysis.findings.length;

    if (analysis.findings.length > 0) {
      summary.sessionsWithFindings += 1;
    }

    if (analysis.hasChanges) {
      providerSummary.changes += 1;
      summary.sessionsWithChanges += 1;
    }

    summary.sessions += 1;
    summary.findings += analysis.findings.length;

    for (const finding of analysis.findings) {
        const key = `${analysis.provider}:${analysis.sessionId}:${finding.type}`;
        const current = groupMap.get(key);

        if (current === undefined) {
          groupMap.set(key, {
            provider: analysis.provider,
            sessionId: analysis.sessionId,
            type: finding.type,
            count: 1,
            previews: [finding.preview],
            rawSamples: finding.rawSample === undefined ? [] : [finding.rawSample],
            fingerprints: [finding.fingerprint],
          });
        } else {
          current.count += 1;

          if (!current.previews.includes(finding.preview) && current.previews.length < 3) {
            current.previews.push(finding.preview);
          }

          pushUniqueRawSample(current.rawSamples, finding.rawSample);

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
            rawSamples: finding.rawSample === undefined ? [] : [finding.rawSample],
            providers: new Set([analysis.provider]),
            sessions: new Set([`${analysis.provider}:${analysis.sessionId}`]),
            types: new Set([finding.type]),
          });
          continue;
        }

        entry.findings += 1;

        if (!entry.previews.includes(finding.preview) && entry.previews.length < 3) {
          entry.previews.push(finding.preview);
        }

        pushUniqueRawSample(entry.rawSamples, finding.rawSample);

        entry.providers.add(analysis.provider);
        entry.sessions.add(`${analysis.provider}:${analysis.sessionId}`);
        entry.types.add(finding.type);
      }
    };

  return {
    addArtifact(artifact) {
      const analyzedSession = analyzeArtifact(artifact, options.detectionOptions);

      if (retainSessions) {
        analyzedSessions.push(analyzedSession);
      }

      addSessionAnalysis({
        provider: artifact.handle.provider,
        sessionId: artifact.handle.sessionId,
        findings: analyzedSession.findings.map(toScanFinding),
        hasChanges: analyzedSession.fieldPlans.length > 0,
      });
    },
    addSessionAnalysis,
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
