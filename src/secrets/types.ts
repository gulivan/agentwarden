import type { AgentProvider, MaskPolicy, SessionArtifact, StringFieldRef } from '../providers/types.js';

export type SecretType =
  | 'secret_assignment'
  | 'authorization_header'
  | 'cookie'
  | 'url_credentials'
  | 'signed_query'
  | 'basic_auth'
  | 'base64_secret'
  | 'private_key'
  | 'jwt'
  | 'raw_token'
  | 'path_username'
  | 'email';

export interface DetectionSpan {
  type: SecretType;
  start: number;
  end: number;
  rawValue: string;
  replacement: string;
  preview: string;
  confidence: number;
  fingerprint: string;
}

export interface SessionFinding {
  provider: AgentProvider;
  sessionId: string;
  type: SecretType;
  fieldId: string;
  fieldPath: string;
  sourceLabel: string;
  preview: string;
  fingerprint: string;
  maskPolicy: MaskPolicy;
}

export interface FieldPlan {
  field: StringFieldRef;
  findings: SessionFinding[];
  nextValue: string;
}

export interface FindingGroup {
  provider: AgentProvider;
  sessionId: string;
  type: SecretType;
  count: number;
  previews: string[];
  fingerprints: string[];
}

export interface AnalyzedSession {
  artifact: SessionArtifact;
  findings: SessionFinding[];
  fieldPlans: FieldPlan[];
}

export interface ScanSummary {
  sessions: number;
  findings: number;
  sessionsWithFindings: number;
  sessionsWithChanges: number;
  providers: Record<AgentProvider, { sessions: number; findings: number; changes: number }>;
}

export interface AnalysisResult {
  analyzedSessions: AnalyzedSession[];
  findingGroups: FindingGroup[];
  summary: ScanSummary;
}
