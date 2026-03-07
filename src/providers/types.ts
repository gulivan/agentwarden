export const AGENT_PROVIDERS = ['codex', 'claude', 'gemini', 'opencode'] as const;

export type AgentProvider = (typeof AGENT_PROVIDERS)[number];

export type MaskPolicy = 'safe' | 'conditional' | 'report_only';

export type ProviderNoticeLevel = 'warning' | 'error';

export interface ProviderNotice {
  provider: AgentProvider;
  level: ProviderNoticeLevel;
  message: string;
  sessionId?: string;
}

export interface BackupTarget {
  kind: 'file' | 'sqlite';
  path: string;
}

export interface SessionHandle {
  provider: AgentProvider;
  sessionId: string;
  location: string;
  title?: string;
  metadata?: Record<string, string>;
}

export interface StringFieldRef {
  id: string;
  path: string;
  sourceLabel: string;
  value: string;
  maskPolicy: MaskPolicy;
  contextKey?: string;
  setValue(nextValue: string): void;
}

export interface PersistResult {
  writes: string[];
  warnings: ProviderNotice[];
}

export interface SessionArtifact {
  handle: SessionHandle;
  fields: StringFieldRef[];
  warnings: ProviderNotice[];
  backupTargets: BackupTarget[];
  writeChanges(): Promise<PersistResult>;
}

export interface ProviderDiscoveryResult {
  sessions: SessionHandle[];
  warnings: ProviderNotice[];
  errors: ProviderNotice[];
}

export interface ProviderReader {
  provider: AgentProvider;
  discoverSessions(): Promise<ProviderDiscoveryResult>;
  loadSession(handle: SessionHandle): Promise<SessionArtifact>;
}
