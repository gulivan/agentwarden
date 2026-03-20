import { SECRET_TYPES, type SecretType } from './types.js';

export interface SecretTypeDefinition {
  type: SecretType;
  groupId: SecretTypeGroupId;
  description: string;
  example: string;
}

export interface SecretTypeGroupDefinition {
  id: string;
  label: string;
  description: string;
  showMembers?: boolean;
  types: readonly SecretType[];
}

export const SECRET_TYPE_GROUPS = [
  {
    id: 'high_precision',
    label: 'High precision',
    description: 'Lower-noise secret types that skip user data and fuzzier heuristics.',
    showMembers: false,
    types: ['authorization_header', 'signed_query', 'basic_auth', 'private_key', 'jwt', 'raw_token', 'url_credentials'],
  },
  {
    id: 'api_keys',
    label: 'API keys & tokens',
    description: 'Assignments, signed URLs, raw tokens, and encoded secret blobs.',
    types: ['secret_assignment', 'signed_query', 'raw_token', 'base64_secret'],
  },
  {
    id: 'session_auth',
    label: 'Session & auth data',
    description: 'Headers, cookies, and JWTs used to authenticate requests.',
    types: ['authorization_header', 'cookie', 'basic_auth', 'jwt'],
  },
  {
    id: 'credentials',
    label: 'Credentials & private keys',
    description: 'Credentials embedded in URLs plus PEM private keys.',
    types: ['url_credentials', 'private_key'],
  },
  {
    id: 'user_data',
    label: 'User data',
    description: 'Personal identifiers exposed in session content.',
    types: ['path_username', 'email'],
  },
] as const satisfies readonly SecretTypeGroupDefinition[];

export type SecretTypeGroupId = (typeof SECRET_TYPE_GROUPS)[number]['id'];

export const SECRET_TYPE_DEFINITIONS: Record<SecretType, SecretTypeDefinition> = {
  secret_assignment: {
    type: 'secret_assignment',
    groupId: 'api_keys',
    description:
      'Sensitive-looking keys assigned directly to a value, such as API keys, tokens, passwords, authorization values, or cookies.',
    example: 'api_key=sk-example1234567890',
  },
  authorization_header: {
    type: 'authorization_header',
    groupId: 'session_auth',
    description: '`Authorization` or `Proxy-Authorization` headers that use `Bearer`, `Basic`, or `Token`.',
    example: 'Authorization: Bearer sk-example1234567890',
  },
  cookie: {
    type: 'cookie',
    groupId: 'session_auth',
    description: '`Cookie` or `Set-Cookie` header values that may contain session IDs or other secrets.',
    example: 'Cookie: session_token=abc123def456ghi789',
  },
  url_credentials: {
    type: 'url_credentials',
    groupId: 'credentials',
    description: 'Credentials embedded directly in a URL before the host, such as `user:password@`.',
    example: 'https://alice:super-secret@example.com/private',
  },
  signed_query: {
    type: 'signed_query',
    groupId: 'api_keys',
    description:
      'Sensitive query parameter values such as `access_token`, `api_key`, `signature`, `x-amz-signature`, or `x-goog-signature`.',
    example: 'https://example.com/download?access_token=tok_example_1234567890',
  },
  basic_auth: {
    type: 'basic_auth',
    groupId: 'session_auth',
    description: 'Base64 credentials inside an HTTP Basic auth header.',
    example: 'Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l',
  },
  base64_secret: {
    type: 'base64_secret',
    groupId: 'api_keys',
    description:
      'Standalone Base64 text that decodes to secret-looking content such as `token=...`, `password:...`, or `client_secret=...`.',
    example: 'dG9rZW49c2stZXhhbXBsZTEyMzQ1Ng==',
  },
  private_key: {
    type: 'private_key',
    groupId: 'credentials',
    description: 'PEM-formatted private keys such as RSA, EC, DSA, OpenSSH, or PGP blocks.',
    example: '-----BEGIN PRIVATE KEY-----',
  },
  jwt: {
    type: 'jwt',
    groupId: 'session_auth',
    description: 'JSON Web Tokens with the usual three-part `header.payload.signature` format.',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz',
  },
  raw_token: {
    type: 'raw_token',
    groupId: 'api_keys',
    description: 'Known token formats from common providers, such as OpenAI, Anthropic, GitHub, Google, or Slack.',
    example: 'ghp_1234567890abcdefghijklmnop',
  },
  path_username: {
    type: 'path_username',
    groupId: 'user_data',
    description: 'Usernames exposed in local filesystem paths such as `/Users/name`, `/home/name`, or `C:\\Users\\name`.',
    example: '/Users/alice/.codex/sessions',
  },
  email: {
    type: 'email',
    groupId: 'user_data',
    description: 'Email addresses found in session content.',
    example: 'alice@example.com',
  },
};

const SECRET_TYPE_GROUP_MAP = new Map<SecretTypeGroupId, (typeof SECRET_TYPE_GROUPS)[number]>(
  SECRET_TYPE_GROUPS.map((group) => [group.id, group]),
);

export interface ExpandedSecretFilterTokens {
  groups: SecretTypeGroupId[];
  invalid: string[];
  types: SecretType[];
}

export function isSecretTypeGroupId(value: string): value is SecretTypeGroupId {
  return SECRET_TYPE_GROUP_MAP.has(value as SecretTypeGroupId);
}

export function expandSecretFilterTokens(tokens: readonly string[]): ExpandedSecretFilterTokens {
  const selectedGroups = new Set<SecretTypeGroupId>();
  const selectedTypes = new Set<SecretType>();
  const invalid: string[] = [];

  for (const token of tokens) {
    const trimmed = token.trim();

    if (trimmed.length === 0) {
      continue;
    }

    const normalized = trimmed.toLowerCase();

    if (SECRET_TYPES.includes(normalized as SecretType)) {
      selectedTypes.add(normalized as SecretType);
      continue;
    }

    if (isSecretTypeGroupId(normalized)) {
      selectedGroups.add(normalized);
      SECRET_TYPE_GROUP_MAP.get(normalized)?.types.forEach((type) => selectedTypes.add(type));
      continue;
    }

    invalid.push(trimmed);
  }

  return {
    groups: SECRET_TYPE_GROUPS.filter((group) => selectedGroups.has(group.id)).map((group) => group.id),
    invalid,
    types: SECRET_TYPES.filter((type) => selectedTypes.has(type)),
  };
}

export function formatSecretFilterChoices(): string {
  return [...SECRET_TYPE_GROUPS.map((group) => group.id), ...SECRET_TYPES].join(', ');
}

export const USER_DATA_TYPES = new Set<SecretType>(
  SECRET_TYPE_GROUPS.find((group) => group.id === 'user_data')?.types ?? [],
);

export const DEFAULT_SCAN_TYPES: readonly SecretType[] = SECRET_TYPES.filter((type) => !USER_DATA_TYPES.has(type));

export function getSecretTypeDefinition(type: SecretType): SecretTypeDefinition {
  return SECRET_TYPE_DEFINITIONS[type];
}
