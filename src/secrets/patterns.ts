export const SENSITIVE_ASSIGNMENT_PATTERN =
  /((?:^|[\s,{])(?:[A-Za-z][A-Za-z0-9_.-]*?(?:api[_-]?key|token|secret|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|pwd|authorization|cookie))["']?\s*[:=]\s*["']?)([^\s"'`,}]+)/gim;

export const AUTHORIZATION_HEADER_PATTERN =
  /((?:authorization|proxy-authorization)\b["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{6,})/gim;

export const BARE_BEARER_TOKEN_PATTERN = /(\bBearer\s+)([A-Za-z0-9._~+/=-]{8,})\b/gim;

export const COOKIE_PATTERN = /((?:cookie|set-cookie)\b["']?\s*[:=]\s*["']?)([^\n"']{6,})/gim;

export const URL_CREDENTIALS_PATTERN = /(\b[a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+:[^/\s@]+)(@[^\s?#]+)/gim;

export const SIGNED_QUERY_PATTERN =
  /((?:[?&](?:access_token|refresh_token|token|api[_-]?key|apikey|key|client_secret|signature|sig|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|awsaccesskeyid|password|passwd|pwd)=))([^&#\s]+)/gim;

export const BASIC_AUTH_PATTERN = /(Authorization\b["']?\s*[:=]\s*["']?Basic\s+)([A-Za-z0-9+/]{8,}={0,2})/gim;

export const BASE64_SECRET_PATTERN = /(^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{12,}={0,2})(?=$|[^A-Za-z0-9+/=])/gm;

export const PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g;

export const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

export const RAW_TOKEN_PATTERN =
  /\b(?:sk-[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{12,}|anthropic-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;

export const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

export const PATH_USERNAME_PATTERNS = [
  /\/Users\/([^/\s]+)/g,
  /\/home\/([^/\s]+)/g,
  /[A-Za-z]:[\\/]+Users[\\/]([^\\/\s]+)/g,
];

export const JSON_LIKE_PREFIX = /^[\[{]/;
