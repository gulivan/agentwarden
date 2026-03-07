# Agent Warden

A Bun CLI for scanning local AI agent session storage for exposed secrets and masking them when needed.

## Installation

```bash
bun install
```

## Development

```bash
bun run dev
```

## Build

```bash
bun run build
```

## Commands

### Scan sessions

`scan` reads local session data, checks it for exposed values, and prints a report.
By default it checks all finding types and shows a high-level summary:

- totals across all scanned sessions
- findings by provider
- findings by type
- top sessions with the most findings

When you run `scan` in a terminal with no filters, Agent Warden opens an interactive wizard with keyboard selectors. Use `↑` / `↓` to move, `space` to toggle multi-select rows, and `enter` to continue. The wizard lets you:

1. select all clients or a subset of clients
2. select all finding types or a custom mix of groups and individual types
3. choose whether to show no values, masked examples, or raw values in the report
4. run the scan, then optionally show aggregate spotted stats, save the report to a file, and mask findings

Use `--details` when you want the per-session per-type breakdown table.
Use `--samples` when you want masked example values in the output. Samples are already redacted and usually keep only a safe beginning and ending, like `sk-ant****9xyz`.
Use `--direct` to skip the interactive wizard.

Saved reports go to `~/.agentwarden/reports`. Agent Warden creates that directory with owner-only permissions. If you choose `--raw-samples`, any saved report will contain those raw values too.

```bash
bun run src/index.ts scan
```

Useful flags:

- `--agent <agent>`: scan only one provider (`codex`, `claude`, `gemini`, `opencode`)
- `--agents <agents>`: scan a comma-separated list of providers
- `--json`: emit JSON output
- `--details`: include the per-session breakdown table
- `--samples`: show masked sample values for findings
- `--raw-samples`: show unmasked sample values in the report (sensitive)
- `--types <types>`: only check specific finding types or preset groups
- `--exclude-types <types>`: skip specific finding types or preset groups
- `--interactive`: force the wizard even when flags are present
- `--direct`: skip the wizard and scan immediately

Examples:

```bash
# Launch the interactive scan wizard
bun run src/index.ts scan

# Skip the wizard and scan everything with the default summary report
bun run src/index.ts scan --direct

# Scan only Codex sessions
bun run src/index.ts scan --direct --agent codex

# Scan multiple providers
bun run src/index.ts scan --direct --agents codex,claude

# Only check for emails and JWTs
bun run src/index.ts scan --direct --types email,jwt

# Use preset groups
bun run src/index.ts scan --direct --types api_keys,user_data --samples

# Use the lower-noise preset
bun run src/index.ts scan --direct --types high_precision

# Show raw values instead of masked samples
bun run src/index.ts scan --direct --raw-samples

# Check everything except usernames in paths and emails
bun run src/index.ts scan --direct --exclude-types path_username,email

# Show the detailed per-session breakdown with samples
bun run src/index.ts scan --direct --details --samples

# Produce machine-readable JSON
bun run src/index.ts scan --direct --json
```

### Mask secrets

`mask_secrets` loads sessions, detects findings, and writes masked values back to disk.
By default it checks all finding types before masking. Use `--dry-run` to preview what would change.
When backups are enabled, Agent Warden stores them under `~/.agentwarden/backups/<timestamp>-mask_secrets` and writes a `manifest.json` alongside them.

```bash
bun run src/index.ts mask_secrets
```

Useful flags:

- `--agent <agent>`: mask only one provider
- `--agents <agents>`: mask a comma-separated list of providers
- `--dry-run`: show planned changes without writing
- `--no-backup`: disable backups before writes
- `--types <types>`: only mask findings of specific types or preset groups
- `--exclude-types <types>`: skip specific finding types or preset groups

Examples:

```bash
# Preview changes without writing anything
bun run src/index.ts mask_secrets --dry-run

# Only mask auth headers and raw tokens
bun run src/index.ts mask_secrets --types authorization_header,raw_token

# Mask a preset group
bun run src/index.ts mask_secrets --types user_data

# Mask everything except emails
bun run src/index.ts mask_secrets --exclude-types email

# Only mask one provider
bun run src/index.ts mask_secrets --agent gemini

# Mask multiple providers
bun run src/index.ts mask_secrets --agents codex,claude
```

## Finding types

Type filtering is configurable. If you do not pass `--types` or `--exclude-types`, Agent Warden checks all finding types.

### Preset groups

You can use these group names anywhere you use `--types` or `--exclude-types`, and they are also available in the interactive scan wizard:

| Group | Includes |
| --- | --- |
| `high_precision` | `authorization_header`, `signed_query`, `basic_auth`, `private_key`, `jwt`, `raw_token`, `url_credentials` |
| `api_keys` | `secret_assignment`, `signed_query`, `raw_token`, `base64_secret` |
| `session_auth` | `authorization_header`, `cookie`, `basic_auth`, `jwt` |
| `credentials` | `url_credentials`, `private_key` |
| `user_data` | `path_username`, `email` |

### Individual types

| Type | Description | Example |
| --- | --- | --- |
| `secret_assignment` | Sensitive-looking keys assigned directly to a value, such as API keys, tokens, passwords, authorization values, or cookies. | ``api_key=sk-example1234567890`` |
| `authorization_header` | `Authorization` or `Proxy-Authorization` header values that use `Bearer`, `Basic`, or `Token`. | ``Authorization: Bearer sk-example1234567890`` |
| `cookie` | `Cookie` or `Set-Cookie` header values that may contain session IDs or other secrets. | ``Cookie: session_token=abc123def456ghi789`` |
| `url_credentials` | Credentials embedded directly in a URL before the host, such as `user:password@`. | ``https://alice:super-secret@example.com/private`` |
| `signed_query` | Sensitive query parameter values such as `access_token`, `api_key`, `signature`, `x-amz-signature`, or `x-goog-signature`. | ``https://example.com/download?access_token=tok_example_1234567890`` |
| `basic_auth` | Base64 credentials inside an HTTP Basic auth header. | ``Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l`` |
| `base64_secret` | Standalone Base64 text that decodes to secret-looking content such as `token=...`, `password:...`, or `client_secret=...`. | ``dG9rZW49c2stZXhhbXBsZTEyMzQ1Ng==`` |
| `private_key` | PEM-formatted private keys such as RSA, EC, DSA, OpenSSH, or PGP private key blocks. | ``-----BEGIN PRIVATE KEY-----`` |
| `jwt` | JSON Web Tokens with the usual three-part `header.payload.signature` format. | ``eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz`` |
| `raw_token` | Known token formats from common providers, such as OpenAI, Anthropic, GitHub, Google, or Slack. | ``ghp_1234567890abcdefghijklmnop`` |
| `path_username` | Usernames exposed in local filesystem paths such as `/Users/name`, `/home/name`, or `C:\Users\name`. | ``/Users/alice/.codex/sessions`` |
| `email` | Email addresses found in session content. | ``alice@example.com`` |

These examples are illustrative only. Actual findings can appear inside JSON, logs, prompts, headers, nested strings, or other session text.
