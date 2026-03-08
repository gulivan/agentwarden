# Agent Warden

Fully local CLI that scans AI agent sessions for exposed secrets and masks them in place. No external connections.

Supports **Claude Code**, **Codex**, **Gemini CLI**, and **OpenCode** session storage.

## Installation

```bash
# Run without installing
npx agentwarden@latest scan

# Install globally
npm install -g agentwarden
```

## Usage

### `scan` — Find exposed secrets

Scans local session files and reports findings. Running without flags opens an interactive wizard where you pick providers, finding types, and output options.

```bash
# Interactive wizard
agentwarden scan

# Skip wizard, scan everything
agentwarden scan --direct

# Scan specific providers with masked samples
agentwarden scan --direct --agents codex,claude --samples

# Only high-confidence finding types
agentwarden scan --direct --types high_precision

# JSON output
agentwarden scan --direct --json
```

<details>
<summary>All scan flags</summary>

| Flag | Description |
| --- | --- |
| `--agent <name>` | Scan one provider |
| `--agents <list>` | Comma-separated providers |
| `--details` | Per-session breakdown table |
| `--samples` | Show masked sample values |
| `--raw-samples` | Show unmasked values (sensitive) |
| `--types <list>` | Only these finding types or groups |
| `--exclude-types <list>` | Skip these finding types or groups |
| `--json` | JSON output |
| `--direct` | Skip interactive wizard |
| `--interactive` | Force wizard even when flags are set |

</details>

Saved reports go to `~/.agentwarden/reports` (owner-only permissions).

### `mask_secrets` — Redact secrets on disk

Detects findings and overwrites them with masked values. Backups are saved to `~/.agentwarden/backups/` by default.

```bash
# Preview changes
agentwarden mask_secrets --dry-run

# Mask everything
agentwarden mask_secrets

# Mask only API keys for one provider
agentwarden mask_secrets --agent gemini --types api_keys
```

<details>
<summary>All mask_secrets flags</summary>

| Flag | Description |
| --- | --- |
| `--agent <name>` | Mask one provider |
| `--agents <list>` | Comma-separated providers |
| `--dry-run` | Preview without writing |
| `--no-backup` | Skip backup |
| `--types <list>` | Only these finding types or groups |
| `--exclude-types <list>` | Skip these finding types or groups |

</details>

## Finding types

By default all types are checked. Use `--types` or `--exclude-types` to filter.

<details>
<summary>Preset groups</summary>

| Group | Includes |
| --- | --- |
| `high_precision` | `authorization_header`, `signed_query`, `basic_auth`, `private_key`, `jwt`, `raw_token`, `url_credentials` |
| `api_keys` | `secret_assignment`, `signed_query`, `raw_token`, `base64_secret` |
| `session_auth` | `authorization_header`, `cookie`, `basic_auth`, `jwt` |
| `credentials` | `url_credentials`, `private_key` |
| `user_data` | `path_username`, `email` |

</details>

<details>
<summary>Individual types</summary>

| Type | Description |
| --- | --- |
| `secret_assignment` | API keys, tokens, or passwords assigned to a variable |
| `authorization_header` | Bearer/Basic/Token auth headers |
| `cookie` | Cookie or Set-Cookie header values |
| `url_credentials` | `user:password@host` in URLs |
| `signed_query` | Sensitive query params (`access_token`, `api_key`, signatures) |
| `basic_auth` | Base64 credentials in Basic auth |
| `base64_secret` | Base64 text that decodes to secret-looking content |
| `private_key` | PEM-formatted private keys |
| `jwt` | JSON Web Tokens |
| `raw_token` | Known token formats (OpenAI, Anthropic, GitHub, Google, Slack, etc.) |
| `path_username` | Usernames in filesystem paths |
| `email` | Email addresses |

</details>

## Development

```bash
bun install
bun run build:native  # compile the current-platform Rust scanner
bun run dev           # watch mode
bun run build         # production build
bun run src/index.ts  # run directly
```

Set `AGENTWARDEN_DISABLE_RUST_SCANNER=1` to force the TypeScript scanner fallback.
Set `AGENTWARDEN_DISABLE_SCAN_CACHE=1` to benchmark cold scans, or `AGENTWARDEN_SCAN_CACHE_PATH` to override the cache file location.
The scan cache stores fingerprints and masked previews only; scans that request raw samples bypass the cache, and cached files are invalidated using file size, timestamps, and a small content probe hash.

## Releasing

Create a GitHub release tagged as `v<package.json version>` to publish to npm automatically, or push the matching Git tag directly.
Set the repository secret `NPM_TOKEN` first. Pre-releases publish with the npm `next` dist-tag; stable releases publish as `latest`.
If the same version is already on npm, the publish workflow exits cleanly without trying to republish it.

## License

MIT
