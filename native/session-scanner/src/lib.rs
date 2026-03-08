use std::collections::{HashMap, HashSet};

use base64::Engine;
use napi::bindgen_prelude::Result;
use napi_derive::napi;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

static SENSITIVE_ASSIGNMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?im)((?:^|[\s,{])(?:[A-Za-z][A-Za-z0-9_.-]*?(?:api[_-]?key|token|secret|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|pwd|authorization|cookie))["']?\s*[:=]\s*["']?)([^\s"'`,}]+)"###).unwrap()
});
static AUTHORIZATION_HEADER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?im)((?:authorization|proxy-authorization)\b["']?\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{6,})"###).unwrap()
});
static BARE_BEARER_TOKEN_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"(?im)(\bBearer\s+)([A-Za-z0-9._~+/=-]{8,})\b"###).unwrap());
static COOKIE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?im)((?:cookie|set-cookie)\b["']?\s*[:=]\s*["']?)([^\n"']{6,})"###).unwrap()
});
static URL_CREDENTIALS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?im)(\b[a-z][a-z0-9+.-]*:\/\/)([^\/\s:@]+:[^\/\s@]+)(@[^\s?#]+)"###).unwrap()
});
static SIGNED_QUERY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?im)((?:[?&](?:access_token|refresh_token|token|api[_-]?key|apikey|key|client_secret|signature|sig|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|awsaccesskeyid|password|passwd|pwd)=))([^&#\s]+)"###).unwrap()
});
static BASIC_AUTH_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?im)(Authorization\b["']?\s*[:=]\s*["']?Basic\s+)([A-Za-z0-9+/]{8,}={0,2})"###)
        .unwrap()
});
static BASE64_SECRET_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?m)(^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{12,}={0,2})($|[^A-Za-z0-9+/=])"###)
        .unwrap()
});
static PRIVATE_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"###).unwrap()
});
static JWT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"###).unwrap()
});
static RAW_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"\b(?:sk-[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{12,}|sk-ant-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"###).unwrap()
});
static EMAIL_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"###).unwrap());
static PATH_USERNAME_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r###"/Users/([A-Za-z0-9][A-Za-z0-9._-]{0,63})"###).unwrap(),
        Regex::new(r###"/home/([A-Za-z0-9][A-Za-z0-9._-]{0,63})"###).unwrap(),
        Regex::new(r###"[A-Za-z]:[\\/]+Users[\\/]([A-Za-z0-9][A-Za-z0-9._-]{0,63})"###).unwrap(),
    ]
});
static BASE64_VALUE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^[A-Za-z0-9+/]+={0,2}$"###).unwrap());
static HUMAN_PLACEHOLDER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?iu)^(?:your(?:[_-][\p{L}\d]+){0,6}|example(?:[_-][\p{L}\d]+){0,6}|sample(?:[_-][\p{L}\d]+){0,6}|dummy(?:[_-][\p{L}\d]+){0,6}|placeholder(?:[_-][\p{L}\d]+){0,6}|changeme|replace(?:[_-]?me)?|long-lived|short-lived|activation-token(?:[-_][\p{L}\d]+){0,6}|noemail|ваш(?:[_-][\p{L}\d]+){0,6})$"###).unwrap()
});
static GENERIC_TOKEN_LABEL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?i)^(?:header|authorization|auth|bearer|token|secret|password|passwd|credential|credentials|extraction)$"###)
        .unwrap()
});
static ENV_VAR_NAME_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"###).unwrap());
static SIMPLE_TYPE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?i)^(?:true|false|null|undefined|boolean|string|number)$"###).unwrap()
});
static LEADING_TRAILING_QUOTES_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^["'`]+|["'`]+$"###).unwrap());
static TRAILING_SYNTAX_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r###"[;),!]+$"###).unwrap());
static WORD_SEGMENT_SPLIT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"[^0-9\p{L}]+"###).unwrap());
static ASCII_SEGMENT_SPLIT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"[^A-Za-z0-9]+"###).unwrap());
static LABEL_ONLY_SEGMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?iu)^(?:\d{1,6}|access|admin|ant|api\d*|apikey|authorization|auth|ban|bearer|cookie|cpk|credential|credentials|example|extraction|header|key|kimi|omni|or|password|pass|placeholder|polza|postgres|prx|proxy|refresh|replicate|root|sample|secret|session|sk|test|token|upstream|usagebatch|user|username|value|v\d+|ваш)$"###).unwrap()
});
static PLACEHOLDER_SNAKE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"(?i)^[a-z]+(?:[-_][a-z]+){1,6}$"###).unwrap());
static PLACEHOLDER_SNAKE_SECRET_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?i)(secret|token|password|webhook|proxy|rotation|same)"###).unwrap()
});
static CODE_REF_ENV_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"^(?:process\.env|import\.meta\.env)\.[A-Za-z_][A-Za-z0-9_]*(?:\??\.[A-Za-z_$][\w$]*)*$"###).unwrap()
});
static CODE_REF_DOTTED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^(?:[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)+$"###).unwrap());
static CODE_REF_CALL_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^[A-Za-z_$][\w$]*\("###).unwrap());
static CODE_REF_OPS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"(?:\?\.|===|!==|&&|\|\||=>|[(){}\[\]`])"###).unwrap());
static MARKUP_PREFIX_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^(?:<|<!doctype|<\?xml)"###).unwrap());
static MARKUP_TAG_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"<(?:svg|html|body|div|path|span|script|style)\b"###).unwrap());
static SYNTHETIC_ANGLE_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r###"^<[^>]+>$"###).unwrap());
static TYPE_EXPRESSION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"^(?:Option|Vec|Result|String|str|bytes?|Buffer|Array|Record|Map|Set|HashMap|HashSet|Promise)(?:<|\b|&|\[)"###).unwrap()
});
static LONG_XYZ_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"(?i)^(?:x{3,}|y{3,}|z{3,})$"###).unwrap());
static SAMPLE_SEQ_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?i)^(?:abc123|def456|ghi789|jkl012|mno345|token123)$"###).unwrap()
});
static PLACEHOLDER_SEGMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?iu)^(?:test\d*|demo\d*|sample\d*|example\d*|placeholder\d*|dummy\d*|mock\d*|fake\d*|changeme|replaceme|snapshot|usagebatch|refreshed|rotation|rotate|revoke|revoked|wrong|invalid|ban|watch)$"###).unwrap()
});
static YOUR_SEGMENT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"(?iu)^(?:your|yours|ваш)$"###).unwrap());
static ONLY_STARS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^\*{3,}(?::\*{3,})?$"###).unwrap());
static ANGLE_LINE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^<[^>\n`]*>?`?$"###).unwrap());
static DOLLAR_IDENT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^\$[A-Za-z_][A-Za-z0-9_]*$"###).unwrap());
static JUST_LETTERS_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r###"^[A-Za-z]+$"###).unwrap());
static HEX_SEGMENT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"(?i)^[a-f0-9]{12,}$"###).unwrap());
static ONLY_STARS_OR_ANGLE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"^\*+$|^<[^>]+>$"###).unwrap());
static TOKEN_WORD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?i)(token|secret|pass(?:word)?|auth|bearer|basic|api[_-]?key|client[_-]?secret|cookie)"###).unwrap()
});
static TOKEN_ASSIGNMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?i)(?:^|[\s,{])(token|secret|pass(?:word)?|auth|bearer|basic|api[_-]?key|client[_-]?secret|cookie)\s*[:=]\s*\S{6,}"###).unwrap()
});
static CONTEXT_KEY_SECRET_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r###"(?i)(api[_-]?key|token|secret|access[_-]?token|refresh[_-]?token|password|passwd|pwd|authorization|cookie)"###).unwrap()
});
static ONLY_ALPHA_NUM_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r###"[^A-Za-z0-9]+"###).unwrap());

const RESERVED_EMAIL_DOMAINS: &[&str] = &["example.com", "example.net", "example.org"];
const RESERVED_EMAIL_SUFFIXES: &[&str] = &[".test", ".invalid", ".localhost"];
const GENERIC_URL_PASSWORDS: &[&str] = &[
    "admin", "apikey", "api_key", "changeme", "default", "pass", "password", "postgres", "root",
    "secret", "test", "token", "user", "username",
];
const TEXT_TYPES: &[&str] = &[
    "secret_assignment",
    "authorization_header",
    "cookie",
    "url_credentials",
    "signed_query",
    "basic_auth",
    "base64_secret",
    "private_key",
    "jwt",
    "raw_token",
    "path_username",
    "email",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FieldInput {
    context_key: Option<String>,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchInput {
    enabled_types: Option<Vec<String>>,
    fields: Vec<FieldInput>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DetectionSpan {
    #[serde(rename = "type")]
    kind: String,
    start: usize,
    end: usize,
    raw_value: String,
    replacement: String,
    preview: String,
    confidence: u8,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldOutput {
    findings: Vec<DetectionSpan>,
    next_value: String,
}

#[derive(Debug, Serialize)]
struct BatchOutput {
    results: Vec<FieldOutput>,
}

fn is_type_enabled(secret_type: &str, enabled_types: Option<&HashSet<String>>) -> bool {
    enabled_types.is_none_or(|enabled| enabled.contains(secret_type))
}

fn count_chars(value: &str) -> usize {
    if value.is_ascii() {
        return value.len();
    }

    value.chars().count()
}

fn char_to_byte_index(value: &str, char_index: usize) -> usize {
    if value.is_ascii() {
        return char_index.min(value.len());
    }

    if char_index == 0 {
        return 0;
    }

    for (seen, (byte_index, _)) in value.char_indices().enumerate() {
        if seen == char_index {
            return byte_index;
        }
    }

    value.len()
}

fn slice_by_chars(value: &str, start: usize, end: usize) -> &str {
    if value.is_ascii() {
        return &value[start.min(value.len())..end.min(value.len())];
    }

    let start_byte = char_to_byte_index(value, start);
    let end_byte = char_to_byte_index(value, end);
    &value[start_byte..end_byte]
}

fn byte_to_char_index(value: &str, byte_index: usize) -> usize {
    if value.is_ascii() {
        return byte_index.min(value.len());
    }

    value[..byte_index].chars().count()
}

fn fingerprint_secret(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(16);

    for byte in digest.iter().take(8) {
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

fn mask_token(value: &str) -> String {
    let length = count_chars(value);
    if length <= 8 {
        return "*".repeat(length.max(4));
    }

    let prefix_length = if length > 20 { 6 } else { 3 };
    let suffix_length = if length > 12 { 4 } else { 2 };
    format!(
        "{}****{}",
        slice_by_chars(value, 0, prefix_length),
        slice_by_chars(value, length - suffix_length, length)
    )
}

fn mask_email(value: &str) -> String {
    let mut parts = value.split('@');
    let local_part = parts.next().unwrap_or_default();
    let Some(domain_part) = parts.next() else {
        return mask_token(value);
    };

    let local_len = count_chars(local_part);
    let safe_local = if local_len <= 2 {
        format!("{}*", slice_by_chars(local_part, 0, 1.min(local_len)))
    } else {
        format!("{}***", slice_by_chars(local_part, 0, 2))
    };

    format!("{safe_local}@{domain_part}")
}

fn mask_username(value: &str) -> String {
    let length = count_chars(value);
    if length <= 2 {
        return format!("{}*", slice_by_chars(value, 0, 1.min(length)));
    }

    format!(
        "{}***{}",
        slice_by_chars(value, 0, 1),
        slice_by_chars(value, length - 1, length)
    )
}

fn mask_private_key(value: &str) -> String {
    let lines: Vec<&str> = value.lines().collect();
    if lines.len() < 2 {
        return "[PRIVATE KEY REDACTED]".to_string();
    }

    let first_line = lines
        .first()
        .copied()
        .unwrap_or("-----BEGIN PRIVATE KEY-----");
    let last_line = lines.last().copied().unwrap_or("-----END PRIVATE KEY-----");
    format!("{first_line}\n[PRIVATE KEY REDACTED]\n{last_line}")
}

fn apply_replacements(source: &str, replacements: &[(usize, usize, String)]) -> String {
    let mut output = source.to_string();
    let mut sorted = replacements.to_vec();
    sorted.sort_by(|left, right| right.0.cmp(&left.0));

    for (start, end, replacement) in sorted {
        let start_byte = char_to_byte_index(&output, start);
        let end_byte = char_to_byte_index(&output, end);
        output.replace_range(start_byte..end_byte, &replacement);
    }

    output
}

fn strip_trailing_syntax(value: &str) -> String {
    TRAILING_SYNTAX_PATTERN
        .replace_all(value.trim(), "")
        .to_string()
}

fn strip_wrapping_quotes(value: &str) -> String {
    LEADING_TRAILING_QUOTES_PATTERN
        .replace_all(&strip_trailing_syntax(value), "")
        .to_string()
}

fn looks_like_env_var_name(value: &str) -> bool {
    ENV_VAR_NAME_PATTERN.is_match(value)
}

fn get_word_like_segments(value: &str) -> Vec<String> {
    WORD_SEGMENT_SPLIT_PATTERN
        .split(&value.to_lowercase())
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn looks_like_placeholder_segment(segment: &str) -> bool {
    LONG_XYZ_PATTERN.is_match(segment)
        || SAMPLE_SEQ_PATTERN.is_match(segment)
        || PLACEHOLDER_SEGMENT_PATTERN.is_match(segment)
        || YOUR_SEGMENT_PATTERN.is_match(segment)
}

fn looks_like_type_expression(value: &str) -> bool {
    TYPE_EXPRESSION_PATTERN.is_match(value)
}

fn has_long_random_segment(value: &str) -> bool {
    ASCII_SEGMENT_SPLIT_PATTERN.split(value).any(|segment| {
        if segment.len() < 8 {
            return false;
        }

        if HEX_SEGMENT_PATTERN.is_match(segment) {
            return true;
        }

        let has_letter = segment
            .chars()
            .any(|character| character.is_ascii_alphabetic());
        let has_digit = segment.chars().any(|character| character.is_ascii_digit());
        let has_upper = segment
            .chars()
            .any(|character| character.is_ascii_uppercase());
        let has_lower = segment
            .chars()
            .any(|character| character.is_ascii_lowercase());

        (segment.len() >= 10 && has_letter && has_digit)
            || (segment.len() >= 16 && has_upper && has_lower && has_digit)
    })
}

fn looks_like_label_only_value(value: &str) -> bool {
    let segments = get_word_like_segments(value);
    !segments.is_empty()
        && segments.iter().all(|segment| {
            looks_like_placeholder_segment(segment) || LABEL_ONLY_SEGMENT_PATTERN.is_match(segment)
        })
}

fn looks_like_placeholder(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);

    if normalized.is_empty()
        || ONLY_STARS_PATTERN.is_match(&normalized)
        || normalized.contains("${")
        || normalized.contains("{{")
        || ANGLE_LINE_PATTERN.is_match(&normalized)
        || normalized.to_lowercase().starts_with("<same")
        || normalized.starts_with("...")
        || HUMAN_PLACEHOLDER_PATTERN.is_match(&normalized)
    {
        return true;
    }

    let segments = get_word_like_segments(&normalized);
    if !segments.is_empty()
        && segments
            .iter()
            .all(|segment| looks_like_placeholder_segment(segment))
    {
        return true;
    }

    PLACEHOLDER_SNAKE_PATTERN.is_match(&normalized)
        && PLACEHOLDER_SNAKE_SECRET_PATTERN.is_match(&normalized)
}

fn looks_like_code_reference(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);

    !normalized.is_empty()
        && (DOLLAR_IDENT_PATTERN.is_match(&normalized)
            || CODE_REF_ENV_PATTERN.is_match(&normalized)
            || CODE_REF_DOTTED_PATTERN.is_match(&normalized)
            || CODE_REF_CALL_PATTERN.is_match(&normalized)
            || CODE_REF_OPS_PATTERN.is_match(value))
}

fn looks_like_markup_content(value: &str) -> bool {
    let normalized = value.trim().to_lowercase();
    MARKUP_PREFIX_PATTERN.is_match(&normalized)
        || MARKUP_TAG_PATTERN.is_match(&normalized)
        || normalized.contains("xmlns=")
}

fn looks_like_reserved_example_email(value: &str) -> bool {
    let normalized = value.trim().to_lowercase();
    let mut parts = normalized.split('@');
    let local_part = parts.next().unwrap_or_default();
    let domain_part = parts.next().unwrap_or_default();

    local_part.is_empty()
        || domain_part.is_empty()
        || RESERVED_EMAIL_DOMAINS.contains(&domain_part)
        || RESERVED_EMAIL_SUFFIXES
            .iter()
            .any(|suffix| domain_part.ends_with(suffix))
        || local_part.starts_with("cli-invalid")
        || local_part == "noemail"
}

fn looks_like_synthetic_token_value(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);
    let compact = ONLY_ALPHA_NUM_PATTERN
        .replace_all(&normalized, "")
        .to_string();

    if normalized.is_empty()
        || looks_like_placeholder(&normalized)
        || looks_like_code_reference(&normalized)
        || looks_like_env_var_name(&normalized)
        || GENERIC_TOKEN_LABEL_PATTERN.is_match(&normalized)
        || SYNTHETIC_ANGLE_PATTERN.is_match(&normalized)
        || looks_like_type_expression(&normalized)
        || get_word_like_segments(&normalized)
            .iter()
            .any(|segment| looks_like_placeholder_segment(segment))
    {
        return true;
    }

    if JUST_LETTERS_PATTERN.is_match(&compact) && compact.len() < 20 {
        return true;
    }

    looks_like_label_only_value(&normalized) && !has_long_random_segment(&normalized)
}

fn looks_like_sensitive_assignment_value(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);
    if count_chars(&normalized) < 6 {
        return false;
    }

    if SIMPLE_TYPE_PATTERN.is_match(&normalized)
        || looks_like_placeholder(&normalized)
        || looks_like_code_reference(&normalized)
        || looks_like_env_var_name(&normalized)
        || looks_like_type_expression(&normalized)
    {
        return false;
    }

    if (normalized.starts_with("sk-")
        || normalized.starts_with("prx_")
        || normalized.starts_with("omni_")
        || normalized.starts_with("cpk_")
        || normalized.starts_with("ghp_")
        || normalized.starts_with("gho_")
        || normalized.starts_with("ghu_")
        || normalized.starts_with("ghs_")
        || normalized.starts_with("ghr_"))
        && looks_like_synthetic_token_value(&normalized)
    {
        return false;
    }

    !JUST_LETTERS_PATTERN.is_match(&normalized) || count_chars(&normalized) >= 12
}

fn looks_like_sensitive_authorization_value(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);
    let compact = ONLY_ALPHA_NUM_PATTERN
        .replace_all(&normalized, "")
        .to_string();

    count_chars(&normalized) >= 10
        && !looks_like_synthetic_token_value(&normalized)
        && (has_long_random_segment(&normalized)
            || (compact.len() >= 12
                && compact
                    .chars()
                    .any(|character| character.is_ascii_alphabetic())
                && compact.chars().any(|character| character.is_ascii_digit())))
}

fn looks_like_sensitive_cookie_value(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);
    count_chars(&normalized) >= 8
        && !looks_like_placeholder(&normalized)
        && !looks_like_code_reference(&normalized)
        && normalized.contains('=')
}

fn looks_like_sensitive_url_credential(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);
    let Some(separator_index) = normalized.find(':') else {
        return false;
    };

    if separator_index == 0 || separator_index == normalized.len() - 1 {
        return false;
    }

    let username = &normalized[..separator_index];
    let password = &normalized[separator_index + 1..];
    let username_lower = username.to_lowercase();
    let password_lower = password.to_lowercase();

    count_chars(password) >= 6
        && !looks_like_placeholder(&normalized)
        && !looks_like_code_reference(&normalized)
        && !looks_like_placeholder(username)
        && !looks_like_placeholder(password)
        && !looks_like_code_reference(username)
        && !looks_like_code_reference(password)
        && !looks_like_env_var_name(username)
        && !looks_like_env_var_name(password)
        && !ONLY_STARS_OR_ANGLE_PATTERN.is_match(username)
        && !ONLY_STARS_OR_ANGLE_PATTERN.is_match(password)
        && !GENERIC_URL_PASSWORDS.contains(&password_lower.as_str())
        && !GENERIC_URL_PASSWORDS.contains(&username_lower.as_str())
        && !(username_lower == password_lower && looks_like_label_only_value(&password_lower))
        && !looks_like_synthetic_token_value(password)
}

fn looks_like_sensitive_signed_query_value(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);
    let compact = ONLY_ALPHA_NUM_PATTERN
        .replace_all(&normalized, "")
        .to_string();

    count_chars(&normalized) >= 8
        && !looks_like_synthetic_token_value(&normalized)
        && !looks_like_placeholder(&normalized)
        && !looks_like_code_reference(&normalized)
        && !["admin", "password", "secret", "token"].contains(&normalized.to_lowercase().as_str())
        && (has_long_random_segment(&normalized)
            || (compact.len() >= 16
                && compact
                    .chars()
                    .any(|character| character.is_ascii_alphabetic())
                && compact.chars().any(|character| character.is_ascii_digit())))
}

fn looks_like_sensitive_raw_token_value(value: &str) -> bool {
    let normalized = strip_wrapping_quotes(value);
    let compact = ONLY_ALPHA_NUM_PATTERN
        .replace_all(&normalized, "")
        .to_string();

    count_chars(&normalized) >= 12
        && !looks_like_synthetic_token_value(&normalized)
        && (has_long_random_segment(&normalized) || compact.len() >= 24)
}

fn looks_like_sensitive_base64(decoded: &str) -> bool {
    let trimmed = decoded.trim();
    count_chars(trimmed) >= 8
        && !looks_like_markup_content(trimmed)
        && !looks_like_placeholder(trimmed)
        && !looks_like_code_reference(trimmed)
        && (TOKEN_WORD_PATTERN.is_match(trimmed) || TOKEN_ASSIGNMENT_PATTERN.is_match(trimmed))
}

fn add_span(
    spans: &mut Vec<DetectionSpan>,
    kind: &str,
    start: usize,
    end: usize,
    raw_value: String,
    replacement: String,
    confidence: u8,
) {
    if raw_value.trim().is_empty() {
        return;
    }

    spans.push(DetectionSpan {
        kind: kind.to_string(),
        start,
        end,
        preview: replacement.clone(),
        fingerprint: fingerprint_secret(&raw_value),
        raw_value,
        replacement,
        confidence,
    });
}

fn dedupe_spans(spans: Vec<DetectionSpan>) -> Vec<DetectionSpan> {
    let mut sorted = spans;
    sorted.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then(right.confidence.cmp(&left.confidence))
            .then((right.end - right.start).cmp(&(left.end - left.start)))
    });

    let mut accepted: Vec<DetectionSpan> = Vec::new();

    for candidate in sorted {
        let overlapping_index = accepted
            .iter()
            .position(|current| candidate.start < current.end && current.start < candidate.end);

        match overlapping_index {
            None => accepted.push(candidate),
            Some(index) => {
                let current = &accepted[index];
                let candidate_score =
                    usize::from(candidate.confidence) * 1000 + (candidate.end - candidate.start);
                let current_score =
                    usize::from(current.confidence) * 1000 + (current.end - current.start);
                if candidate_score > current_score {
                    accepted[index] = candidate;
                }
            }
        }
    }

    accepted.sort_by_key(|span| span.start);
    accepted
}

fn build_escaped_json_string_offsets(value: &str) -> Vec<usize> {
    let mut offsets = vec![0];
    let mut escaped_length = 0;

    for character in value.chars() {
        let serialized =
            serde_json::to_string(&character.to_string()).unwrap_or_else(|_| "\"\"".to_string());
        let escaped = &serialized[1..serialized.len() - 1];
        escaped_length += count_chars(escaped);
        offsets.push(escaped_length);
    }

    offsets
}

fn collect_nested_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(inner) => output.push(inner.clone()),
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_nested_strings(item, output)),
        Value::Object(map) => map
            .values()
            .for_each(|item| collect_nested_strings(item, output)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn find_from(value: &str, needle: &str, start: usize) -> Option<usize> {
    value[start..].find(needle).map(|offset| start + offset)
}

fn detect_nested_json_spans(
    text: &str,
    enabled_types: Option<&HashSet<String>>,
) -> Vec<DetectionSpan> {
    let trimmed = text.trim();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return Vec::new();
    }

    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return Vec::new();
    };

    let mut nested_strings = Vec::new();
    collect_nested_strings(&parsed, &mut nested_strings);

    let mut spans = Vec::new();
    let mut next_search_index_by_serialized_value: HashMap<String, usize> = HashMap::new();

    for nested_string in nested_strings {
        let Ok(serialized_value) = serde_json::to_string(&nested_string) else {
            continue;
        };
        let escaped_offsets = build_escaped_json_string_offsets(&nested_string);
        let search_index = next_search_index_by_serialized_value
            .get(&serialized_value)
            .copied()
            .unwrap_or(0);
        let Some(serialized_index) = find_from(text, &serialized_value, search_index) else {
            continue;
        };
        next_search_index_by_serialized_value.insert(
            serialized_value.clone(),
            serialized_index + serialized_value.len(),
        );
        let content_index = serialized_index + 1;
        let content_char_index = byte_to_char_index(text, content_index);

        for nested_span in detect_spans(&nested_string, None, enabled_types) {
            let Some(start_offset) = escaped_offsets.get(nested_span.start).copied() else {
                continue;
            };
            let Some(end_offset) = escaped_offsets.get(nested_span.end).copied() else {
                continue;
            };
            let Ok(serialized_replacement) = serde_json::to_string(&nested_span.replacement) else {
                continue;
            };

            spans.push(DetectionSpan {
                kind: nested_span.kind,
                start: content_char_index + start_offset,
                end: content_char_index + end_offset,
                raw_value: nested_span.raw_value,
                replacement: serialized_replacement[1..serialized_replacement.len() - 1]
                    .to_string(),
                preview: nested_span.replacement,
                confidence: nested_span.confidence,
                fingerprint: nested_span.fingerprint,
            });
        }
    }

    spans
}

fn decode_base64_utf8(value: &str) -> Option<String> {
    if value.len() < 12 || value.len() % 4 != 0 || !BASE64_VALUE_PATTERN.is_match(value) {
        return None;
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    (!decoded.contains('\u{FFFD}')).then_some(decoded)
}

fn detect_spans(
    text: &str,
    context_key: Option<&str>,
    enabled_types: Option<&HashSet<String>>,
) -> Vec<DetectionSpan> {
    if enabled_types.is_some_and(HashSet::is_empty) {
        return Vec::new();
    }

    let mut spans = Vec::new();

    if is_type_enabled("secret_assignment", enabled_types) {
        for captures in SENSITIVE_ASSIGNMENT_PATTERN.captures_iter(text) {
            let Some(prefix) = captures.get(1) else {
                continue;
            };
            let Some(value) = captures.get(2) else {
                continue;
            };
            let value_str = value.as_str();
            if !looks_like_sensitive_assignment_value(value_str) {
                continue;
            }
            add_span(
                &mut spans,
                "secret_assignment",
                byte_to_char_index(text, prefix.end()),
                byte_to_char_index(text, prefix.end()) + count_chars(value_str),
                value_str.to_string(),
                mask_token(value_str),
                10,
            );
        }
    }

    if is_type_enabled("authorization_header", enabled_types) {
        for pattern in [&*AUTHORIZATION_HEADER_PATTERN, &*BARE_BEARER_TOKEN_PATTERN] {
            for captures in pattern.captures_iter(text) {
                let Some(prefix) = captures.get(1) else {
                    continue;
                };
                let Some(value) = captures.get(2) else {
                    continue;
                };
                let value_str = value.as_str();
                if !looks_like_sensitive_authorization_value(value_str) {
                    continue;
                }
                let confidence = if std::ptr::eq(pattern, &*AUTHORIZATION_HEADER_PATTERN) {
                    10
                } else {
                    9
                };
                add_span(
                    &mut spans,
                    "authorization_header",
                    byte_to_char_index(text, prefix.end()),
                    byte_to_char_index(text, prefix.end()) + count_chars(value_str),
                    value_str.to_string(),
                    mask_token(value_str),
                    confidence,
                );
            }
        }
    }

    if is_type_enabled("cookie", enabled_types) {
        for captures in COOKIE_PATTERN.captures_iter(text) {
            let Some(prefix) = captures.get(1) else {
                continue;
            };
            let Some(value) = captures.get(2) else {
                continue;
            };
            let value_str = value.as_str();
            if !looks_like_sensitive_cookie_value(value_str) {
                continue;
            }
            add_span(
                &mut spans,
                "cookie",
                byte_to_char_index(text, prefix.end()),
                byte_to_char_index(text, prefix.end()) + count_chars(value_str),
                value_str.to_string(),
                mask_token(value_str),
                9,
            );
        }
    }

    if is_type_enabled("url_credentials", enabled_types) {
        for captures in URL_CREDENTIALS_PATTERN.captures_iter(text) {
            let Some(prefix) = captures.get(1) else {
                continue;
            };
            let Some(value) = captures.get(2) else {
                continue;
            };
            let value_str = value.as_str();
            if !looks_like_sensitive_url_credential(value_str) {
                continue;
            }
            add_span(
                &mut spans,
                "url_credentials",
                byte_to_char_index(text, prefix.end()),
                byte_to_char_index(text, prefix.end()) + count_chars(value_str),
                value_str.to_string(),
                mask_token(value_str),
                10,
            );
        }
    }

    if is_type_enabled("signed_query", enabled_types) {
        for captures in SIGNED_QUERY_PATTERN.captures_iter(text) {
            let Some(prefix) = captures.get(1) else {
                continue;
            };
            let Some(value) = captures.get(2) else {
                continue;
            };
            let value_str = value.as_str();
            if !looks_like_sensitive_signed_query_value(value_str) {
                continue;
            }
            add_span(
                &mut spans,
                "signed_query",
                byte_to_char_index(text, prefix.end()),
                byte_to_char_index(text, prefix.end()) + count_chars(value_str),
                value_str.to_string(),
                mask_token(value_str),
                9,
            );
        }
    }

    if is_type_enabled("basic_auth", enabled_types) {
        for captures in BASIC_AUTH_PATTERN.captures_iter(text) {
            let Some(prefix) = captures.get(1) else {
                continue;
            };
            let Some(value) = captures.get(2) else {
                continue;
            };
            let value_str = value.as_str();
            add_span(
                &mut spans,
                "basic_auth",
                byte_to_char_index(text, prefix.end()),
                byte_to_char_index(text, prefix.end()) + count_chars(value_str),
                value_str.to_string(),
                mask_token(value_str),
                9,
            );
        }
    }

    if is_type_enabled("base64_secret", enabled_types) {
        for captures in BASE64_SECRET_PATTERN.captures_iter(text) {
            let Some(prefix) = captures.get(1) else {
                continue;
            };
            let Some(value) = captures.get(2) else {
                continue;
            };
            let value_str = value.as_str();
            let Some(decoded) = decode_base64_utf8(value_str) else {
                continue;
            };
            if !looks_like_sensitive_base64(&decoded) {
                continue;
            }
            add_span(
                &mut spans,
                "base64_secret",
                byte_to_char_index(text, prefix.end()),
                byte_to_char_index(text, prefix.end()) + count_chars(value_str),
                value_str.to_string(),
                mask_token(value_str),
                7,
            );
        }
    }

    if is_type_enabled("private_key", enabled_types) {
        for matched in PRIVATE_KEY_PATTERN.find_iter(text) {
            let raw_value = matched.as_str();
            add_span(
                &mut spans,
                "private_key",
                byte_to_char_index(text, matched.start()),
                byte_to_char_index(text, matched.end()),
                raw_value.to_string(),
                mask_private_key(raw_value),
                10,
            );
        }
    }

    if is_type_enabled("jwt", enabled_types) {
        for matched in JWT_PATTERN.find_iter(text) {
            let raw_value = matched.as_str();
            add_span(
                &mut spans,
                "jwt",
                byte_to_char_index(text, matched.start()),
                byte_to_char_index(text, matched.end()),
                raw_value.to_string(),
                mask_token(raw_value),
                8,
            );
        }
    }

    if is_type_enabled("raw_token", enabled_types) {
        for matched in RAW_TOKEN_PATTERN.find_iter(text) {
            let raw_value = matched.as_str();
            if !looks_like_sensitive_raw_token_value(raw_value) {
                continue;
            }
            add_span(
                &mut spans,
                "raw_token",
                byte_to_char_index(text, matched.start()),
                byte_to_char_index(text, matched.end()),
                raw_value.to_string(),
                mask_token(raw_value),
                7,
            );
        }
    }

    if is_type_enabled("email", enabled_types) {
        for matched in EMAIL_PATTERN.find_iter(text) {
            let raw_value = matched.as_str();
            if looks_like_reserved_example_email(raw_value) {
                continue;
            }
            add_span(
                &mut spans,
                "email",
                byte_to_char_index(text, matched.start()),
                byte_to_char_index(text, matched.end()),
                raw_value.to_string(),
                mask_email(raw_value),
                4,
            );
        }
    }

    if is_type_enabled("path_username", enabled_types) {
        for pattern in PATH_USERNAME_PATTERNS.iter() {
            for captures in pattern.captures_iter(text) {
                let Some(full_match) = captures.get(0) else {
                    continue;
                };
                let Some(user_match) = captures.get(1) else {
                    continue;
                };
                let user = user_match.as_str();
                if user.is_empty() {
                    continue;
                }
                let Some(user_offset) = full_match.as_str().find(user) else {
                    continue;
                };
                let start_byte = full_match.start() + user_offset;
                add_span(
                    &mut spans,
                    "path_username",
                    byte_to_char_index(text, start_byte),
                    byte_to_char_index(text, start_byte) + count_chars(user),
                    user.to_string(),
                    mask_username(user),
                    5,
                );
            }
        }
    }

    if spans.is_empty()
        && context_key.is_some()
        && is_type_enabled("secret_assignment", enabled_types)
        && CONTEXT_KEY_SECRET_PATTERN.is_match(context_key.unwrap_or_default())
    {
        let trimmed = text.trim();
        if count_chars(trimmed) >= 6
            && !trimmed.chars().any(|character| character.is_whitespace())
            && looks_like_sensitive_assignment_value(trimmed)
            && let Some(start_byte) = text.find(trimmed)
        {
            let start = byte_to_char_index(text, start_byte);
            add_span(
                &mut spans,
                "secret_assignment",
                start,
                start + count_chars(trimmed),
                trimmed.to_string(),
                mask_token(trimmed),
                8,
            );
        }
    }

    let nested_spans = detect_nested_json_spans(text, enabled_types);
    spans.extend(nested_spans);
    dedupe_spans(spans)
}

fn build_masked_value(field: &FieldInput, enabled_types: Option<&HashSet<String>>) -> FieldOutput {
    let findings = detect_spans(&field.value, field.context_key.as_deref(), enabled_types);
    if findings.is_empty() {
        return FieldOutput {
            next_value: field.value.clone(),
            findings,
        };
    }

    let replacements = findings
        .iter()
        .map(|finding| (finding.start, finding.end, finding.replacement.clone()))
        .collect::<Vec<_>>();

    FieldOutput {
        next_value: apply_replacements(&field.value, &replacements),
        findings,
    }
}

#[napi(js_name = "scanFieldsBatch")]
pub fn scan_fields_batch(input: String) -> Result<String> {
    let parsed: BatchInput = serde_json::from_str(&input)
        .map_err(|error| napi::Error::from_reason(format!("Invalid scanner request: {error}")))?;

    let enabled_types = parsed
        .enabled_types
        .map(|items| items.into_iter().collect::<HashSet<_>>());
    if let Some(ref configured) = enabled_types {
        let invalid = configured
            .iter()
            .filter(|item| !TEXT_TYPES.contains(&item.as_str()))
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return Err(napi::Error::from_reason(format!(
                "Unknown secret types: {}",
                invalid.into_iter().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
    }

    let results = parsed
        .fields
        .par_iter()
        .map(|field| build_masked_value(field, enabled_types.as_ref()))
        .collect::<Vec<_>>();

    serde_json::to_string(&BatchOutput { results }).map_err(|error| {
        napi::Error::from_reason(format!("Unable to serialize scanner response: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_key_fallback_ignores_tabbed_values() {
        let spans = detect_spans("abcdefghijkl\tmnopqrst", Some("api_key"), None);
        assert!(spans.is_empty());
    }

    #[test]
    fn nested_json_uses_exact_serialized_string_matches() {
        let private_key = [
            "-----BEGIN PRIVATE KEY-----",
            "ABCDEF1234567890",
            "-----END PRIVATE KEY-----",
        ]
        .join("\n");
        let nested = serde_json::to_string(&serde_json::json!({ "key": private_key })).unwrap();
        let value = serde_json::to_string(&serde_json::json!({
            "prefix": format!("before {nested} after"),
            "target": nested,
        }))
        .unwrap();

        let output = build_masked_value(
            &FieldInput {
                context_key: Some("payload".to_string()),
                value,
            },
            None,
        );

        let parsed: Value = serde_json::from_str(&output.next_value).unwrap();
        let target = parsed.get("target").and_then(Value::as_str).unwrap();
        let nested_parsed: Value = serde_json::from_str(target).unwrap();

        assert_eq!(
            nested_parsed.get("key").and_then(Value::as_str),
            Some("[PRIVATE KEY REDACTED]")
        );
    }
}
