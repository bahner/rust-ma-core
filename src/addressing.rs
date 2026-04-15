use std::collections::HashMap;

use did_ma::Did;

/// Extract the IPNS-resolvable base DID (without fragment) from a DID string.
/// Use only for transport / document operations, never for identity comparison.
pub fn did_root(input: &str) -> String {
    let trimmed = input.trim();
    match trimmed.split_once('#') {
        Some((root, _)) => root.to_string(),
        None => trimmed.to_string(),
    }
}

/// Construct a full DID string from an IPNS key and a fragment.
/// Returns `did:ma:<ipns>#<fragment>`.
pub fn create_world_did(ipns: &str, fragment: &str) -> String {
    Did::new(ipns, fragment)
        .expect("create_world_did: invalid ipns or fragment")
        .id()
}

/// Check whether two DIDs share the same IPNS key (same DID document).
/// This is NOT an identity check — two DIDs from the same document are
/// different identities that happen to share a transport key.
pub fn same_ipns(a: &Did, b: &Did) -> bool {
    a.ipns == b.ipns
}

pub fn normalize_iroh_address(address: &str) -> String {
    let value = address.trim();
    if let Some(rest) = value.strip_prefix("/iroh/") {
        return rest.to_string();
    }
    value.to_string()
}

pub fn normalize_relay_url(input: &str) -> String {
    let mut value = input.trim().to_string();
    while value.ends_with('.') || value.ends_with('/') {
        value.pop();
    }
    value.push('/');
    value
}

pub fn normalize_endpoint_id(address: &str) -> Option<String> {
    let endpoint = normalize_iroh_address(address);
    if endpoint.len() != 64 || !endpoint.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(endpoint.to_ascii_lowercase())
}

pub fn endpoint_id_from_address(input: &str) -> Option<String> {
    let value = input.trim();
    if value.is_empty() {
        return None;
    }

    for prefix in ["/ma-iroh/", "/iroh+ma/", "/iroh/"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let endpoint = rest.split('/').next().unwrap_or_default().trim();
            if endpoint.is_empty() {
                return None;
            }
            return normalize_endpoint_id(endpoint);
        }
    }

    normalize_endpoint_id(value)
}

pub fn endpoint_id_from_transport_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => endpoint_id_from_address(s),
        serde_json::Value::Object(map) => {
            for key in [
                "endpoint_id",
                "endpointId",
                "iroh",
                "address",
                "currentInbox",
                "current_inbox",
                "presenceHint",
                "presence_hint",
            ] {
                if let Some(serde_json::Value::String(s)) = map.get(key) {
                    if let Some(endpoint) = endpoint_id_from_address(s) {
                        return Some(endpoint);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

pub fn resolve_inbox_endpoint_id(
    current_inbox: Option<&str>,
    presence_hint: Option<&str>,
    transports: Option<&serde_json::Value>,
) -> Option<String> {
    if let Some(current) = current_inbox {
        if let Some(endpoint) = endpoint_id_from_address(current) {
            return Some(endpoint);
        }
    }

    if let Some(hint) = presence_hint {
        if let Some(endpoint) = endpoint_id_from_address(hint) {
            return Some(endpoint);
        }
    }

    if let Some(value) = transports {
        if let Some(items) = value.as_array() {
            for item in items {
                if let Some(endpoint) = endpoint_id_from_transport_value(item) {
                    return Some(endpoint);
                }
            }
        } else if let Some(endpoint) = endpoint_id_from_transport_value(value) {
            return Some(endpoint);
        }
    }

    None
}

pub fn resolve_alias_input(input: &str, alias_book: &HashMap<String, String>) -> String {
    let key = input.trim();
    if key.is_empty() {
        return String::new();
    }
    alias_book
        .get(key)
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

pub fn find_alias_for_address(address: &str, alias_book: &HashMap<String, String>) -> Option<String> {
    let raw = address.trim();
    if raw.is_empty() {
        return None;
    }

    if alias_book.contains_key(raw) {
        return Some(raw.to_string());
    }

    let root = did_root(raw);
    let endpoint = normalize_endpoint_id(raw);

    for (name, target) in alias_book {
        let value = target.trim();
        if value.is_empty() {
            continue;
        }
        if value == raw {
            return Some(name.clone());
        }
        if !root.is_empty() && (value == root || did_root(value) == root) {
            return Some(name.clone());
        }
        if let (Some(expected), Some(actual)) = (endpoint.as_deref(), normalize_endpoint_id(value).as_deref()) {
            if expected == actual {
                return Some(name.clone());
            }
        }
    }

    None
}

pub fn humanize_identifier(value: &str, alias_book: &HashMap<String, String>) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    find_alias_for_address(trimmed, alias_book).unwrap_or_else(|| trimmed.to_string())
}

pub fn find_did_by_endpoint(endpoint_like: &str, did_endpoint_map: &HashMap<String, String>) -> Option<String> {
    let endpoint = normalize_endpoint_id(endpoint_like)?;
    for (did, candidate) in did_endpoint_map {
        if normalize_endpoint_id(candidate).as_deref() == Some(endpoint.as_str()) {
            return Some(did.clone());
        }
    }
    None
}

pub fn humanize_text(text: &str, alias_book: &HashMap<String, String>) -> String {
    text.split_whitespace()
        .map(|token| {
            let normalized = token.trim_matches(|ch: char| {
                !(ch.is_ascii_alphanumeric() || ch == ':' || ch == '#' || ch == '/' || ch == '-' || ch == '_')
            });
            if normalized.is_empty() {
                return token.to_string();
            }

            let candidate = normalized.trim_end_matches(|ch: char| {
                matches!(ch, ':' | '.' | ',' | ';' | '!' | '?' | ')')
            });
            if candidate.is_empty() {
                return token.to_string();
            }

            let replacement = if candidate.starts_with("did:ma:") {
                humanize_identifier(&did_root(candidate), alias_book)
            } else if candidate.starts_with("/iroh/") {
                humanize_identifier(candidate, alias_book)
            } else if normalize_endpoint_id(candidate).is_some() {
                humanize_identifier(candidate, alias_book)
            } else {
                String::new()
            };

            if replacement.is_empty() || replacement == candidate {
                token.to_string()
            } else {
                token.replacen(candidate, &replacement, 1)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
