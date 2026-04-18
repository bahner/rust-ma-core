//! Transport string parsing and endpoint resolution from DID documents.
//!
//! DID documents contain a `services` array with entries like:
//!
//! ```text
//! /iroh/<endpoint-id>/<protocol>
//! ```
//!
//! This module provides helpers to parse those strings, extract endpoint IDs,
//! and resolve inbox endpoints from DID document metadata.

/// Parse a transport string and extract the endpoint ID.
///
/// Accepts formats:
/// - `/iroh/<endpoint-id>/<protocol>`
/// - `/ma-iroh/<endpoint-id>/<protocol>` (legacy, accepted per Postel's law)
/// - `/iroh+ma/<endpoint-id>/...`
/// - bare 64-char hex endpoint ID
pub fn endpoint_id_from_transport(input: &str) -> Option<String> {
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

/// Parse a transport string and extract the protocol (service identifier).
///
/// For `/iroh/<endpoint-id>/ma/inbox/0.0.1` returns `Some("/ma/inbox/0.0.1")`.
pub fn protocol_from_transport(input: &str) -> Option<String> {
    let value = input.trim();
    for prefix in ["/ma-iroh/", "/iroh+ma/", "/iroh/"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            // Skip the endpoint-id segment
            if let Some(after_id) = rest.find('/') {
                let protocol = &rest[after_id..];
                if !protocol.is_empty() {
                    return Some(protocol.to_string());
                }
            }
        }
    }
    None
}

/// Extract endpoint ID from a transport JSON value (string or object).
pub fn endpoint_id_from_transport_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => endpoint_id_from_transport(s),
        serde_json::Value::Object(map) => {
            for key in ["endpoint_id", "endpointId", "iroh", "address"] {
                if let Some(serde_json::Value::String(s)) = map.get(key) {
                    if let Some(endpoint) = endpoint_id_from_transport(s) {
                        return Some(endpoint);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Resolve the inbox endpoint ID from a DID document's `ma` section.
///
/// Iterates `services` array entries looking for a parseable endpoint ID.
pub fn resolve_inbox_endpoint_id(services: Option<&serde_json::Value>) -> Option<String> {
    let value = services?;
    if let Some(items) = value.as_array() {
        for item in items {
            if let Some(endpoint) = endpoint_id_from_transport_value(item) {
                return Some(endpoint);
            }
        }
    } else if let Some(endpoint) = endpoint_id_from_transport_value(value) {
        return Some(endpoint);
    }
    None
}

/// Find the first transport entry matching a given protocol and return its endpoint ID.
pub fn resolve_endpoint_for_protocol(
    services: Option<&serde_json::Value>,
    target_protocol: &str,
) -> Option<String> {
    let target = normalize_protocol(target_protocol);
    let value = services?;

    if let Some(items) = value.as_array() {
        for item in items {
            if let Some(endpoint) = endpoint_for_service_item(item, &target) {
                return Some(endpoint);
            }
        }
        return None;
    }

    endpoint_for_service_item(value, &target)
}

fn endpoint_for_service_item(item: &serde_json::Value, target_protocol: &str) -> Option<String> {
    if let Some(s) = item.as_str() {
        let protocol = protocol_from_transport(s)?;
        if normalize_protocol(&protocol) == target_protocol {
            return endpoint_id_from_transport(s);
        }
        return None;
    }

    let map = item.as_object()?;

    let protocol = map
        .get("protocol")
        .or_else(|| map.get("service"))
        .or_else(|| map.get("alpn"))
        .and_then(|v| v.as_str())?;

    if normalize_protocol(protocol) != target_protocol {
        return None;
    }

    for key in ["endpoint_id", "endpointId", "iroh", "address"] {
        if let Some(serde_json::Value::String(s)) = map.get(key) {
            if let Some(endpoint) = endpoint_id_from_transport(s) {
                return Some(endpoint);
            }
        }
    }

    None
}

fn normalize_protocol(input: &str) -> String {
    let protocol = input.trim();
    if protocol.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    if !protocol.starts_with('/') {
        out.push('/');
    }
    out.push_str(protocol.trim_start_matches('/'));
    out
}

/// Normalize an endpoint ID string: strip `/iroh/` prefix, validate hex format.
pub fn normalize_endpoint_id(address: &str) -> Option<String> {
    let value = address.trim();
    let endpoint = value.strip_prefix("/iroh/").unwrap_or(value);
    if endpoint.len() != 64 || !endpoint.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(endpoint.to_ascii_lowercase())
}

/// Build a transport string from an endpoint ID and protocol.
///
/// Returns `/iroh/<endpoint-id><protocol>` where protocol starts with `/`.
pub fn transport_string(endpoint_id: &str, protocol: &str) -> String {
    format!("/iroh/{}{}", endpoint_id, normalize_protocol(protocol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iroh_transport() {
        let input =
            "/iroh/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/ma/inbox/0.0.1";
        let id = endpoint_id_from_transport(input).unwrap();
        assert_eq!(
            id,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_legacy_ma_iroh_transport() {
        // Postel's law: still accept /ma-iroh/ on input
        let input = "/ma-iroh/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/ma/inbox/0.0.1";
        let id = endpoint_id_from_transport(input).unwrap();
        assert_eq!(
            id,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_protocol_from_transport() {
        let input =
            "/iroh/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/ma/inbox/0.0.1";
        assert_eq!(protocol_from_transport(input).unwrap(), "/ma/inbox/0.0.1");
    }

    #[test]
    fn parse_protocol_from_legacy_transport() {
        let input = "/ma-iroh/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/ma/presence/0.0.1";
        assert_eq!(
            protocol_from_transport(input).unwrap(),
            "/ma/presence/0.0.1"
        );
    }

    #[test]
    fn bare_endpoint_id() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(endpoint_id_from_transport(id).unwrap(), id);
    }

    #[test]
    fn rejects_short_id() {
        assert!(endpoint_id_from_transport("abcdef").is_none());
    }

    #[test]
    fn rejects_empty() {
        assert!(endpoint_id_from_transport("").is_none());
        assert!(endpoint_id_from_transport("  ").is_none());
    }

    #[test]
    fn normalizes_to_lowercase() {
        let id = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let result = endpoint_id_from_transport(id).unwrap();
        assert_eq!(result, id.to_ascii_lowercase());
    }

    #[test]
    fn resolve_from_services_array() {
        let services = serde_json::json!([
            "/iroh/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/ma/inbox/0.0.1"
        ]);
        let id = resolve_inbox_endpoint_id(Some(&services)).unwrap();
        assert_eq!(
            id,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn resolve_from_legacy_services_array() {
        // Postel's law: still resolve /ma-iroh/ services
        let services = serde_json::json!([
            "/ma-iroh/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/ma/inbox/0.0.1"
        ]);
        let id = resolve_inbox_endpoint_id(Some(&services)).unwrap();
        assert_eq!(
            id,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn resolve_endpoint_for_specific_protocol() {
        let services = serde_json::json!([
            "/iroh/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/ma/inbox/0.0.1",
            "/iroh/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/ma/presence/0.0.1"
        ]);
        let id = resolve_endpoint_for_protocol(Some(&services), "/ma/presence/0.0.1").unwrap();
        assert_eq!(
            id,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn resolve_endpoint_for_protocol_from_object() {
        let services = serde_json::json!([
            {
                "protocol": "/ma/inbox/0.0.1",
                "endpoint_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        ]);
        let id = resolve_endpoint_for_protocol(Some(&services), "/ma/inbox/0.0.1").unwrap();
        assert_eq!(
            id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn resolve_endpoint_for_protocol_allows_missing_leading_slash() {
        let services = serde_json::json!([
            {
                "protocol": "ma/inbox/0.0.1",
                "endpoint_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        ]);
        let id = resolve_endpoint_for_protocol(Some(&services), "/ma/inbox/0.0.1").unwrap();
        assert_eq!(
            id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn transport_string_format() {
        let s = transport_string(
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "/ma/inbox/0.0.1",
        );
        assert_eq!(
            s,
            "/iroh/abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234/ma/inbox/0.0.1"
        );
    }

    #[test]
    fn transport_string_normalizes_missing_leading_slash() {
        let s = transport_string(
            "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "ma/inbox/0.0.1",
        );
        assert_eq!(
            s,
            "/iroh/abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234/ma/inbox/0.0.1"
        );
    }
}
