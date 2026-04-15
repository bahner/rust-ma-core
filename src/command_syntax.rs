#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyCommand {
    pub key: String,
    pub value: Option<String>,
}

pub fn parse_property_command(input: &str) -> Option<PropertyCommand> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let payload = if let Some(rest) = trimmed.strip_prefix("prop ") {
        rest.trim()
    } else {
        trimmed
    };

    if payload.is_empty() {
        return None;
    }

    let mut parts = payload.splitn(2, char::is_whitespace);
    let key = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    if key.is_empty() {
        return None;
    }

    let value = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    Some(PropertyCommand { key, value })
}

pub fn parse_property_command_for_keys(input: &str, allowed_keys: &[&str]) -> Option<PropertyCommand> {
    let parsed = parse_property_command(input)?;

    if !allowed_keys
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(parsed.key.as_str()))
    {
        return None;
    }

    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::{parse_property_command, parse_property_command_for_keys};

    #[test]
    fn parses_generic_payload() {
        let parsed = parse_property_command("cid bafy...")
            .expect("generic property command should parse");
        assert_eq!(parsed.key, "cid");
        assert_eq!(parsed.value.as_deref(), Some("bafy..."));
    }

    #[test]
    fn parses_plain_dot_payload() {
        let parsed = parse_property_command_for_keys("owner did:ma:foo", &["owner"])
            .expect("owner command should parse");
        assert_eq!(parsed.key, "owner");
        assert_eq!(parsed.value.as_deref(), Some("did:ma:foo"));
    }

    #[test]
    fn parses_legacy_prop_payload() {
        let parsed = parse_property_command_for_keys("prop owner did:ma:foo", &["owner"])
            .expect("prop owner command should parse");
        assert_eq!(parsed.key, "owner");
        assert_eq!(parsed.value.as_deref(), Some("did:ma:foo"));
    }

    #[test]
    fn rejects_non_allowed_key() {
        let parsed = parse_property_command_for_keys("save", &["owner", "did"]);
        assert!(parsed.is_none());
    }
}