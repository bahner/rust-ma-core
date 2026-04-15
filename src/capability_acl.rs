use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow};
use did_ma::Did;
use serde::Deserialize;

pub type CapabilityAcl = HashMap<String, Vec<String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSubjectAcl {
    pub exact: HashSet<String>,
    pub wildcard: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCapabilityAcl {
    pub subjects: HashMap<String, CompiledSubjectAcl>,
}

#[derive(Debug, Clone, Deserialize)]
struct CapabilityAclDoc {
    acl: CapabilityAcl,
}

pub fn validate_capability_acl(acl: &CapabilityAcl, source: &str) -> Result<()> {
    for (subject, patterns) in acl {
        if subject != "*" && !subject.eq_ignore_ascii_case("owner") {
            Did::try_from(subject.as_str())
                .map_err(|e| anyhow!("invalid ACL subject '{}' in {}: {}", subject, source, e))?;
        }
        for pattern in patterns {
            if pattern.trim().is_empty() {
                return Err(anyhow!(
                    "empty capability pattern for subject '{}' in {}",
                    subject,
                    source
                ));
            }
        }
    }
    Ok(())
}

pub fn parse_capability_acl_text(raw: &str, source: &str) -> Result<CapabilityAcl> {
    if let Ok(doc) = serde_yaml::from_str::<CapabilityAclDoc>(raw) {
        validate_capability_acl(&doc.acl, source)?;
        return Ok(doc.acl);
    }
    if let Ok(doc) = serde_json::from_str::<CapabilityAclDoc>(raw) {
        validate_capability_acl(&doc.acl, source)?;
        return Ok(doc.acl);
    }
    if let Ok(acl) = serde_yaml::from_str::<CapabilityAcl>(raw) {
        validate_capability_acl(&acl, source)?;
        return Ok(acl);
    }
    if let Ok(acl) = serde_json::from_str::<CapabilityAcl>(raw) {
        validate_capability_acl(&acl, source)?;
        return Ok(acl);
    }
    Err(anyhow!("unsupported capability ACL format in {}", source))
}

pub fn capability_pattern_matches(pattern: &str, value: &str) -> bool {
    // Simple glob matcher where '*' matches zero or more characters.
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let mut pi = 0usize;
    let mut vi = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_vi = 0usize;

    while vi < v.len() {
        if pi < p.len() && p[pi] == v[vi] {
            pi += 1;
            vi += 1;
            continue;
        }
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_vi = vi;
            continue;
        }
        if let Some(star_at) = star_pi {
            pi = star_at + 1;
            star_vi += 1;
            vi = star_vi;
            continue;
        }
        return false;
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

pub fn subject_has_capability(acl: &CapabilityAcl, subject: &str, capability: &str) -> bool {
    let patterns = acl.get(subject).or_else(|| acl.get("*"));
    let Some(patterns) = patterns else {
        return false;
    };
    patterns
        .iter()
        .any(|pattern| capability_pattern_matches(pattern.trim(), capability))
}

pub fn subject_has_capability_with_owner(
    acl: &CapabilityAcl,
    subject: &str,
    owner_did: Option<&str>,
    capability: &str,
) -> bool {
    let owner_match = owner_did
        .is_some_and(|owner| owner == subject)
        && acl
            .get("owner")
            .map(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| capability_pattern_matches(pattern.trim(), capability))
            })
            .unwrap_or(false);

    owner_match || subject_has_capability(acl, subject, capability)
}

pub fn parse_object_local_capability_acl(
    state: &serde_json::Value,
) -> Result<Option<CapabilityAcl>> {
    let Some(acl_value) = state
        .as_object()
        .and_then(|obj| obj.get("acl").or_else(|| obj.get("capabilities_acl")))
    else {
        return Ok(None);
    };

    let acl: CapabilityAcl = serde_json::from_value(acl_value.clone())
        .map_err(|e| anyhow!("invalid object local capability ACL: {}", e))?;
    validate_capability_acl(&acl, "object-local-acl")?;
    Ok(Some(acl))
}

pub fn compile_acl(acl: &CapabilityAcl, source: &str) -> Result<CompiledCapabilityAcl> {
    validate_capability_acl(acl, source)?;

    let mut subjects = HashMap::new();
    for (subject, patterns) in acl {
        let mut exact = HashSet::new();
        let mut wildcard = Vec::new();
        for pattern in patterns {
            let trimmed = pattern.trim();
            if trimmed.contains('*') {
                wildcard.push(trimmed.to_string());
            } else {
                exact.insert(trimmed.to_string());
            }
        }

        // Canonicalization: if a subject has '*' wildcard, all other wildcards
        // and exact entries are redundant for allow semantics.
        if wildcard.iter().any(|pattern| pattern == "*") {
            wildcard = vec!["*".to_string()];
            exact.clear();
        }

        // Canonicalization: remove exact entries already matched by wildcard.
        if !wildcard.is_empty() {
            exact.retain(|cap| {
                !wildcard
                    .iter()
                    .any(|pattern| capability_pattern_matches(pattern, cap))
            });
        }

        wildcard.sort();
        wildcard.dedup();
        subjects.insert(subject.clone(), CompiledSubjectAcl { exact, wildcard });
    }

    Ok(CompiledCapabilityAcl { subjects })
}

pub fn compile_acl_from_text(raw: &str, source: &str) -> Result<CompiledCapabilityAcl> {
    let acl = parse_capability_acl_text(raw, source)?;
    compile_acl(&acl, source)
}

pub fn evaluate_compiled_acl(
    acl: &CompiledCapabilityAcl,
    subject: &str,
    capability: &str,
) -> bool {
    let subject_acl = acl
        .subjects
        .get(subject)
        .or_else(|| acl.subjects.get("*"));
    let Some(subject_acl) = subject_acl else {
        return false;
    };

    if subject_acl.exact.contains(capability) {
        return true;
    }

    subject_acl
        .wildcard
        .iter()
        .any(|pattern| capability_pattern_matches(pattern, capability))
}

pub fn evaluate_compiled_acl_with_owner(
    acl: &CompiledCapabilityAcl,
    subject: &str,
    owner_did: Option<&str>,
    capability: &str,
) -> bool {
    let owner_match = owner_did
        .is_some_and(|owner| owner == subject)
        && evaluate_compiled_acl(acl, "owner", capability);

    owner_match || evaluate_compiled_acl(acl, subject, capability)
}
