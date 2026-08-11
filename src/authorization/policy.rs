use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use http::header::HeaderName;

use crate::config::{BodyAccess, HttpsMode, MethodMatch, Policy, Rule, RuleAction, UrlPattern};
use crate::policy::Decision;
use crate::policy::compile::compile_policy;
use crate::policy::matcher::{Request, evaluate_policy, evaluate_tls_bump_preflight_policy};
use crate::policy::model::{CompiledCredentialLimit, CompiledPolicy};

use super::{AuthorizationToken, ResolvedAuthorizationPolicy};

pub(crate) struct DynamicPolicy {
    compiled: CompiledPolicy,
    credentials: HashMap<Arc<str>, DynamicCredential>,
}

impl DynamicPolicy {
    pub(crate) fn compile(rules: Vec<(Rule, Option<DynamicCredential>)>) -> Result<Self> {
        let credentials = rules
            .iter()
            .filter_map(|(rule, credential)| {
                credential
                    .as_ref()
                    .map(|credential| (rule.id.clone(), credential.clone()))
            })
            .collect();
        let policy = Policy {
            name: Arc::from("authorization-service"),
            rules: Arc::from(
                rules
                    .into_iter()
                    .map(|(rule, _)| rule)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
        };
        crate::config::validate_policy_rules(&policy).context("invalid dynamic request policy")?;
        Ok(Self {
            compiled: compile_policy(&policy)?,
            credentials,
        })
    }

    #[cfg(test)]
    pub(crate) fn compile_rules(rules: Vec<Rule>) -> Result<Self> {
        Self::compile(rules.into_iter().map(|rule| (rule, None)).collect())
    }

    pub(crate) fn evaluate(&self, request: &Request<'_>) -> Option<DynamicEvaluation> {
        let decision = evaluate_policy(&self.compiled, request)?;
        let credential = match &decision {
            Decision::Allow { rule, .. } => self.credentials.get(rule).cloned(),
            Decision::Deny { .. } => None,
        };
        Some(DynamicEvaluation {
            decision,
            credential,
        })
    }

    pub(crate) fn allows_tls_bump(&self, request: &Request<'_>) -> bool {
        evaluate_tls_bump_preflight_policy(&self.compiled, request)
    }
}

pub(crate) struct DynamicEvaluation {
    pub(crate) decision: Decision,
    pub(crate) credential: Option<DynamicCredential>,
}

#[derive(Clone)]
pub(crate) struct DynamicCredential {
    pub(crate) credential_reference: Arc<str>,
    pub(crate) protected_headers: Arc<[HeaderName]>,
    pub(crate) body_access: BodyAccess,
}

#[derive(Clone)]
pub(crate) struct CredentialAuthorization {
    pub(crate) token: Arc<AuthorizationToken>,
    pub(crate) authorization_service: Arc<str>,
    pub(crate) credential_reference: Arc<str>,
    pub(crate) protected_headers: Arc<[HeaderName]>,
    pub(crate) body_access: BodyAccess,
}

#[derive(Clone)]
pub(crate) struct DelegatedAuthorization {
    pub(crate) token: Arc<AuthorizationToken>,
    pub(crate) policy: Arc<ResolvedAuthorizationPolicy>,
    pub(crate) rule: Arc<str>,
    pub(crate) credential: Option<Arc<CredentialAuthorization>>,
}

impl std::fmt::Debug for DelegatedAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedAuthorization")
            .field("authorization_token_id", &self.token.correlation())
            .field("policy_version", &self.policy.policy_version)
            .field("rule", &self.rule)
            .field("has_credential", &self.credential.is_some())
            .finish()
    }
}

pub(crate) fn build_dynamic_credential(
    credential_reference: String,
    protected_headers: Vec<String>,
    body_access: BodyAccess,
) -> Result<DynamicCredential> {
    ensure!(
        !credential_reference.trim().is_empty(),
        "credential reference must not be empty"
    );
    let protected_headers = parse_protected_headers(&protected_headers)?;
    Ok(DynamicCredential {
        credential_reference: Arc::from(credential_reference),
        protected_headers,
        body_access,
    })
}

pub(crate) fn authorize_credential(
    token: Arc<AuthorizationToken>,
    authorization_service: Arc<str>,
    dynamic: Option<&DynamicCredential>,
    request: &Request<'_>,
    local_limits: &[CompiledCredentialLimit],
) -> Result<Option<Arc<CredentialAuthorization>>> {
    let Some(dynamic) = dynamic else {
        return Ok(None);
    };
    ensure!(
        local_limits.iter().any(|candidate| {
            candidate.credential_reference == dynamic.credential_reference
                && candidate.origin.matches_request(
                    request.scheme,
                    request.host,
                    request.port,
                    request.path,
                )
                && headers_are_subset(&dynamic.protected_headers, &candidate.protected_headers)
                && body_access_is_subset(dynamic.body_access, candidate.body_access)
        }),
        "credential request is outside the client's local limit"
    );
    let credential_reference = dynamic.credential_reference.clone();
    let protected_headers = dynamic.protected_headers.clone();
    let body_access = dynamic.body_access;
    Ok(Some(Arc::new(CredentialAuthorization {
        token,
        authorization_service,
        credential_reference,
        protected_headers,
        body_access,
    })))
}

fn parse_protected_headers(names: &[String]) -> Result<Arc<[HeaderName]>> {
    ensure!(!names.is_empty(), "protected_headers must not be empty");
    let mut seen = HashSet::new();
    let mut parsed = Vec::with_capacity(names.len());
    for name in names {
        let header = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid protected header name '{name}'"))?;
        ensure!(
            !is_forbidden_protected_header(header.as_str()),
            "forbidden protected header '{}'",
            header.as_str()
        );
        ensure!(
            seen.insert(header.clone()),
            "duplicate protected header '{}'",
            header.as_str()
        );
        parsed.push(header);
    }
    Ok(Arc::from(parsed.into_boxed_slice()))
}

fn headers_are_subset(dynamic: &[HeaderName], local: &[HeaderName]) -> bool {
    dynamic.iter().all(|name| local.contains(name))
}

fn body_access_is_subset(dynamic: BodyAccess, local: BodyAccess) -> bool {
    dynamic == BodyAccess::None || local == BodyAccess::BoundedPayload
}

pub(crate) fn is_forbidden_protected_header(name: &str) -> bool {
    matches!(
        crate::proxy::headers::classify_request_header(name),
        crate::proxy::headers::HeaderDisposition::Connection
            | crate::proxy::headers::HeaderDisposition::Host
            | crate::proxy::headers::HeaderDisposition::ContentLength
            | crate::proxy::headers::HeaderDisposition::TransferEncoding
            | crate::proxy::headers::HeaderDisposition::Skip
    ) || matches!(name, "expect" | "trailer" | "via" | "cookie" | "set-cookie")
}

pub(crate) fn make_dynamic_rule(
    index: usize,
    action: RuleAction,
    methods: MethodMatch,
    url_pattern: Option<UrlPattern>,
) -> Rule {
    Rule {
        id: Arc::from(format!("authorization-service#{index}")),
        action,
        methods,
        url_pattern,
        https_mode: HttpsMode::Inspect,
        cache: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_credential_is_parsed_without_interpreting_its_reference() {
        let accepted = build_dynamic_credential(
            "profile-a".to_string(),
            vec!["authorization".to_string()],
            BodyAccess::None,
        )
        .unwrap();
        assert_eq!(accepted.credential_reference.as_ref(), "profile-a");
        assert!(
            build_dynamic_credential(
                "profile-a".to_string(),
                vec!["cookie".to_string()],
                BodyAccess::None,
            )
            .is_err()
        );
    }

    #[test]
    fn dynamic_rules_reject_connect() {
        assert!(super::super::service::parse_methods(Some(vec!["CONNECT".to_string()])).is_err());
    }
}
