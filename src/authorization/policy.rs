use std::sync::Arc;

use anyhow::{Context, Result};

use crate::config::{HttpsMode, MethodMatch, Policy, Rule, RuleAction, UrlPattern};
use crate::policy::Decision;
use crate::policy::compile::compile_policy;
use crate::policy::matcher::{Request, evaluate_policy, evaluate_tls_bump_preflight_policy};
use crate::policy::model::CompiledPolicy;

use super::{AuthorizationToken, ResolvedAuthorizationPolicy};

pub(crate) struct DynamicPolicy {
    compiled: CompiledPolicy,
}

impl DynamicPolicy {
    pub(crate) fn compile(rules: Vec<Rule>) -> Result<Self> {
        let policy = Policy {
            name: Arc::from("authorization-service"),
            rules: Arc::from(rules.into_boxed_slice()),
        };
        crate::config::validate_policy_rules(&policy).context("invalid dynamic request policy")?;
        Ok(Self {
            compiled: compile_policy(&policy)?,
        })
    }

    pub(crate) fn compile_rules(rules: Vec<Rule>) -> Result<Self> {
        Self::compile(rules)
    }

    pub(crate) fn evaluate(&self, request: &Request<'_>) -> Option<Decision> {
        evaluate_policy(&self.compiled, request)
    }

    pub(crate) fn allows_tls_bump(&self, request: &Request<'_>) -> bool {
        evaluate_tls_bump_preflight_policy(&self.compiled, request)
    }
}

#[derive(Clone)]
pub(crate) struct DelegatedAuthorization {
    pub(crate) token: Arc<AuthorizationToken>,
    pub(crate) policy: Arc<ResolvedAuthorizationPolicy>,
    pub(crate) rule: Arc<str>,
}

impl std::fmt::Debug for DelegatedAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedAuthorization")
            .field("authorization_token_id", &self.token.correlation())
            .field("policy_version", &self.policy.policy_version)
            .field("rule", &self.rule)
            .finish()
    }
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
    #[test]
    fn dynamic_rules_reject_connect() {
        assert!(super::super::service::parse_methods(Some(vec!["CONNECT".to_string()])).is_err());
    }
}
