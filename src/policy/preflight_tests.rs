use std::sync::Arc;

use http::{Method, StatusCode};

use crate::authorization::policy::DynamicPolicy;
use crate::config::{
    Client, ClientSelector, Config, HttpsMode, MethodMatch, Policy, Rule, RuleAction, Scheme,
    ValidatedConfig, parse_url_pattern,
};

use super::compile::compile_config;
use super::matcher::{PolicyMatcher, Request};

fn allow(methods: &[&str], path: &str, query_present: Option<bool>) -> Rule {
    Rule {
        id: Arc::from("test"),
        action: RuleAction::Allow,
        methods: if methods == ["ANY"] {
            MethodMatch::Any
        } else {
            MethodMatch::List(
                methods
                    .iter()
                    .map(|method| method.parse().unwrap())
                    .collect(),
            )
        },
        url_pattern: Some(parse_url_pattern(&format!("https://api.example.test{path}")).unwrap()),
        query_present,
        https_mode: HttpsMode::Inspect,
        cache: None,
    }
}

fn deny(mut rule: Rule) -> Rule {
    rule.action = RuleAction::Deny {
        status: StatusCode::FORBIDDEN,
        reason: None,
        body: None,
    };
    rule
}

fn request() -> Request<'static> {
    Request {
        method: &Method::CONNECT,
        scheme: Scheme::Https,
        host: "api.example.test",
        port: Some(443),
        path: "api.example.test:443",
        query: None,
    }
}

fn local_preflight(policies: Vec<Vec<Rule>>, order: &[usize]) -> bool {
    let policies: Vec<Policy> = policies
        .into_iter()
        .enumerate()
        .map(|(index, rules)| Policy {
            name: Arc::from(format!("policy-{index}")),
            rules: rules.into(),
        })
        .collect();
    let config = ValidatedConfig::new(Config {
        clients: vec![Client {
            name: Arc::from("default"),
            selector: ClientSelector::Fallback,
            policies: order
                .iter()
                .map(|&index| policies[index].name.clone())
                .collect(),
            authorization_service: None,
            password_hash: None,
            credential_limits: Arc::from([]),
            max_connections: 1024,
        }],
        policies,
    })
    .unwrap();
    let compiled = Arc::new(compile_config(&config).unwrap());
    PolicyMatcher::new(compiled.clone())
        .evaluate_tls_bump_preflight(&compiled.clients[0].policies, &request())
}

// Exercise the same decisions within one policy, across the client's ordered
// policies, and through the delegated-policy entry point.
fn check(rules: Vec<Rule>, expected: bool) {
    assert_eq!(
        local_preflight(vec![rules.clone()], &[0]),
        expected,
        "single policy: {rules:?}"
    );
    assert_eq!(
        local_preflight(
            rules.iter().cloned().map(|rule| vec![rule]).collect(),
            &(0..rules.len()).collect::<Vec<_>>(),
        ),
        expected,
        "multiple policies: {rules:?}"
    );
    assert_eq!(
        DynamicPolicy::compile_rules(rules.clone())
            .unwrap()
            .allows_tls_bump(&request()),
        expected,
        "delegated policy: {rules:?}"
    );
}

#[test]
fn preflight_checks_complete_method_coverage_including_extensions() {
    for (denied, allowed, expected) in [
        (vec!["ANY"], vec!["GET"], false),
        (vec!["GET"], vec!["GET"], false),
        (vec!["POST", "GET"], vec!["GET"], false),
        (vec!["GET"], vec!["GET", "POST"], true),
        (vec!["GET"], vec!["ANY"], true),
        (vec!["ANY"], vec!["ANY"], false),
        (vec!["ANY"], vec!["PROPFIND"], false),
        (vec!["GET", "PROPFIND"], vec!["PROPFIND"], false),
        (vec!["GET"], vec!["PROPFIND"], true),
        (vec!["PROPFIND"], vec!["PROPPATCH"], true),
    ] {
        check(
            vec![
                deny(allow(&denied, "/**", None)),
                allow(&allowed, "/safe", None),
            ],
            expected,
        );
    }
}

#[test]
fn preflight_checks_only_unrestricted_or_identical_paths() {
    for (denied, allowed, expected) in [
        ("", "/safe", false),
        ("/**", "", false),
        ("/safe", "/safe", false),
        ("/api/*", "/api/*", false),
        ("/api/**", "/api/**", false),
        ("/safe", "/**", true),
        ("/private", "/safe", true),
        ("/api/**", "/api/safe", true),
        ("/literal\\*", "/literal%2A", true),
        ("/literal%2A", "/literal\\*", true),
    ] {
        check(
            vec![
                deny(allow(&["ANY"], denied, None)),
                allow(&["GET"], allowed, None),
            ],
            expected,
        );
    }
    let mut unrestricted_deny = deny(allow(&["ANY"], "", None));
    unrestricted_deny.url_pattern = None;
    check(
        vec![unrestricted_deny, allow(&["GET"], "/safe", None)],
        false,
    );
}

#[test]
fn preflight_preserves_asterisk_form_options() {
    for methods in [&["OPTIONS"][..], &["ANY"][..]] {
        check(
            vec![deny(allow(&["ANY"], "/**", None)), allow(methods, "", None)],
            true,
        );
        check(
            vec![deny(allow(&["ANY"], "", None)), allow(methods, "", None)],
            false,
        );
        check(
            vec![
                deny(allow(&["ANY"], "/**", None)),
                allow(methods, "/**", None),
            ],
            false,
        );
    }
}

#[test]
fn preflight_respects_literal_queries_and_query_presence() {
    for (denied_path, denied_presence, allowed_path, allowed_presence, expected) in [
        ("/**", None, "/safe?x=1", None, false),
        ("/**", Some(true), "/safe?x=1", None, false),
        ("/**", Some(false), "/safe?", None, true),
        ("/**", Some(true), "/safe", None, true),
        ("/**", Some(false), "/safe", None, true),
        ("/**", Some(false), "/safe", Some(false), false),
        ("/**", Some(true), "/safe", Some(true), false),
        ("/**?", None, "/safe?", Some(true), false),
        ("/**?", Some(true), "/safe?", None, false),
        ("/**?", None, "/safe", None, true),
        ("/**?x=1", None, "/safe?x=1", None, false),
        ("/**?x=1", None, "/safe?x=2", None, true),
        ("/**?x=*", None, "/safe?x=value", None, true),
        ("/**?x=%2A", None, "/safe?x=*", None, true),
    ] {
        check(
            vec![
                deny(allow(&["ANY"], denied_path, denied_presence)),
                allow(&["GET"], allowed_path, allowed_presence),
            ],
            expected,
        );
    }
}

#[test]
fn preflight_matches_each_authority_before_checking_shadowing() {
    for (url, expected) in [
        ("https://*.example.test/**", false),
        ("https://api.example.test:443/**", false),
        ("https://other.example.test/**", true),
        ("https://api.example.test:8443/**", true),
        ("http://api.example.test:443/**", true),
    ] {
        let mut denied = deny(allow(&["ANY"], "/**", None));
        denied.url_pattern = Some(parse_url_pattern(url).unwrap());
        check(vec![denied, allow(&["GET"], "/safe", None)], expected);
    }
}

#[test]
fn preflight_preserves_earlier_allows_and_continues_after_shadowed_allows() {
    let denied = deny(allow(&["GET"], "/**", None));
    let allowed = allow(&["GET"], "/safe", None);
    check(vec![allowed.clone(), denied.clone()], true);
    check(
        vec![
            denied.clone(),
            allowed.clone(),
            allow(&["POST"], "/safe", None),
        ],
        true,
    );
    assert!(!local_preflight(
        vec![vec![allowed.clone()], vec![denied.clone()]],
        &[1, 0]
    ));
    assert!(local_preflight(vec![vec![denied], vec![allowed]], &[1, 0]));
}

#[test]
fn preflight_does_not_combine_partial_denies() {
    check(
        vec![
            deny(allow(&["GET"], "/**", None)),
            deny(allow(&["POST"], "/**", None)),
            allow(&["GET", "POST"], "/safe", None),
        ],
        true,
    );
}
