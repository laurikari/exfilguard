use std::sync::Arc;

use http::{Method, StatusCode};

use crate::config::{
    HttpsMode, MethodMatch, Policy, Rule, RuleAction, Scheme, parse_url_pattern,
    validate_policy_rules,
};
use crate::proxy::request::parse_http1_request;

use super::Decision;
use super::compile::compile_policy;
use super::matcher::{evaluate_policy, evaluate_tls_bump_preflight};
use super::model::CompiledPolicy;

fn rule(url: Option<&str>, present: Option<bool>) -> Rule {
    Rule {
        id: Arc::from("query"),
        action: RuleAction::Allow,
        methods: MethodMatch::List(vec![Method::GET]),
        url_pattern: url.map(|url| parse_url_pattern(url).unwrap()),
        query_present: present,
        https_mode: HttpsMode::Inspect,
        cache: None,
    }
}

fn policy(rules: Vec<Rule>) -> Policy {
    Policy {
        name: Arc::from("query-tests"),
        rules: rules.into(),
    }
}

fn compile(rules: Vec<Rule>) -> CompiledPolicy {
    let policy = policy(rules);
    validate_policy_rules(&policy).unwrap();
    compile_policy(&policy).unwrap()
}

fn evaluate(policy: &CompiledPolicy, target: &str) -> Option<Decision> {
    let parsed =
        parse_http1_request(Method::GET, target, Some("example.com"), Scheme::Https).unwrap();
    evaluate_policy(policy, &parsed.as_policy_request())
}

#[test]
fn query_presence_and_suffix_matrix() {
    let cases = [
        ("https://example.com/download", None, [true, true, true]),
        (
            "https://example.com/download",
            Some(false),
            [true, false, false],
        ),
        (
            "https://example.com/download",
            Some(true),
            [false, true, true],
        ),
        ("https://example.com/download?", None, [false, true, false]),
        (
            "https://example.com/download?",
            Some(true),
            [false, true, false],
        ),
        (
            "https://example.com/download?file=a",
            None,
            [false, false, true],
        ),
        (
            "https://example.com/download?file=a",
            Some(true),
            [false, false, true],
        ),
    ];
    for (url, present, expected) in cases {
        let compiled = compile(vec![rule(Some(url), present)]);
        for (target, expected) in ["/download", "/download?", "/download?file=a"]
            .into_iter()
            .zip(expected)
        {
            assert_eq!(
                evaluate(&compiled, target).is_some(),
                expected,
                "{url}, {present:?}, {target}"
            );
        }
    }
}

#[test]
fn query_presence_can_constrain_rules_without_a_url() {
    for present in [false, true] {
        let compiled = compile(vec![rule(None, Some(present))]);
        for (target, has_query) in [("/first", false), ("/other?", true), ("/third?x=1", true)] {
            assert_eq!(evaluate(&compiled, target).is_some(), present == has_query);
        }
    }
}

#[test]
fn query_matching_preserves_all_text_distinctions() {
    let query = "file=allowed.md&tag=first&tag=second";
    let compiled = compile(vec![rule(
        Some(&format!("https://example.com/download?{query}")),
        None,
    )]);
    assert!(evaluate(&compiled, &format!("/download?{query}")).is_some());
    for query in [
        "file=private.md&tag=first&tag=second",
        "file=Allowed.md&tag=first&tag=second",
        "file=%61llowed.md&tag=first&tag=second",
        "tag=first&file=allowed.md&tag=second",
        "file=allowed.md&tag=second&tag=first",
        "file=allowed.md&tag=first&tag=second&extra=1",
        "file=allowed.md&tag=first",
    ] {
        assert!(
            evaluate(&compiled, &format!("/download?{query}")).is_none(),
            "{query}"
        );
    }
}

#[test]
fn query_stars_and_other_syntax_are_literal() {
    let queries = [
        "file=*.md",
        "value=hello+world",
        "value=hello%20world",
        "value=%26%3D%3f",
        "value=%26%3D%3F",
        "value=%2526",
        "value=%",
        "value=%GG",
        "next=https://other.example/a?x=1&x=2",
        "flag",
        "flag=",
    ];
    for query in queries {
        let compiled = compile(vec![rule(
            Some(&format!("https://example.com/download?{query}")),
            None,
        )]);
        for candidate in queries {
            assert_eq!(
                evaluate(&compiled, &format!("/download?{candidate}")).is_some(),
                candidate == query,
                "pattern {query}, request {candidate}"
            );
        }
        assert!(evaluate(&compiled, "/download?file=report.md").is_none());
    }
}

#[test]
fn canonical_paths_still_combine_with_literal_queries() {
    let compiled = compile(vec![rule(
        Some("https://example.com/download?file=%61.md"),
        None,
    )]);
    assert!(evaluate(&compiled, "/%64ownload?file=%61.md").is_some());
    assert!(evaluate(&compiled, "/download?file=a.md").is_none());
    let compiled = compile(vec![rule(
        Some("https://example.com/files/*?file=*.md"),
        None,
    )]);
    assert!(evaluate(&compiled, "/files/report?file=*.md").is_some());
    assert!(evaluate(&compiled, "/files/report?file=report.md").is_none());
}

#[test]
fn query_mismatch_falls_through_in_rule_order() {
    let mut deny = rule(Some("https://example.com/download?file=private.md"), None);
    deny.id = Arc::from("deny-private");
    deny.action = RuleAction::Deny {
        status: StatusCode::FORBIDDEN,
        reason: None,
        body: None,
    };
    let compiled = compile(vec![deny, rule(Some("https://example.com/download"), None)]);
    assert!(matches!(
        evaluate(&compiled, "/download?file=private.md"),
        Some(Decision::Deny { .. })
    ));
    for target in [
        "/download",
        "/download?file=allowed.md",
        "/download?file=%70rivate.md",
    ] {
        assert!(matches!(
            evaluate(&compiled, target),
            Some(Decision::Allow { .. })
        ));
    }
}

#[test]
fn query_patterns_parse_authority_before_query_contents() {
    let parsed = parse_url_pattern("https://[::1]:8443?next=/foo?bar=1").unwrap();
    assert_eq!(parsed.host.as_ref(), "::1");
    assert_eq!(parsed.port, Some(8443));
    assert_eq!(parsed.path.as_deref(), Some("/"));
    assert_eq!(parsed.query.as_deref(), Some("next=/foo?bar=1"));
    let compiled = compile(vec![rule(Some("https://[::1]:8443?next=/foo?bar=1"), None)]);
    assert!(evaluate(&compiled, "https://[0:0:0:0:0:0:0:1]:8443/?next=/foo?bar=1").is_some());
    assert!(evaluate(&compiled, "https://[::1]:8443/other?next=/foo?bar=1").is_none());
    assert!(
        parse_url_pattern("https://example.com")
            .unwrap()
            .path
            .is_none()
    );
}

#[test]
fn contradictory_query_constraints_are_rejected() {
    for url in [
        "https://example.com/download?",
        "https://example.com/download?x=1",
    ] {
        let error = validate_policy_rules(&policy(vec![rule(Some(url), Some(false))])).unwrap_err();
        assert!(format!("{error:#}").contains("contradicts"));
    }
}

#[test]
fn query_constraints_are_rejected_on_connect_rules() {
    for (url, present) in [
        ("https://example.com/**?x=1", None),
        ("https://example.com/**?", None),
        ("https://example.com/**", Some(false)),
        ("https://example.com/**", Some(true)),
    ] {
        let mut connect = rule(Some(url), present);
        connect.methods = MethodMatch::List(vec![Method::CONNECT]);
        connect.https_mode = HttpsMode::Tunnel;
        let error = validate_policy_rules(&policy(vec![connect])).unwrap_err();
        assert!(format!("{error:#}").contains("CONNECT rules cannot constrain queries"));
    }
}

#[test]
fn query_constraints_do_not_block_inspection_preflight() {
    let compiled = compile(vec![rule(
        Some("https://example.com/download?file=allowed.md"),
        Some(true),
    )]);
    let request = super::matcher::Request {
        method: &Method::CONNECT,
        scheme: Scheme::Https,
        host: "example.com",
        port: Some(443),
        path: "example.com:443",
        query: None,
    };
    assert!(evaluate_tls_bump_preflight(compiled.rules.iter(), &request));
}

#[test]
fn invalid_queries_are_rejected_without_echoing_contents() {
    for query in [
        "secret-marker#fragment",
        "secret-marker value",
        "secret-marker\r\n",
        "secret-marker\0",
    ] {
        let error =
            parse_url_pattern(&format!("https://example.com/download?{query}")).unwrap_err();
        assert!(!format!("{error:#}").contains("secret-marker"));

        let mut invalid = rule(Some("https://example.com/download"), None);
        invalid.url_pattern.as_mut().unwrap().query = Some(Arc::from(query));
        let error = validate_policy_rules(&policy(vec![invalid])).unwrap_err();
        assert!(!format!("{error:#}").contains("secret-marker"));
    }
}

#[test]
fn programmatic_query_with_no_path_matches_only_root() {
    let mut exact_root = rule(Some("https://example.com"), None);
    exact_root.url_pattern.as_mut().unwrap().query = Some(Arc::from("x=1"));
    let compiled = compile(vec![exact_root]);
    assert!(evaluate(&compiled, "/?x=1").is_some());
    assert!(evaluate(&compiled, "/other?x=1").is_none());
}
