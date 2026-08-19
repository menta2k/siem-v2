//! Cloudflare rule expression evaluation sidecar.
//!
//! This service exists because there is no viable Go binding to wirefilter and
//! its C ABI is still moving, so a cgo binding would break portable Go builds
//! and share a process with log collection (research.md R1). A process boundary
//! gives crash isolation by construction, which FR-073d requires.
//!
//! What it deliberately does NOT claim: this evaluates a rule EXPRESSION. It does
//! not reproduce Cloudflare's full product evaluation — managed rulesets,
//! execution order, skip rules — and every response says so.

mod scheme;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use wirefilter::{ExecutionContext, Scheme};

const ENGINE_VERSION: &str = "wirefilter-engine-0.6.1";
/// A single evaluation must never be able to hold the service open.
const MAX_REQUESTS_PER_CALL: usize = 500;

#[derive(Debug, Deserialize)]
struct EvaluateRequest {
    expression: String,
    #[serde(default)]
    requests: Vec<CapturedRequest>,
}

#[derive(Debug, Deserialize)]
struct CapturedRequest {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default)]
    fields: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct EvaluateResponse {
    expression_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_error: Option<String>,
    scheme_version: &'static str,
    engine_version: &'static str,
    fidelity_note: &'static str,
    results: Vec<EvaluateResult>,
}

#[derive(Debug, Serialize)]
struct EvaluateResult {
    #[serde(rename = "ref")]
    reference: String,
    matched: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    caveats: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    engine_version: &'static str,
    scheme_version: &'static str,
    supported_fields: usize,
}

/// The fidelity limit, stated on every response rather than buried in docs.
const FIDELITY_NOTE: &str =
    "Evaluates a Cloudflare rule expression against captured request fields. This is not \
     Cloudflare's full product evaluation: managed rulesets, rule execution order and skip \
     rules are not reproduced, and a predicate over a field absent from the capture is \
     reported as a caveat rather than a match or a non-match.";

struct AppState {
    scheme: Scheme,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Arc::new(AppState {
        scheme: scheme::build(),
    });

    let app = Router::new()
        .route("/evaluate", post(evaluate))
        .route("/health", get(health))
        .with_state(state);

    let addr: SocketAddr = std::env::var("WIREFILTER_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_string())
        .parse()
        .expect("invalid WIREFILTER_ADDR");

    tracing::info!(%addr, "wirefilter sidecar listening");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = &state.scheme;
    Json(HealthResponse {
        status: "ok",
        engine_version: ENGINE_VERSION,
        scheme_version: scheme::SCHEME_VERSION,
        supported_fields: scheme::supported_fields().len(),
    })
}

async fn evaluate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvaluateRequest>,
) -> impl IntoResponse {
    if req.requests.len() > MAX_REQUESTS_PER_CALL {
        return (
            StatusCode::BAD_REQUEST,
            Json(EvaluateResponse {
                expression_valid: false,
                parse_error: Some(format!(
                    "batch of {} exceeds the limit of {}",
                    req.requests.len(),
                    MAX_REQUESTS_PER_CALL
                )),
                scheme_version: scheme::SCHEME_VERSION,
                engine_version: ENGINE_VERSION,
                fidelity_note: FIDELITY_NOTE,
                results: vec![],
            }),
        );
    }

    // A parse failure is reported as data, not as a transport error: the caller
    // asked a well-formed question about a malformed expression, and the answer
    // is "that expression does not parse", which the UI shows to the operator.
    let ast = match state.scheme.parse(&req.expression) {
        Ok(ast) => ast,
        Err(err) => {
            return (
                StatusCode::OK,
                Json(EvaluateResponse {
                    expression_valid: false,
                    parse_error: Some(err.to_string()),
                    scheme_version: scheme::SCHEME_VERSION,
                    engine_version: ENGINE_VERSION,
                    fidelity_note: FIDELITY_NOTE,
                    results: vec![],
                }),
            );
        }
    };

    let filter = ast.compile();
    let mut results = Vec::with_capacity(req.requests.len());

    for captured in &req.requests {
        let mut ctx = ExecutionContext::new(&state.scheme);
        let mut caveats = Vec::new();

        for (name, value) in &captured.fields {
            if !scheme::is_supported(name) {
                caveats.push(format!(
                    "field {name} is not in this scheme and was ignored"
                ));
                continue;
            }
            if let Err(err) = set_field(&mut ctx, name, value) {
                caveats.push(err);
            }
        }

        // Any supported field the expression references but the capture lacks
        // must be given a placeholder BEFORE execution: wirefilter panics on a
        // registered-but-unset field rather than returning an error.
        //
        // The placeholder is empty rather than absent, and the caveat says so.
        // Reporting "no match" without stating that the input was incomplete
        // would let an operator read uncertainty as safety, which is the single
        // most dangerous thing this service could do.
        for field in scheme::supported_fields() {
            if !references_field(&req.expression, field) || captured.fields.contains_key(field) {
                continue;
            }
            set_placeholder(&mut ctx, field);
            caveats.push(format!(
                "expression references {field}, which the capture does not contain; \
                 it was evaluated as empty, so this result may differ from production"
            ));
        }

        let matched = filter.execute(&ctx).unwrap_or(false);
        results.push(EvaluateResult {
            reference: captured.reference.clone(),
            matched,
            caveats,
        });
    }

    (
        StatusCode::OK,
        Json(EvaluateResponse {
            expression_valid: true,
            parse_error: None,
            scheme_version: scheme::SCHEME_VERSION,
            engine_version: ENGINE_VERSION,
            fidelity_note: FIDELITY_NOTE,
            results,
        }),
    )
}

/// Gives a referenced-but-absent field a type-appropriate empty value.
///
/// Necessary because wirefilter panics on a registered-but-unset field. The
/// values chosen are the natural "nothing here" for each type, matching how a
/// missing field behaves in most rule languages.
fn set_placeholder<'a>(ctx: &mut ExecutionContext<'a>, field: &str) {
    use scheme::FieldType;
    let _ = match scheme::field_type(field) {
        Some(FieldType::Bytes) => ctx.set_field_value(field, ""),
        Some(FieldType::Int) => ctx.set_field_value(field, 0i32),
        Some(FieldType::Bool) => ctx.set_field_value(field, false),
        Some(FieldType::Ip) => {
            ctx.set_field_value(field, std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        }
        None => return,
    };
}

/// Reports whether an expression references a field as a whole token.
///
/// A plain substring test is wrong here and produces confusing false caveats:
/// `http.request.uri` is a substring of `http.request.uri.path`, so an expression
/// using only the path would be reported as referencing the full URI too. Field
/// names are dot-separated identifiers, so the character immediately after a
/// match must not continue the identifier.
fn references_field(expression: &str, field: &str) -> bool {
    let mut from = 0;
    while let Some(idx) = expression[from..].find(field) {
        let start = from + idx;
        let end = start + field.len();

        let before_ok = start == 0
            || !expression[..start]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric() || c == '_' || c == '.')
                .unwrap_or(false);
        let after_ok = expression[end..]
            .chars()
            .next()
            .map(|c| !(c.is_alphanumeric() || c == '_' || c == '.'))
            .unwrap_or(true);

        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Sets one field on the execution context, converting from JSON.
///
/// The lifetime is explicit because the execution context borrows string values
/// rather than copying them: the captured request must outlive the context, which
/// it does since both live within one request handler.
fn set_field<'a>(
    ctx: &mut ExecutionContext<'a>,
    name: &str,
    value: &'a serde_json::Value,
) -> Result<(), String> {
    let result = match value {
        serde_json::Value::String(s) => {
            if name == "ip.src" {
                match s.parse::<std::net::IpAddr>() {
                    Ok(ip) => ctx.set_field_value(name, ip),
                    Err(_) => return Err(format!("field {name}: {s:?} is not a valid IP address")),
                }
            } else {
                ctx.set_field_value(name, s.as_str())
            }
        }
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => ctx.set_field_value(name, i as i32),
            None => return Err(format!("field {name}: number is not an integer")),
        },
        serde_json::Value::Bool(b) => ctx.set_field_value(name, *b),
        serde_json::Value::Null => {
            return Err(format!(
                "field {name} is null in the capture and was not set"
            ))
        }
        other => return Err(format!("field {name}: unsupported value type {other:?}")),
    };
    result.map_err(|e| format!("field {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_reference_respects_token_boundaries() {
        // The bug this guards: a substring match reports the full URI as
        // referenced when only the path is used, producing a caveat that tells
        // the operator their capture is incomplete when it is not.
        assert!(references_field(
            "http.request.uri.path contains \"/admin\"",
            "http.request.uri.path"
        ));
        assert!(!references_field(
            "http.request.uri.path contains \"/admin\"",
            "http.request.uri"
        ));

        assert!(references_field(
            "http.request.uri eq \"/x\"",
            "http.request.uri"
        ));
        assert!(references_field("ip.src in {1.2.3.0/24}", "ip.src"));
        assert!(!references_field("http.host eq \"a\"", "ip.src"));
    }

    #[test]
    fn scheme_parses_representative_expressions() {
        let scheme = scheme::build();
        for expr in [
            "http.request.uri.path contains \"/admin\"",
            "ip.src in {203.0.113.0/24}",
            "cf.threat_score > 10",
            "http.user_agent contains \"curl\" and ssl",
            "cf.bot_management.score < 30",
        ] {
            assert!(
                scheme.parse(expr).is_ok(),
                "expression should parse: {expr}"
            );
        }
    }

    #[test]
    fn unknown_field_is_a_parse_error_not_a_silent_false() {
        // An unsupported field must fail loudly. Silently evaluating it as false
        // would give a confident wrong verdict in a security tool.
        let scheme = scheme::build();
        assert!(scheme.parse("http.request.made_up_field eq \"x\"").is_err());
    }
}
