//! The Cloudflare field scheme.
//!
//! wirefilter itself defines NO fields — the scheme is entirely embedder-defined
//! (research.md R1). Cloudflare's field catalogue is a product-layer construct
//! that is not in the open-source repository, so this file is our independent
//! reconstruction of it from the public field reference, and it is versioned so
//! a stored evaluation result stays interpretable after the scheme grows.

use wirefilter::{Scheme, Type};

/// Version of this scheme, recorded on every evaluation run.
pub const SCHEME_VERSION: &str = "cf-scheme-v1";

/// Builds the scheme of Cloudflare rule-language fields this service supports.
///
/// The set is deliberately a documented SUBSET rather than an approximation of
/// everything Cloudflare offers. A field we do not declare produces an honest
/// parse error the caller can act on; a field we declare but populate wrongly
/// would produce a confident wrong verdict, which is far worse in a security
/// tool.
pub fn build() -> Scheme {
    Scheme! {
        // Request identity and shape
        http.host: Bytes,
        http.request.method: Bytes,
        http.request.uri: Bytes,
        http.request.uri.path: Bytes,
        http.request.uri.query: Bytes,
        http.request.full_uri: Bytes,
        http.request.version: Bytes,
        http.user_agent: Bytes,
        http.referer: Bytes,
        http.cookie: Bytes,
        http.request.body.raw: Bytes,

        // Client identity
        ip.src: Ip,
        ip.geoip.country: Bytes,
        ip.geoip.asnum: Int,
        ip.geoip.continent: Bytes,

        // Cloudflare-computed signals
        cf.threat_score: Int,
        cf.bot_management.score: Int,
        cf.bot_management.verified_bot: Bool,
        cf.client.bot: Bool,
        cf.edge.server_port: Int,

        // TLS
        ssl: Bool,
    }
}

/// Field names this scheme supports, used to tell a caller which of the fields
/// their expression references we cannot evaluate.
pub fn supported_fields() -> Vec<&'static str> {
    vec![
        "http.host",
        "http.request.method",
        "http.request.uri",
        "http.request.uri.path",
        "http.request.uri.query",
        "http.request.full_uri",
        "http.request.version",
        "http.user_agent",
        "http.referer",
        "http.cookie",
        "http.request.body.raw",
        "ip.src",
        "ip.geoip.country",
        "ip.geoip.asnum",
        "ip.geoip.continent",
        "cf.threat_score",
        "cf.bot_management.score",
        "cf.bot_management.verified_bot",
        "cf.client.bot",
        "cf.edge.server_port",
        "ssl",
    ]
}

/// The declared type of a supported field.
///
/// This exists because wirefilter PANICS if an expression references a field that
/// was registered but never given a value — it does not return an error. So any
/// referenced field missing from a capture must be given a type-appropriate
/// placeholder before execution, and the caller told that it was.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Bytes,
    Int,
    Ip,
    Bool,
}

/// Returns a field's type, if it is supported.
pub fn field_type(field: &str) -> Option<FieldType> {
    Some(match field {
        "http.host"
        | "http.request.method"
        | "http.request.uri"
        | "http.request.uri.path"
        | "http.request.uri.query"
        | "http.request.full_uri"
        | "http.request.version"
        | "http.user_agent"
        | "http.referer"
        | "http.cookie"
        | "http.request.body.raw"
        | "ip.geoip.country"
        | "ip.geoip.continent" => FieldType::Bytes,
        "ip.geoip.asnum"
        | "cf.threat_score"
        | "cf.bot_management.score"
        | "cf.edge.server_port" => FieldType::Int,
        "ip.src" => FieldType::Ip,
        "cf.bot_management.verified_bot" | "cf.client.bot" | "ssl" => FieldType::Bool,
        _ => return None,
    })
}

/// Fields whose absence from a capture changes what an expression can decide.
///
/// A predicate over an unset field must produce a CAVEAT, never a silent false —
/// that distinction is what stops an operator reading "no match" as "safe" when
/// the truth is "we could not tell" (contracts/wirefilter-sidecar.md).
pub fn is_supported(field: &str) -> bool {
    supported_fields().contains(&field)
}

#[allow(unused_imports)]
use wirefilter::Scheme as _SchemeAlias;
#[allow(unused)]
fn _type_check(_t: Type) {}
