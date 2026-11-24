//! `FetchDirectory`: the production `Directory`. It reads a WebID profile for
//! its `solid:oidcIssuer` values and an issuer's OpenID configuration for its
//! JWKS, over HTTPS with `worker::Fetch`, and caches both in memory for 600 s.

use std::cell::RefCell;
use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use crate::auth::{AuthError, Directory};
use crate::jwk::Jwk;

pub const CACHE_TTL_S: i64 = 600;
const SOLID_NS: &str = "http://www.w3.org/ns/solid/terms#";
const MAX_DOC_BYTES: usize = 512 * 1024;
/// Bound on cached entries per map, so unauthenticated input cannot grow memory without limit.
const MAX_CACHE_ENTRIES: usize = 1024;

#[derive(Default)]
pub struct FetchDirectory {
    issuers: RefCell<HashMap<String, (i64, Vec<String>)>>,
    jwks: RefCell<HashMap<String, (i64, Vec<Jwk>)>>,
}

impl FetchDirectory {
    pub fn new() -> Self {
        Self::default()
    }
}

fn now_s() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

fn store<T>(map: &RefCell<HashMap<String, (i64, T)>>, key: &str, v: T, now: i64) {
    let mut m = map.borrow_mut();
    if m.len() >= MAX_CACHE_ENTRIES {
        m.retain(|_, (expires, _)| *expires > now);
        if m.len() >= MAX_CACHE_ENTRIES {
            m.clear();
        }
    }
    m.insert(key.to_string(), (now + CACHE_TTL_S, v));
}

fn cached<T: Clone>(map: &RefCell<HashMap<String, (i64, T)>>, key: &str, now: i64) -> Option<T> {
    match map.borrow().get(key) {
        Some((expires, v)) if *expires > now => Some(v.clone()),
        _ => None,
    }
}

fn fetch_err(what: &str) -> impl Fn(worker::Error) -> AuthError + '_ {
    move |_| AuthError::Fetch(format!("{what} fetch failed"))
}

async fn get(url: &str, accept: &str, what: &str) -> Result<String, AuthError> {
    let headers = Headers::new();
    headers.set("Accept", accept).map_err(fetch_err(what))?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let req = Request::new_with_init(url, &init).map_err(fetch_err(what))?;
    let mut resp = Fetch::Request(req).send().await.map_err(fetch_err(what))?;
    let status = resp.status_code();
    if !(200..300).contains(&status) {
        return Err(AuthError::Fetch(format!("{what} fetch status {status}")));
    }
    let body = resp.text().await.map_err(fetch_err(what))?;
    if body.len() > MAX_DOC_BYTES {
        return Err(AuthError::Fetch(format!("{what} too large")));
    }
    Ok(body)
}

fn is_https(url: &str) -> bool {
    url.starts_with("https://")
}

fn trim_slash(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

#[async_trait(?Send)]
impl Directory for FetchDirectory {
    async fn profile_issuers(&self, webid: &str) -> Result<Vec<String>, AuthError> {
        if !is_https(webid) {
            return Err(AuthError::Malformed);
        }
        let now = now_s();
        if let Some(v) = cached(&self.issuers, webid, now) {
            return Ok(v);
        }
        let doc_url = webid.split('#').next().unwrap_or(webid);
        let ttl = get(doc_url, "text/turtle", "profile").await?;
        let issuers = oidc_issuers(&ttl);
        store(&self.issuers, webid, issuers.clone(), now);
        Ok(issuers)
    }

    async fn jwks(&self, issuer: &str) -> Result<Vec<Jwk>, AuthError> {
        if !is_https(issuer) {
            return Err(AuthError::IssuerNotTrusted);
        }
        let issuer = trim_slash(issuer);
        let now = now_s();
        if let Some(v) = cached(&self.jwks, issuer, now) {
            return Ok(v);
        }
        let conf = get(
            &format!("{issuer}/.well-known/openid-configuration"),
            "application/json",
            "openid configuration",
        )
        .await?;
        let conf: Value = serde_json::from_str(&conf)
            .map_err(|_| AuthError::Fetch("openid configuration not json".into()))?;
        // The configuration must describe this issuer, or it is not this issuer's.
        match conf.get("issuer").and_then(Value::as_str) {
            Some(i) if trim_slash(i) == issuer => {}
            _ => {
                return Err(AuthError::Fetch(
                    "openid configuration issuer mismatch".into(),
                ))
            }
        }
        let jwks_uri = conf
            .get("jwks_uri")
            .and_then(Value::as_str)
            .filter(|u| is_https(u))
            .ok_or_else(|| AuthError::Fetch("no https jwks_uri".into()))?;
        let doc = get(jwks_uri, "application/json", "jwks").await?;
        let keys = parse_jwks(&doc)?;
        store(&self.jwks, issuer, keys.clone(), now);
        Ok(keys)
    }
}

/// Keys from a JWKS document. Entries that are not objects are skipped.
pub fn parse_jwks(doc: &str) -> Result<Vec<Jwk>, AuthError> {
    let v: Value =
        serde_json::from_str(doc).map_err(|_| AuthError::Fetch("jwks not json".into()))?;
    let keys = v
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| AuthError::Fetch("jwks has no keys".into()))?;
    Ok(keys.iter().filter_map(Jwk::from_value).collect())
}

/// Every `solid:oidcIssuer` object in a Turtle document, found with a small
/// scan for that one predicate, not a full Turtle parser. It recognises the
/// full IRI form and any prefix bound to the Solid terms namespace, follows
/// comma separated object lists, and keeps only absolute https IRIs.
pub fn oidc_issuers(ttl: &str) -> Vec<String> {
    let mut predicates = vec![format!("<{SOLID_NS}oidcIssuer>")];
    for prefix in solid_prefixes(ttl) {
        predicates.push(format!("{prefix}:oidcIssuer"));
    }
    let mut out: Vec<String> = Vec::new();
    for pred in &predicates {
        let mut from = 0;
        while let Some(pos) = ttl[from..].find(pred.as_str()) {
            let start = from + pos;
            let end = start + pred.len();
            from = end;
            let before_ok = ttl[..start]
                .chars()
                .next_back()
                .is_none_or(|c| c.is_whitespace() || c == ';' || c == '[');
            let after_ok = ttl[end..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace() || c == '<');
            if !before_ok || !after_ok {
                continue;
            }
            let mut rest = &ttl[end..];
            loop {
                rest = rest.trim_start();
                let Some(r) = rest.strip_prefix('<') else {
                    break;
                };
                let Some(close) = r.find('>') else { break };
                let iri = &r[..close];
                if is_https(iri)
                    && !iri.contains(char::is_whitespace)
                    && !out.iter().any(|o| o == iri)
                {
                    out.push(iri.to_string());
                }
                rest = r[close + 1..].trim_start();
                match rest.strip_prefix(',') {
                    Some(r) => rest = r,
                    None => break,
                }
            }
        }
    }
    out
}

/// Prefix names bound to the Solid terms namespace by `@prefix` or `PREFIX`.
fn solid_prefixes(ttl: &str) -> Vec<String> {
    let mut out = Vec::new();
    let target = format!("<{SOLID_NS}>");
    for line in ttl.lines() {
        let l = line.trim_start();
        let rest = if let Some(r) = l.strip_prefix("@prefix") {
            r
        } else if l.len() >= 6 && l[..6].eq_ignore_ascii_case("prefix") {
            &l[6..]
        } else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(colon) = rest.find(':') else {
            continue;
        };
        let name = &rest[..colon];
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            continue;
        }
        if rest[colon + 1..].trim_start().starts_with(&target) {
            out.push(name.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_issuers_with_solid_prefix_and_lists() {
        let ttl = r#"
@prefix solid: <http://www.w3.org/ns/solid/terms#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
<#me> a foaf:Person;
    solid:oidcIssuer <https://issuer.example/>, <https://second.example>;
    foaf:name "Alice".
"#;
        assert_eq!(
            oidc_issuers(ttl),
            vec!["https://issuer.example/", "https://second.example"]
        );
    }

    #[test]
    fn finds_issuers_with_full_iri_and_other_prefix() {
        let ttl = "PREFIX s: <http://www.w3.org/ns/solid/terms#>\n<#me> s:oidcIssuer <https://a.example>.\n<#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <https://b.example>.";
        let mut got = oidc_issuers(ttl);
        got.sort();
        assert_eq!(got, vec!["https://a.example", "https://b.example"]);
    }

    #[test]
    fn ignores_lookalike_predicates_and_non_https() {
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n<#me> notsolid:oidcIssuer <https://evil.example>; solid:oidcIssuerX <https://evil2.example>; solid:oidcIssuer <http://plain.example>.";
        assert!(oidc_issuers(ttl).is_empty());
    }

    #[test]
    fn parses_jwks_and_skips_junk() {
        let keys = parse_jwks(
            r#"{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB"}, 7, {"kty":"EC"}]}"#,
        )
        .unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kid.as_deref(), Some("k1"));
        assert!(parse_jwks("nope").is_err());
    }
}
