//! `FetchDirectory`: the production `Directory`. It reads a WebID profile for
//! its `solid:oidcIssuer` values and an issuer's OpenID configuration for its
//! JWKS, over HTTPS with `worker::Fetch`, and caches both in memory for 600 s.

use std::cell::RefCell;
use std::collections::HashMap;

use async_trait::async_trait;
use oxrdf::{NamedOrBlankNode, Term};
use oxttl::TurtleParser;
use serde_json::Value;
use worker::{Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

use crate::auth::{AuthError, Directory};
use crate::jwk::Jwk;

pub const CACHE_TTL_S: i64 = 600;
const OIDC_ISSUER: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";
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

/// Per fetch deadline, covering the request and the whole body read.
pub const FETCH_TIMEOUT_MS: u64 = 5_000;

/// True unless a `Content-Length` header announces more than `limit` bytes.
/// A missing header passes here (the streaming read still caps the body); an
/// unparsable one, including one too big for u64, is refused.
pub fn content_length_ok(header: Option<&str>, limit: usize) -> bool {
    match header.map(|h| h.trim().parse::<u64>()) {
        None => true,
        Some(Ok(n)) => n <= limit as u64,
        Some(Err(_)) => false,
    }
}

/// Read a byte stream into memory, stopping with an error as soon as it would
/// exceed `limit` bytes. A stream error is an error too.
pub async fn read_limited<S, E>(mut stream: S, limit: usize) -> Result<Vec<u8>, ()>
where
    S: futures_util::Stream<Item = Result<Vec<u8>, E>> + Unpin,
{
    use futures_util::StreamExt;
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ())?;
        if buf.len() + chunk.len() > limit {
            return Err(());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Run `fut` unless `timer` finishes first, in which case return None.
pub async fn race<F, T>(fut: F, timer: T) -> Option<F::Output>
where
    F: std::future::Future,
    T: std::future::Future,
{
    use futures_util::future::{select, Either};
    match select(std::pin::pin!(fut), std::pin::pin!(timer)).await {
        Either::Left((out, _)) => Some(out),
        Either::Right(_) => None,
    }
}

/// The one fetch helper for the WebID, discovery and JWKS documents: GET over
/// https, redirects not followed (manual mode, so any 3xx then fails the
/// status check; a redirect could leave https or the expected host), a 5 s
/// deadline that also aborts the subrequest, and a body cap of
/// `MAX_DOC_BYTES` checked against `Content-Length` and again while streaming.
async fn get(url: &str, accept: &str, what: &str) -> Result<String, AuthError> {
    if !is_https(url) {
        return Err(AuthError::Fetch(format!("{what} not https")));
    }
    let controller = worker::AbortController::default();
    let signal = controller.signal();
    let work = async {
        let headers = Headers::new();
        headers.set("Accept", accept).map_err(fetch_err(what))?;
        let mut init = RequestInit::new();
        init.with_method(Method::Get)
            .with_headers(headers)
            .with_redirect(RequestRedirect::Manual);
        let req = Request::new_with_init(url, &init).map_err(fetch_err(what))?;
        let mut resp = Fetch::Request(req)
            .send_with_signal(&signal)
            .await
            .map_err(fetch_err(what))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            return Err(AuthError::Fetch(format!("{what} fetch status {status}")));
        }
        let len = resp.headers().get("Content-Length").ok().flatten();
        if !content_length_ok(len.as_deref(), MAX_DOC_BYTES) {
            return Err(AuthError::Fetch(format!("{what} too large")));
        }
        let stream = resp.stream().map_err(fetch_err(what))?;
        let body = read_limited(stream, MAX_DOC_BYTES)
            .await
            .map_err(|_| AuthError::Fetch(format!("{what} too large or unreadable")))?;
        String::from_utf8(body).map_err(|_| AuthError::Fetch(format!("{what} not utf-8")))
    };
    let timer = worker::Delay::from(std::time::Duration::from_millis(FETCH_TIMEOUT_MS));
    match race(work, timer).await {
        Some(Ok(body)) => Ok(body),
        Some(Err(e)) => {
            // Close the subrequest now rather than leaving an unread body open.
            controller.abort();
            Err(e)
        }
        None => {
            controller.abort();
            Err(AuthError::Fetch(format!("{what} timed out")))
        }
    }
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
        let issuers = oidc_issuers(&ttl, doc_url, webid);
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

/// The `solid:oidcIssuer` objects whose subject is exactly `webid`, from the
/// Turtle profile document fetched at `doc_url`.
///
/// The document is parsed with a real Turtle parser (`oxttl`), so text inside
/// string literals and comments is never read as a triple, and relative IRIs
/// are resolved against `doc_url`. The subject must equal the WebID,
/// fragment included, so a triple about another subject in the same document
/// adds nothing. Only absolute https IRI objects count. Any syntax error
/// yields no issuers at all (the auth is then refused) rather than a guess.
pub fn oidc_issuers(ttl: &str, doc_url: &str, webid: &str) -> Vec<String> {
    let Ok(parser) = TurtleParser::new().with_base_iri(doc_url) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for triple in parser.for_slice(ttl.as_bytes()) {
        let Ok(t) = triple else {
            return Vec::new();
        };
        if t.predicate.as_str() != OIDC_ISSUER {
            continue;
        }
        let NamedOrBlankNode::NamedNode(subject) = &t.subject else {
            continue;
        };
        if subject.as_str() != webid {
            continue;
        }
        let Term::NamedNode(iri) = &t.object else {
            continue;
        };
        let iri = iri.as_str();
        if is_https(iri) && !out.iter().any(|o| o == iri) {
            out.push(iri.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "https://pod.example/alice/profile/card";
    const WEBID: &str = "https://pod.example/alice/profile/card#me";

    fn issuers(ttl: &str) -> Vec<String> {
        oidc_issuers(ttl, DOC, WEBID)
    }

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
            issuers(ttl),
            vec!["https://issuer.example/", "https://second.example"]
        );
    }

    #[test]
    fn finds_issuers_with_full_iri_and_other_prefix() {
        let ttl = "PREFIX s: <http://www.w3.org/ns/solid/terms#>\n<#me> s:oidcIssuer <https://a.example>.\n<#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <https://b.example>.";
        let mut got = issuers(ttl);
        got.sort();
        assert_eq!(got, vec!["https://a.example", "https://b.example"]);
    }

    #[test]
    fn ignores_lookalike_predicates_and_non_https() {
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n@prefix notsolid: <http://example.org/solid#>.\n<#me> notsolid:oidcIssuer <https://evil.example>; solid:oidcIssuerX <https://evil2.example>; solid:oidcIssuer <http://plain.example>.";
        assert!(issuers(ttl).is_empty());
    }

    #[test]
    fn ignores_issuer_inside_string_literals() {
        let ttl = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
<#me> solid:oidcIssuer <https://issuer.example>;
    foaf:name "x\". <#me> solid:oidcIssuer <https://evil.example>. #";
    foaf:nick 'solid:oidcIssuer <https://evil2.example>';
    foaf:note """
<#me> solid:oidcIssuer <https://evil3.example> .
""", '''<#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <https://evil4.example>.'''.
"#;
        assert_eq!(issuers(ttl), vec!["https://issuer.example"]);
    }

    #[test]
    fn ignores_issuer_inside_comments() {
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n# <#me> solid:oidcIssuer <https://evil.example>.\n<#me> solid:oidcIssuer <https://issuer.example> # ; solid:oidcIssuer <https://evil2.example>\n.";
        assert_eq!(issuers(ttl), vec!["https://issuer.example"]);
    }

    #[test]
    fn ignores_issuer_under_another_subject() {
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n\
            <#me> solid:oidcIssuer <https://issuer.example>.\n\
            <#mallory> solid:oidcIssuer <https://evil.example>.\n\
            <> solid:oidcIssuer <https://evil2.example>.\n\
            <https://other.example/card#me> solid:oidcIssuer <https://evil3.example>.\n\
            [] solid:oidcIssuer <https://evil4.example>.\n\
            <#me> <http://xmlns.com/foaf/0.1/knows> [ solid:oidcIssuer <https://evil5.example> ].";
        assert_eq!(issuers(ttl), vec!["https://issuer.example"]);
        // The same document read for another WebID gives that WebID's issuer.
        assert_eq!(
            oidc_issuers(ttl, DOC, &format!("{DOC}#mallory")),
            vec!["https://evil.example"]
        );
    }

    #[test]
    fn resolves_relative_subject_against_document_url() {
        // `<card#me>` relative to the profile container resolves to the WebID.
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n<card#me> solid:oidcIssuer <https://issuer.example>.";
        assert_eq!(issuers(ttl), vec!["https://issuer.example"]);
        // Against a different document it is a different subject.
        assert!(oidc_issuers(ttl, "https://pod.example/bob/profile/card", WEBID).is_empty());
    }

    #[test]
    fn pods_dev_style_profile_with_ns1_prefix() {
        let ttl = r#"@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix schema: <http://schema.org/> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .
@prefix ns0: <http://www.w3.org/ns/pim/space#> .
@prefix ns1: <http://www.w3.org/ns/solid/terms#> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .

<https://pod.example/alice/profile/card>
  a foaf:PersonalProfileDocument ;
  foaf:maker <https://pod.example/alice/profile/card#me> ;
  foaf:primaryTopic <https://pod.example/alice/profile/card#me> .

<https://pod.example/alice/profile/card#me>
  a schema:Person, foaf:Person ;
  ldp:inbox <https://pod.example/alice/storage/inbox/> ;
  ns0:storage <https://pod.example/alice/storage/> ;
  ns1:account <https://pod.example/alice/storage/> ;
  ns1:oidcIssuer <https://pod.example> ;
  foaf:name "Alice (demo)" ;
  vcard:fn "Alice (demo)" .
"#;
        assert_eq!(issuers(ttl), vec!["https://pod.example"]);
    }

    #[test]
    fn syntax_error_gives_no_issuers() {
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n<#me> solid:oidcIssuer <https://issuer.example>.\nthis is not turtle\n";
        assert!(issuers(ttl).is_empty());
        assert!(oidc_issuers(ttl, "not a url", WEBID).is_empty());
    }

    #[test]
    fn non_ascii_does_not_panic() {
        let ttl = "@prefix solid: <http://www.w3.org/ns/solid/terms#>.\n# abcdeé x \u{1F600}\n\
                   <#me> <http://xmlns.com/foaf/0.1/name> \"é\u{1F600}\"; solid:oidcIssuer <https://issuer.example>, <https://é.example>.";
        assert_eq!(
            issuers(ttl),
            vec!["https://issuer.example", "https://é.example"]
        );
        for cut in 0..ttl.len() {
            if let Some(part) = ttl.get(..cut) {
                let _ = issuers(part);
            }
        }
        // Junk text must not panic either.
        let _ = issuers("<<<\"\"\"'''@prefix : <#> . :a :b [ :c ( :d \"");
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

    #[test]
    fn content_length_guard() {
        assert!(content_length_ok(None, 10));
        assert!(content_length_ok(Some("10"), 10));
        assert!(content_length_ok(Some(" 0 "), 10));
        assert!(!content_length_ok(Some("11"), 10));
        assert!(!content_length_ok(Some("99999999999999999999"), 10));
        assert!(!content_length_ok(Some("abc"), 10));
        assert!(!content_length_ok(Some("-1"), 10));
    }

    #[test]
    fn read_limited_stops_at_the_cap() {
        use futures::executor::block_on;
        use futures::stream;
        let ok = stream::iter(vec![Ok::<_, ()>(vec![1u8; 4]), Ok(vec![2u8; 6])]);
        assert_eq!(block_on(read_limited(ok, 10)).unwrap().len(), 10);
        let over = stream::iter(vec![Ok::<_, ()>(vec![1u8; 4]), Ok(vec![2u8; 7])]);
        assert!(block_on(read_limited(over, 10)).is_err());
        let failing = stream::iter(vec![Ok(vec![1u8; 2]), Err(())]);
        assert!(block_on(read_limited(failing, 10)).is_err());
        // The stream is not polled past the chunk that crosses the cap.
        let endless = stream::repeat(Ok::<_, ()>(vec![0u8; 1024]));
        assert!(block_on(read_limited(endless, 4096)).is_err());
    }

    #[test]
    fn race_returns_none_when_timer_wins() {
        use futures::executor::block_on;
        use futures::future::{pending, ready};
        assert_eq!(block_on(race(ready(7), pending::<()>())), Some(7));
        assert_eq!(block_on(race(pending::<i32>(), ready(()))), None);
    }
}
