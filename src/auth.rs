//! Identity verification for the relay.
//!
//! The relay never trusts a claimed WebID. A client proves who it is with a
//! Solid-OIDC DPoP-bound access token plus a fresh DPoP proof made for the
//! relay URL. `verify` checks both and returns the WebID only when every check
//! passes.

use async_trait::async_trait;
use serde_json::Value;

use crate::jwk::{b64url_decode, sha256_b64url, Alg, Jwk};

/// Maximum distance in seconds between a proof's `iat` and the relay clock.
pub const PROOF_WINDOW_S: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub webid: String,
    pub issuer: String,
    pub jti: String,
    pub exp: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Malformed,
    BadSignature,
    Expired,
    ProofMismatch,
    ProofStale,
    IssuerNotTrusted,
    Fetch(String),
}

/// Where the relay learns which issuers a WebID trusts and which keys an
/// issuer signs with.
#[async_trait(?Send)]
pub trait Directory {
    /// Every `solid:oidcIssuer` listed in the WebID profile document.
    async fn profile_issuers(&self, webid: &str) -> Result<Vec<String>, AuthError>;
    /// The issuer's published signing keys.
    async fn jwks(&self, issuer: &str) -> Result<Vec<Jwk>, AuthError>;
}

/// A compact JWS split into its parts. Nothing in it is trusted until its
/// signature has been checked.
struct Jws {
    header: Value,
    claims: Value,
    signing_input: String,
    signature: Vec<u8>,
}

impl Jws {
    fn parse(jwt: &str) -> Result<Jws, AuthError> {
        let mut parts = jwt.split('.');
        let (Some(h), Some(c), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AuthError::Malformed);
        };
        let header: Value = decode_json(h)?;
        let claims: Value = decode_json(c)?;
        if !header.is_object() || !claims.is_object() {
            return Err(AuthError::Malformed);
        }
        let signature = b64url_decode(s).ok_or(AuthError::Malformed)?;
        Ok(Jws {
            header,
            claims,
            signing_input: format!("{h}.{c}"),
            signature,
        })
    }

    /// The header `alg`, refused unless it is RS256 or ES256.
    fn alg(&self) -> Result<Alg, AuthError> {
        let alg = self
            .header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(AuthError::Malformed)?;
        Alg::parse(alg).ok_or(AuthError::BadSignature)
    }

    fn verify_with(&self, alg: Alg, key: &Jwk) -> bool {
        key.verify(alg, self.signing_input.as_bytes(), &self.signature)
    }
}

fn decode_json(part: &str) -> Result<Value, AuthError> {
    let bytes = b64url_decode(part).ok_or(AuthError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| AuthError::Malformed)
}

fn str_claim<'a>(v: &'a Value, name: &str) -> Result<&'a str, AuthError> {
    match v.get(name).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(AuthError::Malformed),
    }
}

fn int_claim(v: &Value, name: &str) -> Result<i64, AuthError> {
    v.get(name)
        .and_then(Value::as_i64)
        .ok_or(AuthError::Malformed)
}

/// Issuer comparison ignores one trailing slash on either side; nothing else.
fn same_issuer(a: &str, b: &str) -> bool {
    a.strip_suffix('/').unwrap_or(a) == b.strip_suffix('/').unwrap_or(b)
}

/// Verify a Solid-OIDC DPoP-bound access token and the DPoP proof that came
/// with it. `htu` is the relay URL the client dialled, built per the wire
/// contract; `now` is the relay clock in epoch seconds.
///
/// Order of checks: parse both JWTs; token alg; issuer listed in the WebID
/// profile; token signature against the issuer JWKS; token expiry; proof typ;
/// proof key bound by `cnf.jkt`; proof signature; `htm`, `htu`, `iat`, `ath`.
pub async fn verify(
    token: &str,
    proof: &str,
    htu: &str,
    now: i64,
    dir: &dyn Directory,
) -> Result<Verified, AuthError> {
    let tok = Jws::parse(token)?;
    let prf = Jws::parse(proof)?;

    // Token. The webid and iss read here are unverified until the signature
    // check below; they are only used to find out which keys to check against.
    let tok_alg = tok.alg()?;
    let webid = str_claim(&tok.claims, "webid")?;
    let iss = str_claim(&tok.claims, "iss")?;

    let issuers = dir.profile_issuers(webid).await?;
    if !issuers.iter().any(|i| same_issuer(i, iss)) {
        return Err(AuthError::IssuerNotTrusted);
    }

    let kid = tok.header.get("kid").and_then(Value::as_str);
    let keys = dir.jwks(iss).await?;
    let signed = keys
        .iter()
        .filter(|k| kid.is_none() || k.kid.as_deref() == kid)
        .any(|k| tok.verify_with(tok_alg, k));
    if !signed {
        return Err(AuthError::BadSignature);
    }

    // From here the token claims are trusted.
    let exp = int_claim(&tok.claims, "exp")?;
    if exp <= now {
        return Err(AuthError::Expired);
    }
    let jkt = tok
        .claims
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(Value::as_str)
        .ok_or(AuthError::Malformed)?;

    // Proof.
    if prf.header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Err(AuthError::ProofMismatch);
    }
    let prf_alg = prf.alg()?;
    let jwk_value = prf
        .header
        .get("jwk")
        .filter(|j| j.is_object())
        .ok_or(AuthError::Malformed)?;
    let jwk = Jwk::from_value(jwk_value).ok_or(AuthError::Malformed)?;
    if jwk.d.is_some() {
        return Err(AuthError::Malformed);
    }
    let thumb = jwk.thumbprint().ok_or(AuthError::Malformed)?;
    if thumb != jkt {
        return Err(AuthError::ProofMismatch);
    }
    if !prf.verify_with(prf_alg, &jwk) {
        return Err(AuthError::BadSignature);
    }

    // From here the proof claims are trusted.
    if str_claim(&prf.claims, "htm")? != "GET" {
        return Err(AuthError::ProofMismatch);
    }
    if str_claim(&prf.claims, "htu")? != htu {
        return Err(AuthError::ProofMismatch);
    }
    let iat = int_claim(&prf.claims, "iat")?;
    if (i128::from(now) - i128::from(iat)).abs() > i128::from(PROOF_WINDOW_S) {
        return Err(AuthError::ProofStale);
    }
    if str_claim(&prf.claims, "ath")? != sha256_b64url(token.as_bytes()) {
        return Err(AuthError::ProofMismatch);
    }
    let jti = str_claim(&prf.claims, "jti")?;

    Ok(Verified {
        webid: webid.to_string(),
        issuer: iss.to_string(),
        jti: jti.to_string(),
        exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::OnceLock;

    const WEBID: &str = "https://pod.example/alice/profile/card#me";
    const ISS: &str = "https://issuer.example";
    const ISS_B: &str = "https://other-issuer.example";
    const HTU: &str = "https://relay.example/v1/room/0123456789abcdef0123456789abcdef";
    const NOW: i64 = 1_800_000_000;

    enum Key {
        Rsa(rsa::pkcs1v15::SigningKey<sha2::Sha256>, Value),
        Ec(p256::ecdsa::SigningKey, Value),
    }

    impl Key {
        fn alg(&self) -> &'static str {
            match self {
                Key::Rsa(..) => "RS256",
                Key::Ec(..) => "ES256",
            }
        }
        fn public_jwk(&self) -> Value {
            match self {
                Key::Rsa(_, j) | Key::Ec(_, j) => j.clone(),
            }
        }
        fn jwk(&self) -> Jwk {
            Jwk::from_value(&self.public_jwk()).unwrap()
        }
        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            match self {
                Key::Rsa(k, _) => k.sign(msg).to_vec(),
                Key::Ec(k, _) => {
                    let s: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(k, msg);
                    s.to_bytes().to_vec()
                }
            }
        }
    }

    fn rsa_key(seed: u64, kid: &str) -> Key {
        let mut rng = rand::rngs::ChaCha8Rng::seed_from_u64(seed);
        let sk = rsa::PrivateKey::new(&mut rng, 2048).unwrap();
        let pk = sk.to_public_key();
        let jwk = json!({
            "kty": "RSA",
            "kid": kid,
            "n": crate::jwk::b64url_encode(&pk.n_bytes()),
            "e": crate::jwk::b64url_encode(&pk.e_bytes()),
        });
        Key::Rsa(rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(sk), jwk)
    }

    fn ec_key(seed: u8, kid: &str) -> Key {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        let b = point.as_bytes();
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": kid,
            "x": crate::jwk::b64url_encode(&b[1..33]),
            "y": crate::jwk::b64url_encode(&b[33..65]),
        });
        Key::Ec(sk, jwk)
    }

    struct Keys {
        issuer: Key,
        stranger: Key,
        dpop_rsa: Key,
        dpop_ec: Key,
        other_ec: Key,
    }

    fn keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(|| Keys {
            issuer: rsa_key(1, "issuer-key"),
            // Same kid as the issuer key, different key material.
            stranger: rsa_key(2, "issuer-key"),
            dpop_rsa: rsa_key(3, "dpop"),
            dpop_ec: ec_key(4, "dpop"),
            other_ec: ec_key(5, "dpop"),
        })
    }

    fn jwt(header: &Value, claims: &Value, key: &Key) -> String {
        let input = format!(
            "{}.{}",
            crate::jwk::b64url_encode(header.to_string().as_bytes()),
            crate::jwk::b64url_encode(claims.to_string().as_bytes())
        );
        let sig = key.sign(input.as_bytes());
        format!("{input}.{}", crate::jwk::b64url_encode(&sig))
    }

    fn thumb(key: &Key) -> String {
        key.jwk().thumbprint().unwrap()
    }

    fn token_claims(dpop: &Key) -> Value {
        json!({
            "webid": WEBID,
            "iss": ISS,
            "sub": "alice",
            "aud": "solid",
            "iat": NOW - 10,
            "exp": NOW + 300,
            "cnf": { "jkt": thumb(dpop) },
        })
    }

    fn token_with(claims: &Value) -> String {
        let k = &keys().issuer;
        jwt(
            &json!({"alg": "RS256", "typ": "at+jwt", "kid": "issuer-key"}),
            claims,
            k,
        )
    }

    fn proof_claims(token: &str) -> Value {
        json!({
            "htm": "GET",
            "htu": HTU,
            "iat": NOW,
            "jti": "proof-jti-1",
            "ath": sha256_b64url(token.as_bytes()),
        })
    }

    fn proof_with(claims: &Value, header_key: &Key, signing_key: &Key) -> String {
        let header =
            json!({"typ": "dpop+jwt", "alg": signing_key.alg(), "jwk": header_key.public_jwk()});
        jwt(&header, claims, signing_key)
    }

    struct FakeDirectory {
        issuers: HashMap<String, Vec<String>>,
        jwks: HashMap<String, Vec<Jwk>>,
    }

    impl FakeDirectory {
        fn new() -> Self {
            let mut issuers = HashMap::new();
            // Trailing slash on purpose: comparison ignores it.
            issuers.insert(WEBID.to_string(), vec![format!("{ISS}/")]);
            let mut jwks = HashMap::new();
            jwks.insert(ISS.to_string(), vec![keys().issuer.jwk()]);
            jwks.insert(ISS_B.to_string(), vec![keys().issuer.jwk()]);
            FakeDirectory { issuers, jwks }
        }
    }

    #[async_trait(?Send)]
    impl Directory for FakeDirectory {
        async fn profile_issuers(&self, webid: &str) -> Result<Vec<String>, AuthError> {
            self.issuers
                .get(webid)
                .cloned()
                .ok_or_else(|| AuthError::Fetch("no profile".into()))
        }
        async fn jwks(&self, issuer: &str) -> Result<Vec<Jwk>, AuthError> {
            let issuer = issuer.trim_end_matches('/');
            self.jwks
                .get(issuer)
                .cloned()
                .ok_or_else(|| AuthError::Fetch("no jwks".into()))
        }
    }

    fn run(token: &str, proof: &str) -> Result<Verified, AuthError> {
        futures::executor::block_on(verify(token, proof, HTU, NOW, &FakeDirectory::new()))
    }

    fn valid_pair(dpop: &Key) -> (String, String) {
        let token = token_with(&token_claims(dpop));
        let proof = proof_with(&proof_claims(&token), dpop, dpop);
        (token, proof)
    }

    fn assert_alice(r: Result<Verified, AuthError>) {
        let v = r.expect("verify should succeed");
        assert_eq!(v.webid, "https://pod.example/alice/profile/card#me");
        assert_eq!(v.issuer, "https://issuer.example");
        assert_eq!(v.jti, "proof-jti-1");
        assert_eq!(v.exp, NOW + 300);
    }

    #[test]
    fn accepts_valid_rs256_token_and_rs256_proof() {
        let (t, p) = valid_pair(&keys().dpop_rsa);
        assert_alice(run(&t, &p));
    }

    #[test]
    fn accepts_valid_rs256_token_and_es256_proof() {
        let (t, p) = valid_pair(&keys().dpop_ec);
        assert_alice(run(&t, &p));
    }

    #[test]
    fn rejects_expired_token() {
        let dpop = &keys().dpop_ec;
        let mut c = token_claims(dpop);
        c["exp"] = json!(NOW - 1);
        let t = token_with(&c);
        let p = proof_with(&proof_claims(&t), dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::Expired));
        // exp == now is expired too: the rule is exp > now.
        c["exp"] = json!(NOW);
        let t = token_with(&c);
        let p = proof_with(&proof_claims(&t), dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::Expired));
    }

    #[test]
    fn rejects_token_signed_by_unknown_key() {
        let dpop = &keys().dpop_ec;
        let header = json!({"alg": "RS256", "kid": "issuer-key"});
        let t = jwt(&header, &token_claims(dpop), &keys().stranger);
        let p = proof_with(&proof_claims(&t), dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::BadSignature));
        // An unknown kid is a bad signature as well.
        let header = json!({"alg": "RS256", "kid": "nobody"});
        let t = jwt(&header, &token_claims(dpop), &keys().issuer);
        let p = proof_with(&proof_claims(&t), dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::BadSignature));
    }

    #[test]
    fn rejects_alg_none_and_hs256() {
        let dpop = &keys().dpop_ec;
        let claims = token_claims(dpop).to_string();
        let enc = |v: &str| crate::jwk::b64url_encode(v.as_bytes());

        let none = format!("{}.{}.", enc(r#"{"alg":"none"}"#), enc(&claims));
        let p = proof_with(&proof_claims(&none), dpop, dpop);
        assert_eq!(run(&none, &p), Err(AuthError::BadSignature));

        let hs_input = format!(
            "{}.{}",
            enc(r#"{"alg":"HS256","kid":"issuer-key"}"#),
            enc(&claims)
        );
        let hs = format!("{hs_input}.{}", sha256_b64url(hs_input.as_bytes()));
        let p = proof_with(&proof_claims(&hs), dpop, dpop);
        assert_eq!(run(&hs, &p), Err(AuthError::BadSignature));

        // A proof with alg none or HS256 is refused too.
        let (t, _) = valid_pair(dpop);
        let pc = proof_claims(&t).to_string();
        let jwk = dpop.public_jwk();
        let ph = json!({"typ": "dpop+jwt", "alg": "none", "jwk": jwk}).to_string();
        let p = format!("{}.{}.", enc(&ph), enc(&pc));
        assert_eq!(run(&t, &p), Err(AuthError::BadSignature));
        let ph = json!({"typ": "dpop+jwt", "alg": "HS256", "jwk": jwk}).to_string();
        let pi = format!("{}.{}", enc(&ph), enc(&pc));
        let p = format!("{pi}.{}", sha256_b64url(pi.as_bytes()));
        assert_eq!(run(&t, &p), Err(AuthError::BadSignature));
    }

    #[test]
    fn rejects_proof_key_not_matching_cnf_jkt() {
        let dpop = &keys().dpop_ec;
        let other = &keys().other_ec;
        let t = token_with(&token_claims(dpop));
        // Proof made and signed by a different key than the one bound in cnf.jkt.
        let p = proof_with(&proof_claims(&t), other, other);
        assert_eq!(run(&t, &p), Err(AuthError::ProofMismatch));
    }

    #[test]
    fn rejects_proof_signature_by_other_key() {
        // Header names the bound key, but the signature comes from another key.
        let dpop = &keys().dpop_ec;
        let t = token_with(&token_claims(dpop));
        let p = proof_with(&proof_claims(&t), dpop, &keys().other_ec);
        assert_eq!(run(&t, &p), Err(AuthError::BadSignature));
    }

    #[test]
    fn rejects_proof_wrong_htu() {
        let dpop = &keys().dpop_ec;
        let t = token_with(&token_claims(dpop));
        let mut c = proof_claims(&t);
        c["htu"] = json!("https://relay.example/v1/room/ffffffffffffffffffffffffffffffff");
        let p = proof_with(&c, dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::ProofMismatch));
    }

    #[test]
    fn rejects_proof_wrong_htm() {
        let dpop = &keys().dpop_ec;
        let t = token_with(&token_claims(dpop));
        let mut c = proof_claims(&t);
        c["htm"] = json!("POST");
        let p = proof_with(&c, dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::ProofMismatch));
    }

    #[test]
    fn rejects_proof_ath_mismatch() {
        let dpop = &keys().dpop_ec;
        let t = token_with(&token_claims(dpop));
        let mut c = proof_claims(&t);
        c["ath"] = json!(sha256_b64url(b"some other token"));
        let p = proof_with(&c, dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::ProofMismatch));
    }

    #[test]
    fn rejects_proof_older_than_60s() {
        let dpop = &keys().dpop_ec;
        let t = token_with(&token_claims(dpop));
        let mut c = proof_claims(&t);
        c["iat"] = json!(NOW - 60);
        assert!(
            run(&t, &proof_with(&c, dpop, dpop)).is_ok(),
            "60 s old is still inside the window"
        );
        c["iat"] = json!(NOW - 61);
        assert_eq!(
            run(&t, &proof_with(&c, dpop, dpop)),
            Err(AuthError::ProofStale)
        );
    }

    #[test]
    fn rejects_proof_from_future() {
        let dpop = &keys().dpop_ec;
        let t = token_with(&token_claims(dpop));
        let mut c = proof_claims(&t);
        c["iat"] = json!(NOW + 61);
        assert_eq!(
            run(&t, &proof_with(&c, dpop, dpop)),
            Err(AuthError::ProofStale)
        );
    }

    #[test]
    fn rejects_issuer_not_in_profile() {
        // Validly signed token from issuer B; Alice's profile lists only issuer A.
        let dpop = &keys().dpop_ec;
        let mut c = token_claims(dpop);
        c["iss"] = json!(ISS_B);
        let t = token_with(&c);
        let p = proof_with(&proof_claims(&t), dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::IssuerNotTrusted));
    }

    #[test]
    fn rejects_token_without_webid_claim() {
        let dpop = &keys().dpop_ec;
        let mut c = token_claims(dpop);
        c.as_object_mut().unwrap().remove("webid");
        let t = token_with(&c);
        let p = proof_with(&proof_claims(&t), dpop, dpop);
        assert_eq!(run(&t, &p), Err(AuthError::Malformed));
    }

    #[test]
    fn rejects_garbage_as_malformed_without_panicking() {
        let (t, p) = valid_pair(&keys().dpop_ec);
        for bad in [
            "",
            ".",
            "..",
            "a.b.c",
            "a.b",
            "a.b.c.d",
            "!!!.###.$$$",
            "e30.e30.e30",
        ] {
            assert_eq!(run(bad, &p), Err(AuthError::Malformed), "token {bad:?}");
            if bad != "e30.e30.e30" {
                assert_eq!(run(&t, bad), Err(AuthError::Malformed), "proof {bad:?}");
            }
        }
        // A well formed JWT with an empty header is not a DPoP proof.
        assert_eq!(run(&t, "e30.e30.e30"), Err(AuthError::ProofMismatch));
    }

    #[test]
    fn rejects_proof_with_wrong_typ_or_private_key() {
        let dpop = &keys().dpop_ec;
        let t = token_with(&token_claims(dpop));
        let header = json!({"typ": "JWT", "alg": "ES256", "jwk": dpop.public_jwk()});
        let p = jwt(&header, &proof_claims(&t), dpop);
        assert_eq!(run(&t, &p), Err(AuthError::ProofMismatch));
        let mut jwk = dpop.public_jwk();
        jwk["d"] = json!("AAAA");
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk});
        let p = jwt(&header, &proof_claims(&t), dpop);
        assert_eq!(run(&t, &p), Err(AuthError::Malformed));
    }
}
