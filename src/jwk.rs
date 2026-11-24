//! JSON Web Keys: parsing, RFC 7638 thumbprints and JWS signature checks
//! for the two algorithms the relay accepts, RS256 and ES256.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The JWS algorithms the relay accepts. Everything else (including `none`
/// and every HMAC algorithm) is refused before any key is consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Rs256,
    Es256,
}

impl Alg {
    pub fn parse(alg: &str) -> Option<Alg> {
        match alg {
            "RS256" => Some(Alg::Rs256),
            "ES256" => Some(Alg::Es256),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Es256 => "ES256",
        }
    }
}

/// A public JWK as found in a JWKS document or a DPoP proof header.
/// Every member is optional so that a JWKS with unfamiliar keys still parses;
/// a key that lacks what its type needs simply never verifies.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: Option<String>,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    /// Present only on private keys. A proof header carrying it is refused.
    pub d: Option<String>,
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url (no padding) of SHA-256 of `data`.
pub fn sha256_b64url(data: &[u8]) -> String {
    b64url_encode(&Sha256::digest(data))
}

impl Jwk {
    pub fn from_value(v: &serde_json::Value) -> Option<Jwk> {
        serde_json::from_value(v.clone()).ok()
    }

    /// RFC 7638 thumbprint, base64url of SHA-256 of the canonical JSON with
    /// the required members in lexicographic order (RSA: e, kty, n; EC: crv,
    /// kty, x, y). Every member is checked to be valid base64url first, so the
    /// string building below can never be broken by quotes or escapes.
    pub fn thumbprint(&self) -> Option<String> {
        let canonical = match self.kty.as_deref()? {
            "RSA" => {
                let (n, e) = (self.n.as_deref()?, self.e.as_deref()?);
                b64url_decode(n)?;
                b64url_decode(e)?;
                format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
            }
            "EC" => {
                if self.crv.as_deref()? != "P-256" {
                    return None;
                }
                let (x, y) = (self.x.as_deref()?, self.y.as_deref()?);
                b64url_decode(x)?;
                b64url_decode(y)?;
                format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            _ => return None,
        };
        Some(sha256_b64url(canonical.as_bytes()))
    }

    /// True when this key can be used with `alg`: the key type matches and,
    /// if the key names its own `alg` or a `use`, those agree too.
    pub fn suits(&self, alg: Alg) -> bool {
        if let Some(a) = &self.alg {
            if a != alg.as_str() {
                return false;
            }
        }
        if let Some(u) = &self.use_ {
            if u != "sig" {
                return false;
            }
        }
        match alg {
            Alg::Rs256 => self.kty.as_deref() == Some("RSA"),
            Alg::Es256 => self.kty.as_deref() == Some("EC") && self.crv.as_deref() == Some("P-256"),
        }
    }

    /// Verify a JWS signature over `signing_input` with this key. Returns
    /// false on any malformed key or signature; it never panics.
    pub fn verify(&self, alg: Alg, signing_input: &[u8], sig: &[u8]) -> bool {
        if !self.suits(alg) {
            return false;
        }
        match alg {
            Alg::Rs256 => self.verify_rs256(signing_input, sig),
            Alg::Es256 => self.verify_es256(signing_input, sig),
        }
    }

    fn verify_rs256(&self, msg: &[u8], sig: &[u8]) -> bool {
        use rsa::signature::Verifier;
        let (Some(n), Some(e)) = (self.n.as_deref(), self.e.as_deref()) else {
            return false;
        };
        let (Some(n), Some(e)) = (b64url_decode(n), b64url_decode(e)) else {
            return false;
        };
        if n.is_empty() || e.is_empty() || e.len() > 8 {
            return false;
        }
        let n = rsa::BoxedUint::from_be_slice_vartime(&n);
        let e = rsa::BoxedUint::from_be_slice_vartime(&e);
        // 2048 to 4096 bit moduli only: smaller is weak, larger only costs CPU.
        let Ok(pk) = rsa::PublicKey::new_with_size_limits(n, e, 2048..=4096) else {
            return false;
        };
        let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pk);
        let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }

    fn verify_es256(&self, msg: &[u8], sig: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        let (Some(x), Some(y)) = (self.x.as_deref(), self.y.as_deref()) else {
            return false;
        };
        let (Some(x), Some(y)) = (b64url_decode(x), b64url_decode(y)) else {
            return false;
        };
        // JWS ES256 signatures are the raw 64 byte r || s form, not DER.
        if x.len() != 32 || y.len() != 32 || sig.len() != 64 {
            return false;
        }
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point) else {
            return false;
        };
        let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}
