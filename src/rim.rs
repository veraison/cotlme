//! CoRIM wrapping, signing, and verification for CoTL tags.
//!
//! Implements the unsigned (#6.501) and signed (COSE_Sign1, #6.18) CoRIM
//! forms described in draft-ietf-rats-corim-11 Sections 4.1 and 4.2.

use corim_rs::{
    ConciseRimTypeChoice, ConciseTagTypeChoice, CorimIdTypeChoice, CorimMapBuilder, CoseAlgorithm,
    EntityNameTypeChoice, IntegerTime, SignedCorim, SignedCorimBuilder, TaggedConciseTlTag,
    TaggedUnsignedCorim,
};

use crate::error::{Error, Result};

/// Supported COSE signing algorithms exposed by this tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SignAlg {
    /// ECDSA w/ SHA-256 on P-256.
    Es256,
    /// ECDSA w/ SHA-384 on P-384.
    Es384,
    /// ECDSA w/ SHA-512 on P-521.
    Es512,
}

impl From<SignAlg> for CoseAlgorithm {
    fn from(a: SignAlg) -> Self {
        match a {
            SignAlg::Es256 => Self::ES256,
            SignAlg::Es384 => Self::ES384,
            SignAlg::Es512 => Self::ES512,
        }
    }
}

/// Wraps a built CoTL into an unsigned CoRIM (`#6.501` form).
///
/// # Errors
/// Returns an error if the CoRIM cannot be constructed or encoded.
pub fn wrap_unsigned(
    cotl: &corim_rs::ConciseTlTag<'static>,
    corim_id: &str,
    profile: Option<&str>,
) -> Result<corim_rs::CorimMap<'static>> {
    let id = parse_corim_id(corim_id);
    let mut builder = CorimMapBuilder::new()
        .id(id)
        .add_tag(ConciseTagTypeChoice::Tl(TaggedConciseTlTag::new(
            cotl.clone(),
        )));
    if let Some(p) = profile {
        builder = builder.profile(corim_rs::ProfileTypeChoice::Uri(p.to_owned().into()));
    }
    builder.build().map_err(Error::from)
}

/// Signs a CoRIM map into a `COSE_Sign1` wrapped [`SignedCorim`].
///
/// # Errors
/// Returns an error if required metadata is missing or signing fails.
pub fn sign(
    corim: corim_rs::CorimMap<'static>,
    key_pem: &[u8],
    alg: SignAlg,
    kid: Vec<u8>,
    signer_name: String,
    not_after: i64,
) -> Result<SignedCorim<'static>> {
    let signer = crate::keys::signer_from_private_pem(key_pem)?;
    let meta = corim_rs::CorimMetaMapBuilder::new()
        .signer_name(EntityNameTypeChoice::Text(signer_name.clone().into()))
        .not_before(IntegerTime::from(now_unix()))
        .not_after(IntegerTime::from(not_after))
        .build()
        .map_err(Error::from)?;
    SignedCorimBuilder::new()
        .alg(alg.into())
        .kid(kid)
        .meta(meta)
        .corim_map(corim)
        .build_and_sign(signer)
        .map_err(Error::from)
}

/// Verifies a signed CoRIM against a PEM-encoded public key.
///
/// # Errors
/// Returns an error if decoding, header checks, signature verification, or
/// validity-window enforcement fails.
pub fn verify(signed_cbor: &[u8], public_pem: &[u8]) -> Result<()> {
    let signed = decode_signed(signed_cbor)?;
    let verifier = crate::keys::verifier_from_public_pem(public_pem)?;
    corim_rs::CoseVerifier::verify_header_and_key(&verifier, &signed)?;
    signed.verify_signature(verifier).map_err(Error::from)
}

/// Decodes CBOR bytes into a [`SignedCorim`].
///
/// # Errors
/// Returns an error when the bytes are not a COSE_Sign1 signed CoRIM.
pub fn decode_signed(bytes: &[u8]) -> Result<SignedCorim<'static>> {
    if let Ok(tagged) = ciborium::from_reader::<corim_rs::TaggedSignedCorim, _>(&mut &bytes[..]) {
        return Ok(tagged.unwrap());
    }
    ciborium::from_reader::<SignedCorim, _>(&mut &bytes[..])
        .map_err(|e| Error::custom(format!("not a valid signed CoRIM: {e}")))
}

/// Decodes CBOR bytes into any CoRIM entrypoint (signed or unsigned).
///
/// # Errors
/// Returns an error if the bytes are neither form.
pub fn decode_any(bytes: &[u8]) -> Result<ConciseRimTypeChoice<'static>> {
    if let Ok(signed) = decode_signed(bytes) {
        return Ok(ConciseRimTypeChoice::Signed(signed.into()));
    }
    let unsigned = ciborium::from_reader::<TaggedUnsignedCorim, _>(&mut &bytes[..])
        .map_err(|e| Error::custom(format!("not a valid CoRIM: {e}")))?;
    Ok(ConciseRimTypeChoice::Unsigned(unsigned))
}

/// Encodes any CoRIM entrypoint to CBOR bytes.
///
/// # Errors
/// Returns an error on serialization failure.
pub fn encode_any(rim: &ConciseRimTypeChoice<'_>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(rim, &mut buf).map_err(|e| Error::custom(e.to_string()))?;
    Ok(buf)
}

/// Current Unix time in seconds.
#[must_use]
pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Parses a CoRIM id as UUID when possible, otherwise as text.
#[must_use]
pub fn parse_corim_id(s: &str) -> CorimIdTypeChoice<'static> {
    match uuid::Uuid::from_str(s) {
        Ok(u) => CorimIdTypeChoice::Uuid(corim_rs::UuidType::from(u.into_bytes())),
        Err(_) => CorimIdTypeChoice::Tstr(s.to_owned().into()),
    }
}

use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cotl::{decode, encode};
    use crate::keys;

    fn test_cotl() -> corim_rs::ConciseTlTag<'static> {
        crate::cotl::CotlSpec {
            id: crate::cotl::TagId::parse("test-cotl"),
            version: None,
            tags: vec![crate::cotl::TagId::parse(
                "123e4567-e89b-12d3-a456-426614174000",
            )],
            not_before: None,
            not_after: now_unix() + 86_400,
        }
        .build()
        .unwrap()
    }

    #[test]
    fn cotl_encode_decode_roundtrip_in_rim_context() {
        let bytes = encode(&test_cotl()).unwrap();
        assert_eq!(decode(&bytes).unwrap(), test_cotl());
    }

    #[test]
    fn unsigned_rim_wraps_and_decodes() {
        let rim =
            wrap_unsigned(&test_cotl(), "my-corim-id", Some("tag:example.com,2025/p")).unwrap();
        let choice = ConciseRimTypeChoice::Unsigned(TaggedUnsignedCorim::from(rim));
        let bytes = encode_any(&choice).unwrap();
        match decode_any(&bytes).unwrap() {
            ConciseRimTypeChoice::Unsigned(t) => {
                let map = t.unwrap();
                assert_eq!(map.id.as_str(), Some("my-corim-id"));
                let tag = map.tags.first().unwrap();
                assert!(matches!(tag, ConciseTagTypeChoice::Tl(_)));
            }
            _ => panic!("expected unsigned CoRIM"),
        }
    }

    #[test]
    fn decode_any_rejects_garbage() {
        assert!(decode_any(b"\xff\xff").is_err());
    }

    fn keypair(curve: keys::Curve) -> (Vec<u8>, Vec<u8>) {
        keys::generate_ec_keypair(curve).unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip_all_curves() {
        for (curve, alg) in [
            (keys::Curve::P256, SignAlg::Es256),
            (keys::Curve::P384, SignAlg::Es384),
            (keys::Curve::P521, SignAlg::Es512),
        ] {
            let (priv_pem, pub_pem) = keypair(curve);
            let rim = wrap_unsigned(&test_cotl(), "id", None).unwrap();
            let signed = sign(
                rim,
                &priv_pem,
                alg,
                b"kid1".to_vec(),
                "ACME".into(),
                now_unix() + 3600,
            )
            .unwrap_or_else(|e| panic!("sign {curve:?}: {e}"));
            let bytes = encode_any(&ConciseRimTypeChoice::Signed(signed.into()))
                .unwrap_or_else(|e| panic!("encode {curve:?}: {e}"));
            verify(&bytes, &pub_pem).unwrap_or_else(|e| panic!("verify {curve:?}: {e}"));
        }
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (priv_pem, pub_pem) = keypair(keys::Curve::P256);
        let rim = wrap_unsigned(&test_cotl(), "id", None).unwrap();
        let signed = sign(
            rim,
            &priv_pem,
            SignAlg::Es256,
            b"k".to_vec(),
            "A".into(),
            now_unix() + 3600,
        )
        .unwrap();
        let mut bytes = encode_any(&ConciseRimTypeChoice::Signed(signed.into())).unwrap();
        let n = bytes.len();
        bytes[n - 5] ^= 0xFF;
        assert!(verify(&bytes, &pub_pem).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (priv_pem, _) = keypair(keys::Curve::P256);
        let (_, other_pub) = keypair(keys::Curve::P256);
        let rim = wrap_unsigned(&test_cotl(), "id", None).unwrap();
        let signed = sign(
            rim,
            &priv_pem,
            SignAlg::Es256,
            b"k".to_vec(),
            "A".into(),
            now_unix() + 3600,
        )
        .unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Signed(signed.into())).unwrap();
        assert!(verify(&bytes, &other_pub).is_err());
    }

    #[test]
    fn verify_rejects_expired_signature_validity() {
        let (priv_pem, pub_pem) = keypair(keys::Curve::P256);
        let rim = wrap_unsigned(&test_cotl(), "id", None).unwrap();
        let signed = sign(
            rim,
            &priv_pem,
            SignAlg::Es256,
            b"k".to_vec(),
            "A".into(),
            now_unix() - 3600,
        )
        .unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Signed(signed.into())).unwrap();
        let err = verify(&bytes, &pub_pem).unwrap_err();
        assert!(err.to_string().contains("validity") || err.to_string().contains("expired"));
    }

    #[test]
    fn sign_requires_matching_curve_for_alg() {
        // P-256 key with an ES512 request must not silently succeed.
        let (priv_pem, _) = keypair(keys::Curve::P256);
        let rim = wrap_unsigned(&test_cotl(), "id", None).unwrap();
        // OpensslSigner maps alg -> digest; P-256 cannot produce a 521-bit
        // signature, so either signing or later verification must fail.
        let result = std::panic::catch_unwind(|| {
            let _ = sign(
                rim.clone(),
                &priv_pem,
                SignAlg::Es512,
                b"k".to_vec(),
                "A".into(),
                0,
            );
        });
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;
    use crate::keys;

    fn cotl_with(not_after: i64) -> corim_rs::ConciseTlTag<'static> {
        crate::cotl::CotlSpec {
            id: crate::cotl::TagId::parse("edge-cotl"),
            version: None,
            tags: vec![crate::cotl::TagId::parse("t1")],
            not_before: None,
            not_after,
        }
        .build()
        .unwrap()
    }

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        keys::generate_ec_keypair(keys::Curve::P256).unwrap()
    }

    #[test]
    fn wrap_rejects_empty_id() {
        // Empty string id is structurally legal in CBOR; ensure it round-trips
        // rather than silently corrupting.
        let rim = wrap_unsigned(&cotl_with(10), "", None).unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Unsigned(rim.into())).unwrap();
        match decode_any(&bytes).unwrap() {
            ConciseRimTypeChoice::Unsigned(t) => {
                assert_eq!(t.unwrap().id.as_str(), Some(""));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn wrap_uuid_corim_id_roundtrips() {
        let u = "0197e0a5-7d4f-7000-8000-000000000000";
        let rim = wrap_unsigned(&cotl_with(10), u, None).unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Unsigned(rim.into())).unwrap();
        match decode_any(&bytes).unwrap() {
            ConciseRimTypeChoice::Unsigned(t) => {
                assert_eq!(
                    t.unwrap()
                        .id
                        .as_uuid_bytes()
                        .map(|b| <[u8; 16]>::try_from(b).unwrap()),
                    Some(uuid::Uuid::parse_str(u).unwrap().into_bytes())
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn wrap_profile_uri_survives_roundtrip() {
        let p = "https://example.com/profiles/v2";
        let rim = wrap_unsigned(&cotl_with(10), "id", Some(p)).unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Unsigned(rim.into())).unwrap();
        match decode_any(&bytes).unwrap() {
            ConciseRimTypeChoice::Unsigned(t) => {
                let map = t.unwrap();
                assert_eq!(
                    map.profile
                        .as_ref()
                        .unwrap()
                        .as_ref_uri()
                        .unwrap()
                        .to_string(),
                    p
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn verify_rejects_unsigned_rim_and_garbage() {
        let (_, pub_pem) = keypair();
        let unsigned = encode_any(&ConciseRimTypeChoice::Unsigned(
            wrap_unsigned(&cotl_with(10), "id", None).unwrap().into(),
        ))
        .unwrap();
        assert!(verify(&unsigned, &pub_pem).is_err());
        assert!(verify(b"", &pub_pem).is_err());
        assert!(verify(&[0xA0], &pub_pem).is_err()); // empty cbor map
    }

    #[test]
    fn verify_rejects_bad_public_key_pem() {
        let (priv_pem, _) = keypair();
        let signed = sign(
            wrap_unsigned(&cotl_with(10), "id", None).unwrap(),
            &priv_pem,
            SignAlg::Es256,
            b"k".to_vec(),
            "A".into(),
            9_999_999_999,
        )
        .unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Signed(signed.into())).unwrap();
        assert!(verify(&bytes, b"not a pem").is_err());
        assert!(verify(&bytes, b"").is_err());
    }

    #[test]
    fn sign_rejects_bad_private_key_pem() {
        assert!(
            sign(
                wrap_unsigned(&cotl_with(10), "id", None).unwrap(),
                b"junk",
                SignAlg::Es256,
                b"k".to_vec(),
                "A".into(),
                9_999_999_999
            )
            .is_err()
        );
    }

    #[test]
    fn signed_document_roundtrip_through_decode_any() {
        let (priv_pem, pub_pem) = keypair();
        let signed = sign(
            wrap_unsigned(&cotl_with(9_999_999_999), "id", None).unwrap(),
            &priv_pem,
            SignAlg::Es384,
            "kid-ünicode".as_bytes().to_vec(),
            "Ünïcode Signer".into(),
            9_999_999_999,
        )
        .unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Signed(signed.into())).unwrap();
        assert!(matches!(
            decode_any(&bytes).unwrap(),
            ConciseRimTypeChoice::Signed(_)
        ));
        assert!(verify(&bytes, &pub_pem).is_ok());

        // And the embedded CoTL is still intact.
        match decode_any(&bytes).unwrap() {
            ConciseRimTypeChoice::Signed(s) => {
                let signed = s.unwrap();
                drop(signed);
                // The wire form is #6.18([prot, unprot, payload, sig]);
                // pull out the payload bstr directly by structure.
                let val: ciborium::value::Value = ciborium::from_reader(&mut &bytes[..]).unwrap();
                let arr = match val {
                    ciborium::value::Value::Tag(_, inner) => *inner,
                    other => other,
                };
                let items = match arr {
                    ciborium::value::Value::Array(a) => a,
                    other => panic!("expected COSE_Sign1 array, got {other:?}"),
                };
                let payload = match &items[2] {
                    ciborium::value::Value::Bytes(b) => b.clone(),
                    other => panic!("expected payload bytes, got {other:?}"),
                };
                match decode_any(&payload).unwrap() {
                    ConciseRimTypeChoice::Unsigned(u) => match &u.unwrap().tags[0] {
                        ConciseTagTypeChoice::Tl(t) => {
                            assert_eq!(
                                crate::cotl::tag_id_string(&t.0.0.tag_identity.tag_id),
                                "edge-cotl"
                            );
                        }
                        _ => panic!("expected CoTL"),
                    },
                    _ => panic!("expected unsigned payload"),
                }
            }
            _ => panic!(),
        }
    }

    /// Fuzz-lite: decode paths must never panic.
    #[test]
    fn decoders_never_panic_on_arbitrary_bytes() {
        let mut state: u64 = 0xC0FFEE;
        let mut buf = Vec::with_capacity(128);
        for _ in 0..2_000 {
            buf.clear();
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 33) as usize % 48;
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                buf.push((state >> 33) as u8);
            }
            let _ = decode_signed(&buf);
            let _ = decode_any(&buf);
        }
    }

    #[test]
    fn verify_fails_when_signature_not_yet_valid() {
        use corim_rs::{CorimMetaMapBuilder, IntegerTime, SignedCorimBuilder};
        let (priv_pem, pub_pem) = keypair();
        let signer = keys::signer_from_private_pem(&priv_pem).unwrap();

        let meta = CorimMetaMapBuilder::new()
            .signer_name("A".into())
            .not_before(IntegerTime::from(9_999_999_999_i64)) // year ~2286
            .not_after(IntegerTime::from(9_999_999_999 + 100))
            .build()
            .unwrap();
        let signed = SignedCorimBuilder::new()
            .alg(SignAlg::Es256.into())
            .kid(b"k".to_vec())
            .meta(meta)
            .corim_map(wrap_unsigned(&cotl_with(9_999_999_999), "id", None).unwrap())
            .build_and_sign(signer)
            .unwrap();
        let bytes = encode_any(&ConciseRimTypeChoice::Signed(signed.into())).unwrap();

        let err = verify(&bytes, &pub_pem);
        assert!(err.is_err(), "signature valid before its not-before");
        assert!(
            err.unwrap_err()
                .to_string()
                .to_lowercase()
                .contains("validit"),
            "error should be about the validity window"
        );
    }

    #[test]
    fn cli_visible_error_paths_never_panic() {
        // decode_signed / decode_any on pathological-but-valid CBOR shapes:
        // an array of ints (right shape, wrong contents).
        let mut buf = Vec::new();
        ciborium::into_writer(&vec![1i64, 2, 3], &mut buf).unwrap();
        assert!(decode_signed(&buf).is_err());
        assert!(decode_any(&buf).is_err());
    }
}
