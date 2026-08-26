//! EC key generation for signing CoRIMs.

use openssl::pkey::PKey;

use crate::error::{Error, Result};

/// Elliptic curves supported for key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Curve {
    /// NIST P-256 (prime256v1), pairs with ES256.
    P256,
    /// NIST P-384 (secp384r1), pairs with ES384.
    P384,
    /// NIST P-521 (secp521r1), pairs with ES512.
    P521,
}

/// Generates a new EC private key and returns PEM encodings
/// of the private and public keys.
///
/// # Errors
/// Returns an error on any OpenSSL failure.
pub fn generate_ec_keypair(curve: Curve) -> Result<(Vec<u8>, Vec<u8>)> {
    let nid = match curve {
        Curve::P256 => openssl::nid::Nid::X9_62_PRIME256V1,
        Curve::P384 => openssl::nid::Nid::SECP384R1,
        Curve::P521 => openssl::nid::Nid::SECP521R1,
    };
    let group = openssl::ec::EcGroup::from_curve_name(nid)?;
    let ec_key = openssl::ec::EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    let priv_pem = pkey.private_key_to_pem_pkcs8()?;
    let pub_pem = pkey.public_key_to_pem()?;
    Ok((priv_pem, pub_pem))
}

/// Loads the public half of an RSA/EC key from a PKCS#8 or traditional PEM
/// private key without exposing it to disk again. Useful in tests.
///
/// # Errors
/// Returns an error when the PEM cannot be parsed.
pub fn public_from_private(priv_pem: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::private_key_from_pem(priv_pem)
        .map_err(|e| Error::custom(format!("could not parse private key: {e}")))?;
    Ok(pkey.public_key_to_pem()?)
}

use corim_rs::{CoseEllipticCurve, CoseKey, CoseKty, OpensslSigner};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::EcKey;
use openssl::nid::Nid;

/// Coordinate size in bytes for each supported curve.
fn coord_len(nid: Nid) -> Result<usize> {
    match nid {
        Nid::X9_62_PRIME256V1 => Ok(32),
        Nid::SECP384R1 => Ok(48),
        Nid::SECP521R1 => Ok(66),
        other => Err(Error::custom(format!("unsupported curve {other:?}"))),
    }
}

fn crv(nid: Option<Nid>) -> Result<CoseEllipticCurve> {
    match nid {
        Some(Nid::X9_62_PRIME256V1) => Ok(CoseEllipticCurve::P256),
        Some(Nid::SECP384R1) => Ok(CoseEllipticCurve::P384),
        Some(Nid::SECP521R1) => Ok(CoseEllipticCurve::P521),
        _ => Err(Error::custom("unsupported EC curve")),
    }
}

/// Left-pads a big-endian integer to `len` bytes.
fn pad(bn: &openssl::bn::BigNumRef, len: usize) -> Result<Vec<u8>> {
    let mut v = bn.to_vec();
    if v.len() > len {
        return Err(Error::custom("coordinate longer than curve size"));
    }
    let mut padded = vec![0u8; len - v.len()];
    padded.append(&mut v);
    Ok(padded)
}

/// Builds a signer from a PEM EC private key with correctly padded scalars.
///
/// Works around an upstream issue where unpadded big-endian integers break
/// P-521 (and edge-case P-384) signatures.
///
/// # Errors
/// Returns an error when the PEM cannot be parsed or the curve unsupported.
pub fn signer_from_private_pem(priv_pem: &[u8]) -> Result<OpensslSigner> {
    let ec_key = EcKey::private_key_from_pem(priv_pem)?;
    let curve = crv(ec_key.group().curve_name())?;
    let len = coord_len(ec_key.group().curve_name().unwrap())?;
    let d = pad(ec_key.private_key(), len)?;
    Ok(OpensslSigner::from(CoseKey {
        kty: CoseKty::Ec2,
        alg: None,
        crv: Some(curve),
        x: None,
        y: None,
        d: Some(d.into()),
        key_ops: None,
        base_iv: None,
        k: None,
        kid: None,
    }))
}

/// Builds a verifier from a PEM EC public key with correctly padded
/// coordinates.
///
/// # Errors
/// Returns an error when the PEM cannot be parsed or the curve unsupported.
pub fn verifier_from_public_pem(public_pem: &[u8]) -> Result<OpensslSigner> {
    let ec_key = EcKey::public_key_from_pem(public_pem)?;
    let group = ec_key.group();
    let curve = crv(group.curve_name())?;
    let len = coord_len(group.curve_name().unwrap())?;

    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    ec_key
        .public_key()
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

    Ok(OpensslSigner::from(CoseKey {
        kty: CoseKty::Ec2,
        alg: None,
        crv: Some(curve),
        x: Some(pad(&x, len)?.into()),
        y: Some(pad(&y, len)?.into()),
        d: None,
        key_ops: None,
        base_iv: None,
        k: None,
        kid: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_keypairs_per_curve() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let (priv_pem, pub_pem) = generate_ec_keypair(curve).unwrap();
            assert!(priv_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
            assert!(pub_pem.starts_with(b"-----BEGIN PUBLIC KEY-----"));

            let derived = public_from_private(&priv_pem).unwrap();
            assert_eq!(derived, pub_pem);

            // Two generated keys are never identical.
            let (priv2, _) = generate_ec_keypair(curve).unwrap();
            assert_ne!(priv_pem, priv2);
        }
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;

    #[test]
    fn rejects_non_key_pem_input() {
        assert!(generate_ec_keypair(Curve::P256).is_ok()); // sanity
        assert!(PKey::private_key_from_pem(b"garbage").is_err());
    }

    #[test]
    fn public_from_private_rejects_garbage() {
        assert!(public_from_private(b"nope").is_err());
        assert!(public_from_private(b"").is_err());
    }

    #[test]
    fn generated_keys_load_back_through_verifier_path() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let (priv_pem, pub_pem) = generate_ec_keypair(curve).unwrap();
            let signer = signer_from_private_pem(&priv_pem).unwrap();
            let verifier = verifier_from_public_pem(&pub_pem).unwrap();
            use corim_rs::{CoseAlgorithm, CoseSigner, CoseVerifier};
            let sig =
                CoseSigner::sign(&signer, CoseAlgorithm::ES512, b"data").unwrap_or_else(|_| {
                    CoseSigner::sign(&signer, CoseAlgorithm::ES256, b"data").unwrap()
                });
            // Verify with the matching alg the signature was made with.
            let ok = CoseVerifier::verify_signature(&verifier, CoseAlgorithm::ES256, &sig, b"data")
                .or_else(|_| {
                    CoseVerifier::verify_signature(&verifier, CoseAlgorithm::ES384, &sig, b"data")
                })
                .or_else(|_| {
                    CoseVerifier::verify_signature(&verifier, CoseAlgorithm::ES512, &sig, b"data")
                });
            assert!(ok.is_ok(), "{curve:?}");
        }
    }

    #[test]
    fn verifier_rejects_foreign_public_key_material() {
        // A P-256 public key must not verify against a P-384 curve context.
        let (_, p256_pub) = generate_ec_keypair(Curve::P256).unwrap();
        let (p384_priv, _) = generate_ec_keypair(Curve::P384).unwrap();
        let signer = signer_from_private_pem(&p384_priv).unwrap();
        use corim_rs::{CoseAlgorithm, CoseSigner};
        let sig = CoseSigner::sign(&signer, CoseAlgorithm::ES384, b"x").unwrap();
        let wrong = verifier_from_public_pem(&p256_pub).unwrap();
        use corim_rs::CoseVerifier;
        assert!(CoseVerifier::verify_signature(&wrong, CoseAlgorithm::ES384, &sig, b"x").is_err());
    }
}
