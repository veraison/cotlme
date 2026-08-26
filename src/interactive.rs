//! Interactive wizard mode, shown when `cotl` runs without arguments.

use std::path::PathBuf;

use dialoguer::{Input, Select};

use cotlme::cotl::{self, CotlSpec, TagId};
use cotlme::keys;
use cotlme::rim::{self, SignAlg};

/// Runs the interactive wizard.
///
/// # Errors
/// Propagates any I/O or library failure.
pub fn run() -> anyhow::Result<()> {
    println!("cotlme — CoTL/CoRIM tool (draft-ietf-rats-corim-11)\n");

    let choices = [
        "Create a CoTL",
        "Inspect / validate a file",
        "Wrap + sign a CoTL into a signed CoRIM",
        "Verify a signed CoRIM",
        "Generate a signing keypair",
        "Quit",
    ];
    let pick = Select::new()
        .with_prompt("What do you want to do")
        .items(choices)
        .default(0)
        .interact()?;

    match pick {
        0 => create_cotl(),
        1 => inspect(),
        2 => wrap_sign(),
        3 => verify(),
        4 => keygen(),
        _ => Ok(()),
    }
}

fn create_cotl() -> anyhow::Result<()> {
    let id: String = Input::new()
        .with_prompt("CoTL id (UUID or text)")
        .interact()?;
    let tags_raw: String = Input::new()
        .with_prompt("Tag ids to activate (comma-separated)")
        .interact()?;
    let not_after: String = Input::new()
        .with_prompt("Valid until (RFC 3339 or Unix seconds)")
        .default("2100-01-01T00:00:00Z".into())
        .interact()?;
    let out: String = Input::new()
        .with_prompt("Output file")
        .default("out.cotl".into())
        .interact()?;

    let spec = CotlSpec {
        id: TagId::parse(&id),
        version: None,
        tags: tags_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(TagId::parse)
            .collect(),
        not_before: None,
        not_after: crate::parse_time(&not_after)?,
    };
    if spec.tags.is_empty() {
        anyhow::bail!("at least one tag id is required");
    }
    let bytes = cotl::encode(&spec.build()?)?;
    std::fs::write(&out, bytes)?;
    println!("wrote {out}");
    Ok(())
}

fn inspect() -> anyhow::Result<()> {
    let path: String = Input::new().with_prompt("File to inspect").interact()?;
    let bytes = std::fs::read(&path)?;
    if cotl::decode(&bytes).is_ok() {
        let tag = cotl::decode(&bytes)?;
        print!("{}", cotl::summarize(&tag));
        let now = rim::now_unix();
        let report = cotl::validate(&tag, chrono::DateTime::from_timestamp(now, 0).unwrap());
        for w in &report.warnings {
            println!("warning: {w}");
        }
        println!(
            "{}",
            if report.is_valid() {
                "valid"
            } else {
                "INVALID"
            }
        );
    } else {
        // Delegate to the same rendering as `rim show`.
        crate::run_rim(crate::RimCmd::Show {
            file: PathBuf::from(&path),
        })?;
    }
    Ok(())
}

fn wrap_sign() -> anyhow::Result<()> {
    let cotl_path: String = Input::new().with_prompt("CoTL file").interact()?;
    let corim_id: String = Input::new().with_prompt("CoRIM id").interact()?;
    let key_path: String = Input::new().with_prompt("PEM private key").interact()?;
    let signer_name: String = Input::new()
        .with_prompt("Signer name")
        .default("cotlme signer".into())
        .interact()?;
    let out: String = Input::new()
        .with_prompt("Output file")
        .default("signed.corim".into())
        .interact()?;

    let tag = cotl::decode(&std::fs::read(&cotl_path)?)?;
    let map = rim::wrap_unsigned(&tag, &corim_id, None)?;
    let priv_pem = std::fs::read(&key_path)?;
    let signed = rim::sign(
        map,
        &priv_pem,
        SignAlg::Es256,
        b"cotlme".to_vec(),
        signer_name,
        rim::now_unix() + 365 * 86_400,
    )?;
    let bytes = rim::encode_any(&corim_rs::ConciseRimTypeChoice::Signed(signed.into()))?;
    std::fs::write(&out, bytes)?;
    println!("wrote {out}");
    Ok(())
}

fn verify() -> anyhow::Result<()> {
    let file: String = Input::new().with_prompt("Signed CoRIM file").interact()?;
    let key: String = Input::new().with_prompt("PEM public key").interact()?;
    crate::run_rim(crate::RimCmd::Verify {
        file: PathBuf::from(file),
        key: PathBuf::from(key),
    })
}

fn keygen() -> anyhow::Result<()> {
    let curves = ["p256", "p384", "p521"];
    let idx = Select::new()
        .with_prompt("Curve")
        .items(curves)
        .default(0)
        .interact()?;
    let curve = match idx {
        0 => keys::Curve::P256,
        1 => keys::Curve::P384,
        _ => keys::Curve::P521,
    };
    let priv_out: String = Input::new()
        .with_prompt("Private key path")
        .default("signing-key.pem".into())
        .interact()?;
    let pub_out: String = Input::new()
        .with_prompt("Public key path")
        .default("signing-pub.pem".into())
        .interact()?;
    let (priv_pem, pub_pem) = keys::generate_ec_keypair(curve)?;
    std::fs::write(&priv_out, priv_pem)?;
    std::fs::write(&pub_out, pub_pem)?;
    println!("wrote {priv_out} and {pub_out}");
    Ok(())
}
