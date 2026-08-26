//! `cotlme` — a stupid-simple, extremely powerful CoTL/CoRIM tool.
//!
//! Run without arguments for the interactive wizard; otherwise use the
//! clap-driven subcommands (`cotl`, `rim`, `keygen`).

use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand};
use corim_rs::{ConciseRimTypeChoice, ConciseTagTypeChoice};

use cotlme::cotl::{self, CotlSpec, TagId};
use cotlme::keys::{self, Curve};
use cotlme::rim::{self, SignAlg};

#[derive(Parser)]
#[command(
    name = "cotlme",
    about = "Create, inspect, validate, wrap, sign and verify CoTLs and CoRIMs (draft-ietf-rats-corim-11)",
    version,
    arg_required_else_help = false
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an EC keypair for COSE signing.
    Keygen {
        /// Elliptic curve to use.
        #[arg(short, long, value_enum, default_value = "p256")]
        curve: Curve,
        /// Output path for the PEM private key.
        #[arg(short, long)]
        private_out: PathBuf,
        /// Output path for the PEM public key.
        #[arg(short = 'P', long)]
        public_out: PathBuf,
    },
    /// Work with Concise Tag List (CoTL) tags.
    Cotl {
        #[command(subcommand)]
        cmd: CotlCmd,
    },
    /// Work with CoRIMs that carry CoTL tags.
    Rim {
        #[command(subcommand)]
        cmd: RimCmd,
    },
}

#[derive(Subcommand)]
enum CotlCmd {
    /// Create a CoTL tag file.
    Create {
        /// Identifier of this CoTL (UUID or text).
        #[arg(short = 'i', long)]
        id: String,
        /// Optional tag version.
        #[arg(short, long)]
        version: Option<i128>,
        /// Tag identity activated by this list (repeatable).
        #[arg(short = 't', long = "tag", required = true)]
        tags: Vec<String>,
        /// Validity start (Unix seconds or RFC 3339).
        #[arg(long)]
        not_before: Option<String>,
        /// Validity end (Unix seconds or RFC 3339).
        #[arg(long)]
        not_after: String,
        /// Output file (CBOR, tag 508).
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Print a human-readable summary of a CoTL file.
    Show {
        /// Path to the CoTL CBOR file.
        file: PathBuf,
    },
    /// Validate structure and validity window of a CoTL file.
    Validate {
        /// Path to the CoTL CBOR file.
        file: PathBuf,
        /// Check as-of time (Unix seconds or RFC 3339); defaults to now.
        #[arg(long)]
        now: Option<String>,
    },
}

#[derive(Subcommand)]
enum RimCmd {
    /// Wrap a CoTL into an unsigned (#6.501) CoRIM.
    Wrap {
        /// CoTL CBOR file to embed.
        #[arg(short, long)]
        cotl: PathBuf,
        /// Identifier of the new CoRIM (UUID or text).
        #[arg(short = 'i', long)]
        id: String,
        /// Optional profile URI/OID.
        #[arg(short, long)]
        profile: Option<String>,
        /// Output file.
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Sign a CoRIM into a COSE_Sign1 (#6.18) document.
    Sign {
        /// Unsigned CoRIM file to sign.
        #[arg(short, long)]
        input: PathBuf,
        /// PEM private key.
        #[arg(short, long)]
        key: PathBuf,
        /// COSE algorithm.
        #[arg(short, long, value_enum, default_value = "es256")]
        alg: SignAlg,
        /// Key identifier embedded in the protected header.
        #[arg(short = 'K', long, default_value = "cotlme")]
        kid: String,
        /// Name of the signing entity recorded in corim-meta.
        #[arg(short = 'n', long, default_value = "cotlme signer")]
        signer_name: String,
        /// Signature validity end (Unix seconds or RFC 3339).
        #[arg(long)]
        not_after: String,
        /// Output file.
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Verify a signed CoRIM against a PEM public key.
    Verify {
        /// Signed CoRIM file.
        file: PathBuf,
        /// PEM public key of the signer.
        #[arg(short, long)]
        key: PathBuf,
    },
    /// Print a summary of any CoRIM file (signed or unsigned).
    Show {
        /// CoRIM CBOR file.
        file: PathBuf,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => interactive::run(),
        Some(Command::Keygen {
            curve,
            private_out,
            public_out,
        }) => {
            let (priv_pem, pub_pem) = keys::generate_ec_keypair(curve)?;
            write_file(&private_out, &priv_pem)?;
            write_file(&public_out, &pub_pem)?;
            println!("private key: {}", private_out.display());
            println!("public key:  {}", public_out.display());
            Ok(())
        }
        Some(Command::Cotl { cmd }) => run_cotl(cmd),
        Some(Command::Rim { cmd }) => run_rim(cmd),
    }
}

fn run_cotl(cmd: CotlCmd) -> anyhow::Result<()> {
    match cmd {
        CotlCmd::Create {
            id,
            version,
            tags,
            not_before,
            not_after,
            out,
        } => {
            let spec = CotlSpec {
                id: TagId::parse(&id),
                version: version.map(corim_rs::Integer::new),
                tags: tags.iter().map(|t| TagId::parse(t)).collect(),
                not_before: not_before.as_deref().map(parse_time).transpose()?,
                not_after: parse_time(&not_after)?,
            };
            let cotl_tag = spec.build()?;
            let bytes = cotl::encode(&cotl_tag)?;
            write_file(&out, &bytes)?;
            println!("wrote CoTL {} ({})", out.display(), bytes.len());
            Ok(())
        }
        CotlCmd::Show { file } => {
            let tag = load_cotl(&file)?;
            print!("{}", cotl::summarize(&tag));
            Ok(())
        }
        CotlCmd::Validate { file, now } => {
            let tag = load_cotl(&file)?;
            let now = match now {
                Some(t) => parse_time(&t)?,
                None => rim::now_unix(),
            };
            let report = cotl::validate(&tag, chrono::DateTime::from_timestamp(now, 0).unwrap());
            for w in &report.warnings {
                println!("warning: {w}");
            }
            for e in &report.errors {
                eprintln!("error: {e}");
            }
            if report.is_valid() {
                println!("valid");
                Ok(())
            } else {
                Err(anyhow::anyhow!("CoTL is invalid"))
            }
        }
    }
}

fn run_rim(cmd: RimCmd) -> anyhow::Result<()> {
    match cmd {
        RimCmd::Wrap {
            cotl: cotl_path,
            id,
            profile,
            out,
        } => {
            let tag = load_cotl(&cotl_path)?;
            let map = rim::wrap_unsigned(&tag, &id, profile.as_deref())?;
            let bytes = rim::encode_any(&ConciseRimTypeChoice::Unsigned(map.into()))?;
            write_file(&out, &bytes)?;
            println!("wrote unsigned CoRIM {} ({})", out.display(), bytes.len());
            Ok(())
        }
        RimCmd::Sign {
            input,
            key,
            alg,
            kid,
            signer_name,
            not_after,
            out,
        } => {
            let unsigned = std::fs::read(&input)?;
            let map = match rim::decode_any(&unsigned)? {
                ConciseRimTypeChoice::Unsigned(t) => t.unwrap(),
                ConciseRimTypeChoice::Signed(_) => {
                    return Err(anyhow::anyhow!("input is already signed"));
                }
            };
            let priv_pem = std::fs::read(&key)?;
            let signed = rim::sign(
                map,
                &priv_pem,
                alg,
                kid.into_bytes(),
                signer_name,
                parse_time(&not_after)?,
            )?;
            let bytes = rim::encode_any(&ConciseRimTypeChoice::Signed(signed.into()))?;
            write_file(&out, &bytes)?;
            println!("wrote signed CoRIM {} ({})", out.display(), bytes.len());
            Ok(())
        }
        RimCmd::Verify { file, key } => {
            let bytes = std::fs::read(&file)?;
            let pub_pem = std::fs::read(&key)?;
            rim::verify(&bytes, &pub_pem)?;
            println!("signature valid");
            Ok(())
        }
        RimCmd::Show { file } => {
            let bytes = std::fs::read(&file)?;
            match rim::decode_any(&bytes)? {
                ConciseRimTypeChoice::Unsigned(t) => {
                    let map = t.unwrap();
                    println!("form:      unsigned (#6.501)");
                    println!(
                        "id:        {}",
                        match &map.id {
                            CorimIdDisplay::Tstr(s) => s.to_string(),
                            CorimIdDisplay::Uuid(u) => uuid_display(u),
                            _ => "<extension>".into(),
                        }
                    );
                    println!("tags:      {}", map.tags.len());
                    for t in &map.tags {
                        match t {
                            ConciseTagTypeChoice::Tl(cotl_tag) => {
                                println!("  [CoTL] {}", cotl::summarize(&cotl_tag.0.0));
                            }
                            ConciseTagTypeChoice::Mid(_) => println!("  [CoMID]"),
                            ConciseTagTypeChoice::Swid(_) => println!("  [CoSWID]"),
                            ConciseTagTypeChoice::Extension(_) => println!("  [extension]"),
                        }
                    }
                }
                ConciseRimTypeChoice::Signed(t) => {
                    let signed = t.unwrap();
                    println!("form:      signed (COSE_Sign1 #6.18)");
                    println!("algorithm: {:?}", signed.alg);
                    let name = match &signed.meta.signer.signer_name {
                        corim_rs::EntityNameTypeChoice::Text(t) => t.to_string(),
                        _ => "<extension>".to_owned(),
                    };
                    println!("signer:    {name}");
                }
            }
            Ok(())
        }
    }
}

// Small helpers ---------------------------------------------------------

fn write_file(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

fn load_cotl(path: &PathBuf) -> anyhow::Result<corim_rs::ConciseTlTag<'static>> {
    let bytes = std::fs::read(path)?;
    Ok(cotl::decode(&bytes)?)
}

/// Parses Unix seconds or RFC 3339 timestamps.
fn parse_time(s: &str) -> anyhow::Result<i64> {
    if let Ok(secs) = i64::from_str(s) {
        return Ok(secs);
    }
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|e| anyhow::anyhow!("invalid timestamp \"{s}\": {e}"))?;
    Ok(dt.timestamp())
}

mod interactive;

use corim_rs::CorimIdTypeChoice as CorimIdDisplay;
use corim_rs::UuidType as UuidValueType;

fn uuid_display(u: &UuidValueType) -> String {
    let bytes: [u8; 16] = u.0.0;
    uuid::Uuid::from_bytes(bytes).to_string()
}
