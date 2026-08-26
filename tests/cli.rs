//! End-to-end CLI integration tests exercising the full CoTL/CoRIM lifecycle.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_cotlme")
}

fn run(args: &[&str]) -> (String, String, bool) {
    let out = Command::new(bin()).args(args).output().expect("spawn");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("cotlme-it-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn path(&self, f: &str) -> String {
        self.0.join(f).to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const FAR_FUTURE: &str = "2100-01-01T00:00:00Z";

#[test]
fn keygen_produces_usable_pem_pair() {
    let t = TempDir::new("keygen");
    let (out, _, ok) = run(&[
        "keygen",
        "-c",
        "p384",
        "--private-out",
        &t.path("k.pem"),
        "-P",
        &t.path("k.pub.pem"),
    ]);
    assert!(ok, "{out}");
    let priv_pem = std::fs::read(t.path("k.pem")).unwrap();
    assert!(priv_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn cotl_create_show_validate_lifecycle() {
    let t = TempDir::new("cotl");
    let cotl = t.path("t.cotl");
    let (_, _, ok) = run(&[
        "cotl",
        "create",
        "-i",
        "it-cotl",
        "-t",
        "123e4567-e89b-12d3-a456-426614174000",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    assert!(ok);

    let (show, _, ok) = run(&["cotl", "show", &cotl]);
    assert!(ok);
    assert!(show.contains("it-cotl"), "{show}");
    assert!(show.contains("1 tag(s)"));

    let (v, _, ok) = run(&["cotl", "validate", &cotl]);
    assert!(ok, "{v}");
    assert!(v.contains("valid"));
}

#[test]
fn cotl_validate_detects_expiry_via_as_of_time() {
    let t = TempDir::new("expiry");
    let cotl = t.path("t.cotl");
    let (_, _, ok) = run(&[
        "cotl",
        "create",
        "-i",
        "x",
        "-t",
        "some-tag",
        "--not-after",
        "1000000000",
        "-o",
        &cotl,
    ]);
    assert!(ok);

    // As-of 2001 the CoTL is valid; as-of now it is expired.
    let (v, err, ok) = run(&["cotl", "validate", &cotl, "--now", "999000000"]);
    assert!(ok, "{err}");
    assert!(v.contains("valid"));

    let (_, err, ok) = run(&["cotl", "validate", &cotl]);
    assert!(!ok);
    assert!(err.contains("expired"), "{err}");
}

#[test]
fn cotl_create_rejects_empty_tag_list_and_bad_time() {
    let t = TempDir::new("reject");
    // clap requires at least one --tag.
    let (_, _, ok) = run(&[
        "cotl",
        "create",
        "-i",
        "x",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &t.path("nope.cotl"),
    ]);
    assert!(!ok);

    let (_, err, ok) = run(&[
        "cotl",
        "create",
        "-i",
        "x",
        "-t",
        "tag",
        "--not-after",
        "not-a-time",
        "-o",
        &t.path("nope.cotl"),
    ]);
    assert!(!ok);
    assert!(err.contains("invalid timestamp"), "{err}");
}

#[test]
fn full_signing_roundtrip_and_tamper_detection() {
    for curve in ["p256", "p384", "p521"] {
        let name = format!("roundtrip-{curve}");
        let t = TempDir::new(&name);
        let k = t.path("k.pem");
        let kp = t.path("k.pub.pem");
        let cotl = t.path("t.cotl");
        let unsigned = t.path("u.corim");
        let signed = t.path("s.corim");

        let (_, e, ok) = run(&["keygen", "-c", curve, "--private-out", &k, "-P", &kp]);
        assert!(ok, "{curve}: {e}");

        let (_, e, ok) = run(&[
            "cotl",
            "create",
            "-i",
            "id",
            "-t",
            "tag-a",
            "-t",
            "tag-b",
            "--not-after",
            FAR_FUTURE,
            "-o",
            &cotl,
        ]);
        assert!(ok, "{curve}: {e}");

        let (_, e, ok) = run(&[
            "rim", "wrap", "--cotl", &cotl, "-i", "rim-id", "-o", &unsigned,
        ]);
        assert!(ok, "{curve}: {e}");

        let (_, e, ok) = run(&[
            "rim",
            "sign",
            "--input",
            &unsigned,
            "--key",
            &k,
            "-K",
            "kid",
            "-n",
            "ACME",
            "--not-after",
            FAR_FUTURE,
            "-o",
            &signed,
        ]);
        assert!(ok, "{curve}: {e}");

        let (out, e, ok) = run(&["rim", "verify", &signed, "--key", &kp]);
        assert!(ok, "{curve}: verify failed: {out} {e}");
        assert!(out.contains("signature valid"));

        // Tampering invalidates the signature.
        let mut bytes = std::fs::read(&signed).unwrap();
        let n = bytes.len();
        bytes[n - 3] ^= 0xAA;
        std::fs::write(&signed, bytes).unwrap();
        let (_, _, ok) = run(&["rim", "verify", &signed, "--key", &kp]);
        assert!(!ok, "{curve}: tampered payload still verified");
    }
}

#[test]
fn rim_verify_rejects_wrong_key() {
    let t = TempDir::new("wrongkey");
    let k1 = t.path("k1.pem");
    let k2pub = t.path("k2.pub.pem");
    let cotl = t.path("t.cotl");
    let unsigned = t.path("u.corim");
    let signed = t.path("s.corim");

    run(&["keygen", "--private-out", &k1, "-P", &t.path("k1.pub.pem")]);
    run(&["keygen", "--private-out", &t.path("k2.pem"), "-P", &k2pub]);
    run(&[
        "cotl",
        "create",
        "-i",
        "id",
        "-t",
        "tag",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    run(&["rim", "wrap", "--cotl", &cotl, "-i", "r", "-o", &unsigned]);
    run(&[
        "rim",
        "sign",
        "--input",
        &unsigned,
        "--key",
        &k1,
        "--not-after",
        FAR_FUTURE,
        "-o",
        &signed,
    ]);

    let (_, err, ok) = run(&["rim", "verify", &signed, "--key", &k2pub]);
    assert!(!ok);
    assert!(!err.is_empty());
}

#[test]
fn rim_sign_rejects_already_signed_input() {
    let t = TempDir::new("resign");
    let k = t.path("k.pem");
    let cotl = t.path("t.cotl");
    let unsigned = t.path("u.corim");
    let signed = t.path("s.corim");

    run(&["keygen", "--private-out", &k, "-P", &t.path("k.pub.pem")]);
    run(&[
        "cotl",
        "create",
        "-i",
        "id",
        "-t",
        "tag",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    run(&["rim", "wrap", "--cotl", &cotl, "-i", "r", "-o", &unsigned]);
    run(&[
        "rim",
        "sign",
        "--input",
        &unsigned,
        "--key",
        &k,
        "--not-after",
        FAR_FUTURE,
        "-o",
        &signed,
    ]);

    let (_, err, ok) = run(&[
        "rim",
        "sign",
        "--input",
        &signed,
        "--key",
        &k,
        "--not-after",
        FAR_FUTURE,
        "-o",
        &t.path("again.corim"),
    ]);
    assert!(!ok);
    assert!(err.contains("already signed"), "{err}");
}

#[test]
fn rim_show_reports_both_forms() {
    let t = TempDir::new("show");
    let k = t.path("k.pem");
    let kp = t.path("k.pub.pem");
    let cotl = t.path("t.cotl");
    let unsigned = t.path("u.corim");
    let signed = t.path("s.corim");

    run(&["keygen", "--private-out", &k, "-P", &kp]);
    run(&[
        "cotl",
        "create",
        "-i",
        "list-id",
        "-t",
        "tag",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    run(&[
        "rim", "wrap", "--cotl", &cotl, "-i", "rim-id", "-o", &unsigned,
    ]);

    let (out, _, ok) = run(&["rim", "show", &unsigned]);
    assert!(ok);
    assert!(out.contains("unsigned (#6.501)"), "{out}");
    assert!(out.contains("[CoTL]"), "{out}");
    assert!(out.contains("list-id"));

    run(&[
        "rim",
        "sign",
        "--input",
        &unsigned,
        "--key",
        &k,
        "-n",
        "Zeta Corp",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &signed,
    ]);
    let (out, _, ok) = run(&["rim", "show", &signed]);
    assert!(ok);
    assert!(out.contains("COSE_Sign1 #6.18"), "{out}");
    assert!(out.contains("ES256"), "{out}");
    assert!(out.contains("Zeta Corp"), "{out}");
}

#[test]
fn show_on_garbage_file_fails_gracefully() {
    let t = TempDir::new("garbage");
    let g = t.path("g.bin");
    std::fs::write(&g, b"this is not cbor").unwrap();
    let (_, err, ok) = run(&["cotl", "show", &g]);
    assert!(!ok);
    assert!(!err.is_empty());

    let (_, err, ok) = run(&["rim", "show", &g]);
    assert!(!ok);
    assert!(err.contains("error:"), "{err}");
}

#[test]
fn uuid_ids_roundtrip_through_the_cli() {
    let t = TempDir::new("uuid");
    let u = "123e4567-e89b-12d3-a456-426614174000";
    let cotl = t.path("t.cotl");
    let (_, _, ok) = run(&[
        "cotl",
        "create",
        "-i",
        u,
        "-t",
        u,
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    assert!(ok);
    let (out, _, ok) = run(&["cotl", "show", &cotl]);
    assert!(ok);
    assert_eq!(out.matches(u).count(), 2, "{out}");
}

// ---- Edge-case CLI tests ------------------------------------------------

#[test]
fn missing_input_files_fail_cleanly() {
    let t = TempDir::new("missing");
    let (_, err, ok) = run(&["cotl", "show", &t.path("nope.cotl")]);
    assert!(!ok);
    assert!(err.contains("error:"), "{err}");

    let (_, err, ok) = run(&[
        "rim",
        "verify",
        &t.path("nope.corim"),
        "--key",
        &t.path("k.pem"),
    ]);
    assert!(!ok);
    assert!(err.contains("error:"), "{err}");

    let (_, _, ok) = run(&[
        "rim",
        "wrap",
        "--cotl",
        &t.path("nope.cotl"),
        "-i",
        "x",
        "-o",
        &t.path("o.corim"),
    ]);
    assert!(!ok);
}

#[test]
fn not_before_window_is_reported_via_cli() {
    let t = TempDir::new("notbefore");
    let cotl = t.path("t.cotl");
    let (_, _, ok) = run(&[
        "cotl",
        "create",
        "-i",
        "future-list",
        "-t",
        "tag",
        "--not-before",
        "4102444800", // 2100-01-01
        "--not-after",
        "4202444800",
        "-o",
        &cotl,
    ]);
    assert!(ok);

    // Valid structure, but not yet active: warning + still "valid".
    let (out, _, ok) = run(&["cotl", "validate", &cotl]);
    assert!(ok, "{out}");
    assert!(out.contains("not yet valid"), "{out}");
    assert!(out.contains("valid"));
}

#[test]
fn version_flag_roundtrips_through_cli() {
    let t = TempDir::new("version");
    let cotl = t.path("t.cotl");
    let (_, e, ok) = run(&[
        "cotl",
        "create",
        "-i",
        "v-list",
        "--version",
        "42",
        "-t",
        "tag",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    assert!(ok, "{e}");
    let (out, _, ok) = run(&["cotl", "show", &cotl]);
    assert!(ok);
    assert!(out.contains("tag-version:  42"), "{out}");
}

#[test]
fn duplicate_tags_warn_through_cli_validate() {
    let t = TempDir::new("dupes");
    let cotl = t.path("t.cotl");
    let (_, _, ok) = run(&[
        "cotl",
        "create",
        "-i",
        "d",
        "-t",
        "same-tag",
        "-t",
        "same-tag",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    assert!(ok);
    let (out, _, ok) = run(&["cotl", "validate", &cotl]);
    assert!(ok);
    assert!(out.contains("duplicate"), "{out}");
}

#[test]
fn keygen_refuses_to_be_quiet_about_bad_curve_and_overwrites() {
    let t = TempDir::new("badcurve");
    let (_, err, ok) = run(&[
        "keygen",
        "-c",
        "p999",
        "--private-out",
        &t.path("a"),
        "-P",
        &t.path("b"),
    ]);
    assert!(!ok);
    assert!(!err.is_empty());
}

#[test]
fn rim_wrap_rejects_signed_cotl_garbage() {
    let t = TempDir::new("wrapgarbage");
    let bad = t.path("bad.cotl");
    std::fs::write(&bad, b"\xd8\x1a\x44\x33").unwrap(); // tag 26 w/ junk
    let (_, _, ok) = run(&["rim", "wrap", "--cotl", &bad, "-i", "x", "-o", &t.path("o")]);
    assert!(!ok);
}

#[test]
fn sign_with_missing_key_fails_cleanly() {
    let t = TempDir::new("nokey");
    let k = t.path("k.pem");
    let kp = t.path("k.pub.pem");
    let cotl = t.path("t.cotl");
    let unsigned = t.path("u.corim");
    run(&["keygen", "--private-out", &k, "-P", &kp]);
    run(&[
        "cotl",
        "create",
        "-i",
        "i",
        "-t",
        "t",
        "--not-after",
        FAR_FUTURE,
        "-o",
        &cotl,
    ]);
    run(&["rim", "wrap", "--cotl", &cotl, "-i", "r", "-o", &unsigned]);

    let (_, err, ok) = run(&[
        "rim",
        "sign",
        "--input",
        &unsigned,
        "--key",
        &t.path("does-not-exist.pem"),
        "--not-after",
        FAR_FUTURE,
        "-o",
        &t.path("s.corim"),
    ]);
    assert!(!ok);
    assert!(err.contains("error:"), "{err}");
}
