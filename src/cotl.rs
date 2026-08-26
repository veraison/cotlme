//! Concise Tag List (CoTL) creation, encoding, decoding, and validation.
//!
//! A CoTL (`concise-tl-tag`, CBOR tag 508) activates a set of CoMID/CoSWID
//! tags for use in Evidence appraisal, per draft-ietf-rats-corim-11 Section 6.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use corim_rs::{
    ConciseTlTag, Integer, IntegerTime, TagIdTypeChoice, TagIdentityMap, UuidType, ValidityMap,
};
use uuid::Uuid;

use crate::error::{Error, Result};

/// Identifier for a tag referenced by (or identifying) a CoTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagId {
    /// A text identifier.
    Text(String),
    /// A UUID identifier.
    Uuid(Uuid),
}

impl TagId {
    /// Parses `s` as a UUID if possible, otherwise treats it as text.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match Uuid::from_str(s) {
            Ok(uuid) => Self::Uuid(uuid),
            Err(_) => Self::Text(s.to_owned()),
        }
    }

    /// Returns the string form of this identifier.
    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Uuid(u) => u.to_string(),
        }
    }

    fn to_choice(&self) -> TagIdTypeChoice<'static> {
        match self {
            Self::Text(s) => TagIdTypeChoice::Tstr(s.clone().into()),
            Self::Uuid(u) => TagIdTypeChoice::Uuid(UuidType::from(u.into_bytes())),
        }
    }
}

/// High-level description of a CoTL used for construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CotlSpec {
    /// Identity of the CoTL itself.
    pub id: TagId,
    /// Optional version of the CoTL tag.
    pub version: Option<Integer>,
    /// The tags activated by this CoTL. Activation is atomic.
    pub tags: Vec<TagId>,
    /// Optional start of the validity window (Unix seconds).
    pub not_before: Option<i64>,
    /// End of the validity window (Unix seconds). Required by the spec.
    pub not_after: i64,
}

impl CotlSpec {
    /// Builds the concrete [`ConciseTlTag`] from this specification.
    ///
    /// # Errors
    /// Returns an error if no tags are listed or the validity window is
    /// inverted, matching the constraints in Section 6.1 of the draft.
    pub fn build(&self) -> Result<ConciseTlTag<'static>> {
        if self.tags.is_empty() {
            return Err(Error::custom(
                "tags-list must contain at least one tag identity",
            ));
        }
        if let Some(nb) = self.not_before
            && nb >= self.not_after
        {
            return Err(Error::custom(
                "not-before must be strictly earlier than not-after",
            ));
        }

        let tag_identity = TagIdentityMap {
            tag_id: self.id.to_choice(),
            tag_version: self.version,
        };
        let tags_list = self
            .tags
            .iter()
            .map(|t| TagIdentityMap {
                tag_id: t.to_choice(),
                tag_version: None,
            })
            .collect();

        let mut validity = ValidityMap {
            not_before: None,
            not_after: IntegerTime::from(self.not_after),
        };
        if let Some(nb) = self.not_before {
            validity.not_before = Some(IntegerTime::from(nb));
        }

        Ok(ConciseTlTag {
            tag_identity,
            tags_list,
            tl_validity: validity,
        })
    }
}

/// Encodes a CoTL as CBOR bytes wrapped in CBOR tag 508.
///
/// Per draft-ietf-rats-corim-11 Appendix A, the conformant wire form is
/// `#6.508(bytes .cbor concise-tl-tag)` — the enclosed map MUST be carried
/// in a byte string.
///
/// # Errors
/// Returns an error if CBOR serialization fails.
pub fn encode(cotl: &ConciseTlTag<'_>) -> Result<Vec<u8>> {
    let mut inner = Vec::new();
    ciborium::into_writer(cotl, &mut inner).map_err(|e| Error::custom(e.to_string()))?;

    let tagged = ciborium::value::Value::Tag(508, Box::new(ciborium::value::Value::Bytes(inner)));
    let mut buf = Vec::new();
    ciborium::into_writer(&tagged, &mut buf).map_err(|e| Error::custom(e.to_string()))?;
    Ok(buf)
}

/// Decodes CBOR bytes (with or without tag 508) into a [`ConciseTlTag`].
///
/// # Errors
/// Returns an error if the bytes are not valid CBOR or do not describe a
/// well-formed CoTL structure.
pub fn decode(bytes: &[u8]) -> Result<ConciseTlTag<'static>> {
    let raw: ciborium::value::Value = ciborium::from_reader(&mut &bytes[..])
        .map_err(|e| Error::custom(format!("not valid CBOR: {e}")))?;

    match raw {
        // Conformant form: #6.508(bytes .cbor concise-tl-tag).
        ciborium::value::Value::Tag(508, inner) => {
            if let ciborium::value::Value::Bytes(content) = *inner {
                return ciborium::from_reader::<ConciseTlTag, _>(&mut &content[..])
                    .map_err(|e| Error::custom(format!("not a valid CoTL: {e}")));
            }
            // Legacy (non-conformant) form emitted by corim-rs: the bare
            // map inline under the tag.
            let mut legacy = Vec::new();
            ciborium::into_writer(&*inner, &mut legacy)
                .map_err(|e| Error::custom(e.to_string()))?;
            ciborium::from_reader::<ConciseTlTag, _>(&mut &legacy[..])
                .map_err(|e| Error::custom(format!("not a valid CoTL: {e}")))
        }
        // Untagged bare map.
        _ => ciborium::from_reader::<ConciseTlTag, _>(&mut &bytes[..])
            .map_err(|e| Error::custom(format!("not a valid CoTL: {e}"))),
    }
}

/// Outcome of validating a CoTL against a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// Human-readable problems that make the CoTL invalid.
    pub errors: Vec<String>,
    /// Human-readable warnings that do not invalidate the CoTL.
    pub warnings: Vec<String>,
}

impl ValidationReport {
    /// True when there are no validation errors.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validates structural and temporal properties of a CoTL at time `now`.
///
/// Checks performed (per Sections 6.1, 7.3 and 8.2.3.4):
/// * `tags-list` is non-empty (atomic activation requires it).
/// * `tl-validity.not_after` is present and in the future.
/// * `tl-validity.not_before`, when present, is in the past.
/// * `not_before < not_after`.
#[must_use]
pub fn validate(cotl: &ConciseTlTag<'_>, now: DateTime<Utc>) -> ValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if cotl.tags_list.is_empty() {
        errors.push("tags-list is empty; a CoTL must activate at least one tag".to_owned());
    }

    let now_secs = i128::from(now.timestamp());
    let not_after = cotl.tl_validity.not_after.as_i128();
    if let Some(nb) = &cotl.tl_validity.not_before {
        let nb = nb.as_i128();
        if nb >= not_after {
            errors.push("validity window is inverted (not-before >= not-after)".to_owned());
        } else if now_secs < nb {
            warnings.push(format!(
                "CoTL is not yet valid (not-before {nb} is in the future)"
            ));
        }
    }

    if now_secs > not_after {
        errors.push(format!(
            "CoTL has expired (not-after {not_after} is in the past)"
        ));
    }

    // Warn about duplicate entries in the activation list.
    let mut seen: Vec<String> = Vec::new();
    for t in &cotl.tags_list {
        let id = tag_id_string(&t.tag_id);
        if seen.contains(&id) {
            warnings.push(format!("duplicate tag-id in tags-list: {id}"));
        } else {
            seen.push(id);
        }
    }

    ValidationReport { errors, warnings }
}

/// Renders a [`TagIdTypeChoice`] to its canonical string form.
#[must_use]
pub fn tag_id_string(id: &TagIdTypeChoice<'_>) -> String {
    match id {
        TagIdTypeChoice::Tstr(t) => t.to_string(),
        TagIdTypeChoice::Uuid(u) => {
            let bytes: [u8; 16] = u.0.0;
            Uuid::from_bytes(bytes).to_string()
        }
        TagIdTypeChoice::Extension(_) => "<extension>".to_owned(),
    }
}

/// Builds a compact human-readable summary of a CoTL.
#[must_use]
pub fn summarize(cotl: &ConciseTlTag<'_>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "tag-id:       {}\n",
        tag_id_string(&cotl.tag_identity.tag_id)
    ));
    if let Some(v) = cotl.tag_identity.tag_version {
        out.push_str(&format!("tag-version:  {v}\n"));
    }
    out.push_str(&format!("tags-list:    {} tag(s)\n", cotl.tags_list.len()));
    for t in &cotl.tags_list {
        out.push_str(&format!("  - {}\n", tag_id_string(&t.tag_id)));
    }
    out.push_str(&format!(
        "not-after:    {}\n",
        cotl.tl_validity.not_after.as_i128()
    ));
    if let Some(nb) = &cotl.tl_validity.not_before {
        out.push_str(&format!("not-before:   {}\n", nb.as_i128()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01
    const NEAR_PAST: i64 = 1_600_000_000; // 2020-09-13

    fn spec() -> CotlSpec {
        CotlSpec {
            id: TagId::parse("example-cotl"),
            version: Some(Integer::new(1)),
            tags: vec![TagId::parse("11111111-2222-3333-4444-555555555555")],
            not_before: Some(NEAR_PAST),
            not_after: FAR_FUTURE,
        }
    }

    #[test]
    fn build_produces_expected_structure() {
        let cotl = spec().build().unwrap();
        assert!(matches!(cotl.tag_identity.tag_id, TagIdTypeChoice::Tstr(_)));
        assert_eq!(cotl.tag_identity.tag_version, Some(Integer::ONE));
        assert_eq!(cotl.tags_list.len(), 1);
        assert_eq!(cotl.tl_validity.not_after.as_i128(), i128::from(FAR_FUTURE));
        assert_eq!(
            cotl.tl_validity.not_before.as_ref().unwrap().as_i128(),
            i128::from(NEAR_PAST)
        );
    }

    #[test]
    fn build_uuid_roundtrip_preserves_bytes() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let cotl = CotlSpec {
            id: TagId::parse(uuid),
            ..spec()
        }
        .build()
        .unwrap();
        assert_eq!(tag_id_string(&cotl.tag_identity.tag_id), uuid);
    }

    #[test]
    fn build_rejects_empty_tags_list() {
        let mut s = spec();
        s.tags.clear();
        assert!(s.build().is_err());
    }

    #[test]
    fn build_rejects_inverted_validity() {
        let mut s = spec();
        s.not_after = NEAR_PAST - 1;
        assert!(s.build().is_err());
    }

    #[test]
    fn build_rejects_equal_bounds() {
        let mut s = spec();
        s.not_before = Some(FAR_FUTURE);
        s.not_after = FAR_FUTURE;
        assert!(s.build().is_err());
    }

    #[test]
    fn cbor_roundtrip_with_tag() {
        let cotl = spec().build().unwrap();
        let bytes = encode(&cotl).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(cotl, decoded);
    }

    #[test]
    fn cbor_roundtrip_untagged_accepted() {
        let cotl = spec().build().unwrap();
        let mut untagged = Vec::new();
        ciborium::into_writer(&cotl, &mut untagged).unwrap();
        let decoded = decode(&untagged).unwrap();
        assert_eq!(cotl, decoded);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(b"\xff\xff\xff").is_err());
    }

    #[test]
    fn validate_ok_when_within_window() {
        let report = validate(&spec().build().unwrap(), Utc::now());
        assert!(report.is_valid(), "{report:?}");
        assert!(report.warnings.is_empty(), "{report:?}");
    }

    #[test]
    fn validate_fails_when_expired() {
        let report = validate(&spec().build().unwrap(), far_future_dt());
        assert!(!report.is_valid());
        assert!(report.errors[0].contains("expired"));
    }

    #[test]
    fn validate_warns_when_not_yet_valid() {
        let mut s = spec();
        s.not_before = Some(FAR_FUTURE);
        s.not_after = FAR_FUTURE + 10_000;
        let report = validate(&s.build().unwrap(), Utc::now());
        assert!(report.is_valid());
        assert!(report.warnings.iter().any(|w| w.contains("not yet valid")));
    }

    #[test]
    fn validate_fails_on_empty_tags_list() {
        let mut cotl = spec().build().unwrap();
        cotl.tags_list.clear();
        let report = validate(&cotl, Utc::now());
        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|e| e.contains("empty")));
    }

    #[test]
    fn validate_warns_on_duplicates() {
        let mut s = spec();
        let t = s.tags[0].clone();
        s.tags.push(t);
        let report = validate(&s.build().unwrap(), Utc::now());
        assert!(report.is_valid());
        assert!(report.warnings.iter().any(|w| w.contains("duplicate")));
    }

    #[test]
    fn summarize_contains_key_fields() {
        let summary = summarize(&spec().build().unwrap());
        assert!(summary.contains("example-cotl"));
        assert!(summary.contains("1 tag(s)"));
    }

    fn far_future_dt() -> DateTime<Utc> {
        DateTime::from_timestamp(FAR_FUTURE + 1_000_000, 0).unwrap()
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;

    #[test]
    fn parse_uuid_detection_is_exact() {
        // The canonical and URN forms are both accepted by the UUID parser;
        // this is deliberate so draft-recommended `urn:uuid:` references
        // (Section 4.3.1) work verbatim.
        assert!(matches!(
            TagId::parse("urn:uuid:123e4567-e89b-12d3-a456-426614174000"),
            TagId::Uuid(_)
        ));
        assert!(matches!(
            TagId::parse("123E4567-E89B-12D3-A456-426614174000"),
            TagId::Uuid(_)
        )); // uppercase accepted by the parser
        assert!(matches!(
            TagId::parse("123e4567e89b12d3a456426614174000"),
            TagId::Uuid(_)
        ));
        // Near-misses must stay text.
        assert!(matches!(
            TagId::parse("123e4567-e89b-12d3-a456-42661417400g"),
            TagId::Text(_)
        ));
        assert!(matches!(
            TagId::parse("123e4567-e89b-12d3-a456"),
            TagId::Text(_)
        ));
        assert!(matches!(TagId::parse(""), TagId::Text(_)));
        assert!(matches!(
            TagId::parse("123e4567-e89b-12d3-a456-4266141740000"),
            TagId::Text(_)
        ));
    }

    #[test]
    fn tag_id_as_string_roundtrips_both_forms() {
        assert_eq!(TagId::Text("abc".into()).as_string(), "abc");
        let u = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        assert_eq!(
            TagId::Uuid(u).as_string(),
            "123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn build_preserves_tag_order() {
        let s = CotlSpec {
            id: TagId::parse("id"),
            version: None,
            tags: vec![
                TagId::parse("zeta"),
                TagId::parse("alpha"),
                TagId::parse("mid"),
            ],
            not_before: None,
            not_after: 1,
        };
        let cotl = s.build().unwrap();
        let ids: Vec<String> = cotl
            .tags_list
            .iter()
            .map(|t| tag_id_string(&t.tag_id))
            .collect();
        assert_eq!(ids, vec!["zeta", "alpha", "mid"]);
    }

    #[test]
    fn cbor_roundtrip_with_version_set() {
        let mut s = CotlSpec {
            id: TagId::parse("id"),
            version: Some(Integer::new(42)),
            tags: vec![TagId::parse("t")],
            not_before: Some(1),
            not_after: 2,
        };
        s.version = Some(Integer::new(42));
        let cotl = s.build().unwrap();
        let decoded = decode(&encode(&cotl).unwrap()).unwrap();
        assert_eq!(decoded.tag_identity.tag_version, Some(Integer::new(42)));
    }

    #[test]
    fn json_human_readable_roundtrip() {
        let cotl = CotlSpec {
            id: TagId::parse("json-id"),
            version: Some(Integer::new(7)),
            tags: vec![TagId::parse("tag-one")],
            not_before: None,
            not_after: 100,
        }
        .build()
        .unwrap();
        let json = serde_json::to_string(&cotl).unwrap();
        assert!(json.contains("\"tag-id\""));
        let back: ConciseTlTag = serde_json::from_str(&json).unwrap();
        assert_eq!(cotl, back);
    }

    #[test]
    fn json_rejects_unknown_fields() {
        let err = serde_json::from_str::<ConciseTlTag>(r#"{"bogus": 1}"#);
        assert!(err.is_err());
    }

    #[test]
    fn decode_rejects_wrong_cbor_tag_number() {
        // Build a valid CoTL, re-wrap it with the WRONG tag (505 = CoSWID).
        let cotl = CotlSpec {
            id: TagId::parse("x"),
            version: None,
            tags: vec![TagId::parse("t")],
            not_before: None,
            not_after: 1,
        }
        .build()
        .unwrap();
        let mut inner = Vec::new();
        ciborium::into_writer(&cotl, &mut inner).unwrap();
        let mut buf = Vec::new();
        ciborium::into_writer(
            &ciborium::value::Value::Tag(505, Box::new(ciborium::value::Value::Bytes(inner))),
            &mut buf,
        )
        .unwrap();
        assert!(decode(&buf).is_err(), "wrong tag number must be rejected");
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let full = encode(
            &CotlSpec {
                id: TagId::parse("x"),
                version: None,
                tags: vec![TagId::parse("t")],
                not_before: None,
                not_after: 1,
            }
            .build()
            .unwrap(),
        )
        .unwrap();
        for cut in [0usize, 1, 3, full.len() / 2, full.len() - 1] {
            assert!(
                decode(&full[..cut]).is_err(),
                "truncation at {cut} should fail"
            );
        }
    }

    /// Fuzz-lite: decode must never panic on arbitrary input.
    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        // Deterministic LCG so failures are reproducible.
        let mut state: u64 = 0xDEADBEEF;
        let mut buf = Vec::with_capacity(256);
        for _ in 0..2_000 {
            buf.clear();
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 33) as usize % 64;
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                buf.push((state >> 33) as u8);
            }
            let _ = decode(&buf); // may Err, must not panic
        }
    }

    #[test]
    fn validate_boundary_now_equals_not_after_is_still_valid() {
        // Validity windows are INCLUSIVE of not-after (RFC 5280 convention).
        let cotl = CotlSpec {
            id: TagId::parse("x"),
            version: None,
            tags: vec![TagId::parse("t")],
            not_before: None,
            not_after: 5000,
        }
        .build()
        .unwrap();
        let dt = chrono::DateTime::from_timestamp(5000, 0).unwrap();
        let report = validate(&cotl, dt);
        assert!(report.is_valid(), "not-after is inclusive");
    }

    #[test]
    fn validate_boundary_one_second_before_not_after_is_valid() {
        let cotl = CotlSpec {
            id: TagId::parse("x"),
            version: None,
            tags: vec![TagId::parse("t")],
            not_before: None,
            not_after: 5000,
        }
        .build()
        .unwrap();
        let dt = chrono::DateTime::from_timestamp(4999, 0).unwrap();
        assert!(validate(&cotl, dt).is_valid());
    }

    #[test]
    fn validate_boundary_not_before_equal_to_now_is_active() {
        let cotl = CotlSpec {
            id: TagId::parse("x"),
            version: None,
            tags: vec![TagId::parse("t")],
            not_before: Some(100),
            not_after: 200,
        }
        .build()
        .unwrap();
        let dt = chrono::DateTime::from_timestamp(100, 0).unwrap();
        let report = validate(&cotl, dt);
        assert!(report.is_valid());
        assert!(report.warnings.is_empty(), "not-before is inclusive");
    }

    #[test]
    fn build_allows_far_future_extremes_but_rejects_negative_inversion() {
        let ok = CotlSpec {
            id: TagId::parse("x"),
            version: None,
            tags: vec![TagId::parse("t")],
            not_before: Some(i64::MAX / 2),
            not_after: i64::MAX,
        };
        assert!(ok.build().is_ok());

        let bad = CotlSpec {
            not_before: Some(-10),
            not_after: -20,
            ..ok
        };
        assert!(bad.build().is_err());
    }

    #[test]
    fn summarize_handles_missing_optional_fields() {
        let cotl = CotlSpec {
            id: TagId::parse("bare"),
            version: None,
            tags: vec![TagId::parse("t")],
            not_before: None,
            not_after: 5,
        }
        .build()
        .unwrap();
        let summary = summarize(&cotl);
        assert!(!summary.contains("tag-version"));
        assert!(!summary.contains("not-before"));
    }

    #[test]
    fn duplicate_warning_lists_every_dupe() {
        let cotl = ConciseTlTag {
            tag_identity: TagIdentityMap {
                tag_id: TagId::parse("x").to_choice(),
                tag_version: None,
            },
            tags_list: vec![
                TagIdentityMap {
                    tag_id: TagId::parse("dup").to_choice(),
                    tag_version: None,
                },
                TagIdentityMap {
                    tag_id: TagId::parse("dup").to_choice(),
                    tag_version: None,
                },
                TagIdentityMap {
                    tag_id: TagId::parse("dup").to_choice(),
                    tag_version: None,
                },
            ],
            tl_validity: ValidityMap {
                not_before: None,
                not_after: IntegerTime::from(10),
            },
        };
        let report = validate(&cotl, chrono::DateTime::from_timestamp(0, 0).unwrap());
        assert_eq!(
            report
                .warnings
                .iter()
                .filter(|w| w.contains("duplicate"))
                .count(),
            2
        );
    }
}
