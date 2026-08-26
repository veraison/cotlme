//! # cotlme
//!
//! A stupid-simple, extremely powerful tool for working with Concise Tag
//! Lists (CoTLs) and Concise Reference Integrity Manifests (CoRIMs) as
//! specified in `draft-ietf-rats-corim-11`.
//!
//! The library exposes three focused modules:
//!
//! * [`cotl`] — build, encode, decode, validate, and summarize CoTL tags.
//! * [`rim`] — wrap CoTLs in unsigned/signed CoRIMs and verify signatures.
//! * [`keys`] — EC keypair generation for COSE signing.

pub mod cotl;
pub mod error;
pub mod keys;
pub mod rim;
