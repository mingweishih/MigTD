// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! CoRIM-based implementation of [`ServtdProvider`], decoding the wire format
//! produced by the host-side `mig-td-tools` signer.
//!
//! # Two documents
//!
//! The producer emits **two** independent signed CoRIMs, both of which MigTD
//! carries in its CFV:
//!
//! * **TCB Mapping CoRIM** — `SERVTD_INFO_HASH -> isvsvn`. Each authorized
//!   release contributes two triples in the `servtd-hash` environment:
//!   * a `reference-triple` whose single `MeasurementMap.mval.digests[0]` is
//!     the ServTD info hash (authenticity), and
//!   * a `conditional-endorsement-series` (CES) triple whose series record
//!     *selects* on that digest and *adds* `mval.svn = ExactValue(svn)`.
//!   The hash -> svn lookup is driven by the CES triples.
//!
//! * **TD Identity CoRIM** — `isvsvn -> (tcb_date, tcb_status)`. A single
//!   `reference-triple` in the `svn-tcb` environment carrying one
//!   `MeasurementMap` per SVN, keyed by `mkey = Uint(svn)`, with
//!   `mval.extra_entries[MVAL_TEE_TCBDATE]` (CBOR `#6.1(epoch-seconds)`) and
//!   `mval.extra_entries[MVAL_TEE_TCBSTATUS]` (text). Both keys are the
//!   Intel-profile extension keys exported by the `corim` crate
//!   (`tee.tcbdate` = -72, `tee.tcbstatus` = -88), not MigTD-local numbers.
//!
//! Both environments share one component
//! `class.class-id = Uuid(SERVTD_HASH_CLASS_UUID)` and are distinguished by
//! `environment.instance` (`"servtd-hash"` vs `"svn-tcb"`).
//!
//! # `no_std`
//!
//! Built `#![no_std]` in MigTD; decode uses
//! [`corim::validate::decode_and_validate_at`] (the `_at` variant) so no
//! `SystemTime` is touched. Signature verification of the surrounding
//! `COSE_Sign1` envelope is performed by the `crypto` crate before these
//! bytes are handed in; this module covers decode + match only.

use alloc::{
    format,
    string::String,
    vec::Vec,
};
use core::convert::TryFrom;

use corim::{
    profile::intel::{MVAL_TEE_TCBDATE, MVAL_TEE_TCBSTATUS},
    types::{
        comid::ComidTag,
        common::MeasuredElement,
        environment::EnvironmentMap,
        measurement::{MeasurementMap, SvnChoice},
        triples::ConditionalEndorsementSeriesTriple,
    },
    validate::decode_and_validate_at,
};

use crate::{
    v2::servtd_provider::{ServtdIdentity, ServtdLookup, ServtdProvider},
    PolicyError,
};

// ---- Wire-format constants (must match `mig-td-tools::types::servtd`) ------

/// Component class UUID shared by both the `servtd-hash` and `svn-tcb`
/// environments (`mig-td-tools`: `SERVTD_HASH_CLASS_UUID`).
pub const SERVTD_HASH_CLASS_UUID: [u8; 16] = [
    0x7f, 0xb0, 0x0e, 0xe4, 0xa7, 0xff, 0x11, 0xed, 0x9e, 0x2f, 0x00, 0x15, 0x5d, 0x09, 0xde, 0x56,
];

/// Instance bytes selecting the TCB Mapping environment.
pub const SERVTD_HASH_INSTANCE_BYTES: &[u8] = b"servtd-hash";

/// Instance bytes selecting the TD Identity environment.
pub const SVN_TCB_INSTANCE_BYTES: &[u8] = b"svn-tcb";

// `tcb_date` and `tcb_status` are carried under the Intel-profile extension
// keys re-exported from `corim::profile::intel`:
//   MVAL_TEE_TCBDATE   = -72  (`tee.tcbdate`,   CBOR #6.1(epoch-seconds))
//   MVAL_TEE_TCBSTATUS = -88  (`tee.tcbstatus`, text)
// No MigTD-local key numbers are defined here.

/// Decoded CoRIM servtd collateral: the TCB Mapping document (hash -> svn)
/// and the TD Identity document (svn -> tcb level).
pub struct ServtdCorim {
    /// CoMID tags from the TCB Mapping CoRIM (`servtd-hash` environment).
    tcb_mapping: Vec<ComidTag>,
    /// CoMID tags from the TD Identity CoRIM (`svn-tcb` environment).
    td_identity: Vec<ComidTag>,
}

impl ServtdCorim {
    /// Decode the two CoRIM blobs (CBOR, `#6.501` unsigned wrapper) and
    /// validate them structurally per draft-ietf-rats-corim-10.
    /// `now_epoch_secs` evaluates any embedded validity windows.
    ///
    /// Signature verification of the surrounding `COSE_Sign1` envelope is the
    /// caller's responsibility; these inputs are the inner payload bytes.
    pub fn decode(
        tcb_mapping_cbor: &[u8],
        td_identity_cbor: &[u8],
        now_epoch_secs: i64,
    ) -> Result<Self, PolicyError> {
        let (_c1, tcb_mapping) = decode_and_validate_at(tcb_mapping_cbor, now_epoch_secs)
            .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
        let (_c2, td_identity) = decode_and_validate_at(td_identity_cbor, now_epoch_secs)
            .map_err(|_| PolicyError::InvalidServtdIdentity)?;
        Ok(Self {
            tcb_mapping,
            td_identity,
        })
    }

    /// Resolve `SERVTD_INFO_HASH -> isvsvn` via the TCB Mapping CES triples.
    ///
    /// The digest is matched by **value** only; the producer currently labels
    /// the 48-byte SHA-384 ServTD info hash with the SHA-256 algorithm id
    /// (see the design-review gap note), so the algorithm field is not
    /// enforced here.
    fn svn_for_hash(&self, hash: &[u8]) -> Option<u16> {
        for comid in &self.tcb_mapping {
            let Some(ces_list) = comid.triples.conditional_endorsement_series.as_ref() else {
                continue;
            };
            for ces in ces_list {
                if let Some(svn) = ces_svn_for_hash(ces, hash) {
                    return Some(svn);
                }
            }
        }
        None
    }

    /// Resolve `isvsvn -> (tcb_date, tcb_status)` via the TD Identity table.
    fn level_for_svn(&self, svn: u16) -> Option<(String, String)> {
        for comid in &self.td_identity {
            let Some(refs) = comid.triples.reference_triples.as_ref() else {
                continue;
            };
            for triple in refs {
                if !is_svn_tcb_environment(triple.environment()) {
                    continue;
                }
                for meas in triple.measurements() {
                    if measurement_svn(meas) == Some(svn as u64) {
                        return measurement_level(meas);
                    }
                }
            }
        }
        None
    }

    /// Number of CoMID tags in each document. Exposed for diagnostics.
    pub fn comid_counts(&self) -> (usize, usize) {
        (self.tcb_mapping.len(), self.td_identity.len())
    }
}

impl ServtdProvider for ServtdCorim {
    fn lookup(&self, id: &ServtdIdentity) -> Option<ServtdLookup> {
        let hash = id.servtd_info_hash?;
        let isvsvn = self.svn_for_hash(hash)?;
        let (tcb_date, tcb_status) = self.level_for_svn(isvsvn)?;
        Some(ServtdLookup {
            isvsvn,
            tcb_date,
            tcb_status,
        })
    }
}

// ---- Environment matching --------------------------------------------------

fn is_servtd_hash_environment(env: &EnvironmentMap) -> bool {
    env_matches(env, SERVTD_HASH_INSTANCE_BYTES)
}

fn is_svn_tcb_environment(env: &EnvironmentMap) -> bool {
    env_matches(env, SVN_TCB_INSTANCE_BYTES)
}

fn env_matches(env: &EnvironmentMap, instance: &[u8]) -> bool {
    use corim::types::common::{ClassIdChoice, InstanceIdChoice};

    let class_ok = env
        .class
        .as_ref()
        .and_then(|c| c.class_id.as_ref())
        .map(|id| matches!(id, ClassIdChoice::Uuid(u) if *u == SERVTD_HASH_CLASS_UUID))
        .unwrap_or(false);

    let instance_ok = matches!(
        env.instance.as_ref(),
        Some(InstanceIdChoice::Bytes(b)) if b.as_slice() == instance
    );

    class_ok && instance_ok
}

// ---- TCB Mapping (CES) helpers --------------------------------------------

/// If this CES triple is in the `servtd-hash` environment and its first
/// series record selects on `hash`, return the SVN it adds.
fn ces_svn_for_hash(ces: &ConditionalEndorsementSeriesTriple, hash: &[u8]) -> Option<u16> {
    if !is_servtd_hash_environment(&ces.condition().environment) {
        return None;
    }
    for record in ces.series() {
        let selected = record
            .selection()
            .first()
            .and_then(digest_value)
            .map(|d| d == hash)
            .unwrap_or(false);
        if !selected {
            continue;
        }
        if let Some(svn) = record.addition().first().and_then(svn_exact) {
            return u16::try_from(svn).ok();
        }
    }
    None
}

/// First digest value of a measurement (the ServTD info hash).
fn digest_value(m: &MeasurementMap) -> Option<&[u8]> {
    Some(m.mval.digests.as_ref()?.first()?.value())
}

/// The exact SVN carried by a measurement's `mval.svn`, if present.
fn svn_exact(m: &MeasurementMap) -> Option<u64> {
    match m.mval.svn {
        Some(SvnChoice::ExactValue(n)) => Some(n),
        _ => None,
    }
}

// ---- TD Identity helpers ---------------------------------------------------

/// SVN key (`mkey = Uint`) of a TD Identity measurement.
fn measurement_svn(m: &MeasurementMap) -> Option<u64> {
    match &m.mkey {
        Some(MeasuredElement::Uint(n)) => Some(*n),
        _ => None,
    }
}

/// `(tcb_date, tcb_status)` from a TD Identity measurement's extra entries.
/// `tcb_date` is rendered as an ISO-8601 `YYYY-MM-DDTHH:MM:SSZ` string so it
/// is directly comparable with the legacy provider and the policy engine's
/// lexical ISO-8601 ordering.
fn measurement_level(m: &MeasurementMap) -> Option<(String, String)> {
    use corim::cbor::value::Value;

    let epoch = read_epoch(m.mval.extra_entries.get(&MVAL_TEE_TCBDATE)?)?;
    let status = match m.mval.extra_entries.get(&MVAL_TEE_TCBSTATUS)? {
        Value::Text(s) => s.clone(),
        _ => return None,
    };
    Some((epoch_to_iso8601(epoch), status))
}

/// Read an epoch-seconds value from a CBOR `#6.1(int)` tag or a bare integer.
fn read_epoch(v: &corim::cbor::value::Value) -> Option<i64> {
    use corim::cbor::value::Value;
    let inner = match v {
        Value::Tag(1, b) => b.as_ref(),
        other => other,
    };
    match inner {
        Value::Integer(n) => i64::try_from(*n).ok(),
        _ => None,
    }
}

/// Convert epoch seconds to `YYYY-MM-DDTHH:MM:SSZ` (UTC), `no_std`, no chrono.
fn epoch_to_iso8601(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's days-from-civil inverse: days since 1970-01-01 ->
/// `(year, month, day)`.
fn civil_from_days(z0: i64) -> (i64, u32, u32) {
    let z = z0 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{boxed::Box, vec, vec::Vec};
    use corim::{
        builder::{ComidBuilder, CorimBuilder},
        cbor::value::Value,
        types::{
            common::{ClassIdChoice, InstanceIdChoice, TagIdChoice},
            corim::CorimId,
            environment::{ClassMap, EnvironmentMap},
            measurement::{Digest, MeasurementValuesMap},
            triples::{
                CesCondition, ConditionalSeriesRecord, ReferenceTriple,
            },
        },
    };

    /// Producer's (mislabeled) digest alg id — see the SHA-256/SHA-384 gap.
    const SHA256_ALG: i64 = 1;

    fn class() -> ClassMap {
        ClassMap {
            class_id: Some(ClassIdChoice::Uuid(SERVTD_HASH_CLASS_UUID)),
            vendor: None,
            model: None,
            layer: None,
            index: None,
        }
    }

    fn servtd_hash_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(class()),
            instance: Some(InstanceIdChoice::Bytes(SERVTD_HASH_INSTANCE_BYTES.to_vec())),
            group: None,
        }
    }

    fn svn_tcb_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(class()),
            instance: Some(InstanceIdChoice::Bytes(SVN_TCB_INSTANCE_BYTES.to_vec())),
            group: None,
        }
    }

    fn ref_triple(hash: &[u8]) -> ReferenceTriple {
        ReferenceTriple::new(
            servtd_hash_env(),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    digests: Some(vec![Digest::new(SHA256_ALG, hash.to_vec())]),
                    ..MeasurementValuesMap::new()
                },
                authorized_by: None,
            }],
        )
    }

    fn ces_triple(hash: &[u8], svn: u16) -> ConditionalEndorsementSeriesTriple {
        let condition = CesCondition {
            environment: servtd_hash_env(),
            claims_list: Vec::new(),
            authorized_by: None,
        };
        let selection = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(SHA256_ALG, hash.to_vec())]),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        };
        let addition = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(svn as u64)),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        };
        ConditionalEndorsementSeriesTriple::new(
            condition,
            vec![ConditionalSeriesRecord::new(vec![selection], vec![addition])],
        )
    }

    /// Build a TCB Mapping CoRIM mirroring `TcbMappingCorim::add_release`:
    /// a reference-triple plus a CES triple per `(hash, svn)`.
    fn build_tcb_mapping(entries: &[(Vec<u8>, u16)]) -> Vec<u8> {
        let mut comid = ComidBuilder::new(TagIdChoice::Text("migtd-tcb-mapping".into()));
        for (hash, svn) in entries {
            comid = comid.add_reference_triple(ref_triple(hash));
            comid = comid.add_conditional_endorsement_series(ces_triple(hash, *svn));
        }
        let comid = comid.build().expect("build tcb-mapping comid");
        CorimBuilder::new(CorimId::Text("migtd-tcb-mapping".into()))
            .add_comid_tag(comid)
            .expect("attach comid")
            .build_bytes()
            .expect("encode corim")
    }

    /// Build a TD Identity CoRIM mirroring `TdIdentityCorim::add_level`.
    fn build_td_identity(levels: &[(u16, i64, &str)]) -> Vec<u8> {
        let mut measurements = Vec::new();
        for (svn, date, status) in levels {
            let mut mval = MeasurementValuesMap::new();
            mval.extra_entries.insert(
                MVAL_TEE_TCBDATE,
                Value::Tag(1, Box::new(Value::Integer(*date as i128))),
            );
            mval.extra_entries
                .insert(MVAL_TEE_TCBSTATUS, Value::Text(status.to_string()));
            measurements.push(MeasurementMap {
                mkey: Some(MeasuredElement::Uint(*svn as u64)),
                mval,
                authorized_by: None,
            });
        }
        let comid = ComidBuilder::new(TagIdChoice::Text("migtd-td-identity".into()))
            .add_reference_triple(ReferenceTriple::new(svn_tcb_env(), measurements))
            .build()
            .expect("build td-identity comid");
        CorimBuilder::new(CorimId::Text("migtd-td-identity".into()))
            .add_comid_tag(comid)
            .expect("attach comid")
            .build_bytes()
            .expect("encode corim")
    }

    fn hash(byte: u8) -> Vec<u8> {
        vec![byte; 48]
    }

    #[test]
    fn hash_lookup_resolves_svn_then_level() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5), (hash(0xBB), 7)]);
        // 2024-01-01T00:00:00Z = 1704067200 ; 2025-06-01T00:00:00Z = 1748736000
        let id = build_td_identity(&[
            (5, 1_704_067_200, "UpToDate"),
            (7, 1_748_736_000, "OutOfDate"),
        ]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert_eq!(provider.comid_counts(), (1, 1));

        let hit = provider
            .lookup(&ServtdIdentity::from_hash(&hash(0xAA)))
            .expect("match");
        assert_eq!(hit.isvsvn, 5);
        assert_eq!(hit.tcb_date, "2024-01-01T00:00:00Z");
        assert_eq!(hit.tcb_status, "UpToDate");

        let hit2 = provider
            .lookup(&ServtdIdentity::from_hash(&hash(0xBB)))
            .expect("match");
        assert_eq!(hit2.isvsvn, 7);
        assert_eq!(hit2.tcb_date, "2025-06-01T00:00:00Z");
        assert_eq!(hit2.tcb_status, "OutOfDate");
    }

    #[test]
    fn unknown_hash_misses() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let id = build_td_identity(&[(5, 1_704_067_200, "UpToDate")]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert!(provider
            .lookup(&ServtdIdentity::from_hash(&hash(0xCC)))
            .is_none());
    }

    #[test]
    fn known_hash_but_missing_level_misses() {
        // SVN 9 has a mapping but no TD Identity level.
        let tcb = build_tcb_mapping(&[(hash(0xAA), 9)]);
        let id = build_td_identity(&[(5, 1_704_067_200, "UpToDate")]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert!(provider
            .lookup(&ServtdIdentity::from_hash(&hash(0xAA)))
            .is_none());
    }

    #[test]
    fn wrong_length_hash_misses() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let id = build_td_identity(&[(5, 1_704_067_200, "UpToDate")]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert!(provider
            .lookup(&ServtdIdentity::from_hash(&[0xAA; 32]))
            .is_none());
    }

    #[test]
    fn epoch_formatting() {
        assert_eq!(epoch_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso8601(1_704_067_200), "2024-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso8601(1_748_736_000), "2025-06-01T00:00:00Z");
    }

    /// Interop regression: decode CBOR produced by the real host-side
    /// `mig-td-tools` signer (not our test reconstruction) and resolve a
    /// hash through both documents. The fixtures were generated with:
    ///   tcb-mapping-corim add-entry --servtd-hash <0xAA*48> --svn 5
    ///   tcb-mapping-corim add-entry --servtd-hash <0xBB*48> --svn 7
    ///   td-identity-corim add-level --svn 5 --tcb-date 2024-01-01 --tcb-status UpToDate
    ///   td-identity-corim add-level --svn 7 --tcb-date 2025-06-01 --tcb-status OutOfDate
    #[test]
    fn interop_with_mig_td_tools_producer() {
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cbor");
        let id = include_bytes!("../../test/policy_v2/corim/td_identity.cbor");
        let provider = ServtdCorim::decode(tcb, id, 0).expect("decode producer CBOR");

        let hit = provider
            .lookup(&ServtdIdentity::from_hash(&hash(0xAA)))
            .expect("hash 0xAA*48 -> svn 5");
        assert_eq!(hit.isvsvn, 5);
        assert_eq!(hit.tcb_date, "2024-01-01T00:00:00Z");
        assert_eq!(hit.tcb_status, "UpToDate");

        let hit2 = provider
            .lookup(&ServtdIdentity::from_hash(&hash(0xBB)))
            .expect("hash 0xBB*48 -> svn 7");
        assert_eq!(hit2.isvsvn, 7);
        assert_eq!(hit2.tcb_date, "2025-06-01T00:00:00Z");
        assert_eq!(hit2.tcb_status, "OutOfDate");

        assert!(provider
            .lookup(&ServtdIdentity::from_hash(&hash(0xCC)))
            .is_none());
    }
}
