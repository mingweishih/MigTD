// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Unified servtd lookup surface used by `mig_policy` to obtain
//! `(isvsvn, tcb_date, tcb_status)` from a MigTD attestation report.
//!
//! Today the data comes from the legacy `TdIdentity` + `TdTcbMapping` JSON
//! pair (see `servtd_collateral.rs`). A new CoRIM-based provider can plug
//! in behind the same trait so call sites in `mig_policy.rs` are
//! format-agnostic. See `servtd_corim.rs` for the CoRIM implementation.

use alloc::string::{String, ToString};

use crate::{
    v2::servtd_collateral::{Measurements, TdIdentity, TdTcbMapping},
    MigTdInfoProperty, Report,
};

/// Result of a successful servtd lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServtdLookup {
    pub isvsvn: u16,
    pub tcb_date: String,
    pub tcb_status: String,
}

/// Identity of the MigTD whose TCB level is being resolved.
///
/// Different providers key on different fields:
///
/// * the legacy `TdIdentity` + `TdTcbMapping` pair keys on raw
///   [`measurements`](ServtdIdentity::measurements);
/// * the CoRIM provider keys on the SHA-384
///   [`servtd_info_hash`](ServtdIdentity::servtd_info_hash).
///
/// A caller supplies whichever field(s) it has. A provider that cannot find
/// its key returns `None` — there is no cross-keying or fallback inside a
/// single provider (see [`VerifiedPolicy::servtd_lookup`] for the
/// fail-closed selection between providers).
#[derive(Default, Clone, Copy)]
pub struct ServtdIdentity<'a> {
    /// Raw measurement registers (MRTD, RTMR0..3). Used by the legacy
    /// provider.
    pub measurements: Option<&'a Measurements>,
    /// The SHA-384 `SERVTD_INFO_HASH` from the TDX binding table
    /// (`SERVTD_EXT.{INIT_,CUR_}SERVTD_INFO_HASH`). Used by the CoRIM
    /// provider.
    pub servtd_info_hash: Option<&'a [u8]>,
}

impl<'a> ServtdIdentity<'a> {
    /// Build an identity carrying only raw measurements.
    pub fn from_measurements(measurements: &'a Measurements) -> Self {
        Self {
            measurements: Some(measurements),
            servtd_info_hash: None,
        }
    }

    /// Build an identity carrying only a `SERVTD_INFO_HASH`.
    pub fn from_hash(hash: &'a [u8]) -> Self {
        Self {
            measurements: None,
            servtd_info_hash: Some(hash),
        }
    }

    /// Attach a `SERVTD_INFO_HASH` to an existing identity.
    pub fn with_hash(mut self, hash: &'a [u8]) -> Self {
        self.servtd_info_hash = Some(hash);
        self
    }
}

/// Abstracts servtd collateral so the policy engine can consume either the
/// legacy `TdIdentity` + `TdTcbMapping` pair or a CoRIM-encoded equivalent
/// behind one method.
pub trait ServtdProvider {
    /// Resolve `(isvsvn, tcb_date, tcb_status)` for the supplied identity.
    /// Returns `None` if the identity does not carry the key this provider
    /// uses, or if the key is not present in the collateral.
    fn lookup(&self, id: &ServtdIdentity) -> Option<ServtdLookup>;
}

/// Adapter over the legacy `TdIdentity` + `TdTcbMapping` pair.
///
/// Holds borrowed references so it can be constructed cheaply from an
/// already-verified `VerifiedPolicy` without cloning the heavy JSON data.
pub struct LegacyServtdProvider<'a> {
    pub tcb_mapping: &'a TdTcbMapping,
    pub identity: &'a TdIdentity,
}

impl<'a> LegacyServtdProvider<'a> {
    pub fn new(tcb_mapping: &'a TdTcbMapping, identity: &'a TdIdentity) -> Self {
        Self {
            tcb_mapping,
            identity,
        }
    }
}

impl<'a> ServtdProvider for LegacyServtdProvider<'a> {
    fn lookup(&self, id: &ServtdIdentity) -> Option<ServtdLookup> {
        let measurements = id.measurements?;
        let isvsvn = self.tcb_mapping.get_engine_svn_by_measurements(measurements)?;
        let level = self.identity.get_tcb_level_by_svn(isvsvn)?;
        Some(ServtdLookup {
            isvsvn,
            tcb_date: level.tcb_date.to_string(),
            tcb_status: level.tcb_status.to_string(),
        })
    }
}

/// Extract MRTD/RTMR[0..3] from a verified `Report` into a `Measurements`.
/// Mirrors `TdTcbMapping::get_engine_svn_by_report`.
pub fn measurements_from_report(report: &Report) -> Option<Measurements> {
    Some(Measurements::new_from_bytes(
        report
            .get_migtd_info_property(&MigTdInfoProperty::MrTd)
            .ok()?,
        report
            .get_migtd_info_property(&MigTdInfoProperty::Rtmr0)
            .ok()?,
        report
            .get_migtd_info_property(&MigTdInfoProperty::Rtmr1)
            .ok()?,
        Some(
            report
                .get_migtd_info_property(&MigTdInfoProperty::Rtmr2)
                .ok()?,
        ),
        Some(
            report
                .get_migtd_info_property(&MigTdInfoProperty::Rtmr3)
                .ok()?,
        ),
    ))
}
