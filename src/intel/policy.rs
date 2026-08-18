// Copyright 2026, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Canonical byte encoding of the TD report values a verifier expects.
//!
//! Layout (fixed size, [`TD_REPORT_POLICY_SIZE`] bytes):
//! `version ‖ bitmap ‖ xfam ‖ mrtd ‖ mrconfigid ‖ mrowner ‖ mrownerconfig ‖ rtmr0..3 ‖ reportdata`.
//! `mrtd` and `reportdata` are always checked; each other field is checked only if its
//! bitmap bit is set, and must be all zeros otherwise, so every policy has exactly one encoding.

use crate::intel::constants::*;

/// Errors that can occur when parsing or checking a TD report policy.
#[derive(Debug, PartialEq)]
pub enum PolicyError {
    /// The policy has the wrong length.
    InvalidLength,
    /// The policy version is not supported.
    UnsupportedPolicyVersion,
    /// A field not marked in the bitmap contains non-zero bytes.
    NonCanonicalPolicy,
    /// The quote's TD report does not match the policy.
    Mismatch,
}

/// Expected TD report values, parsed from the canonical byte encoding.
///
/// `None` means the field is not checked. Use [`crate::QuoteV4::check_policy`] to
/// compare against a quote's TD report.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TdReportPolicy {
    /// Expected XFAM value, if pinned.
    pub xfam: Option<[u8; BODY_XFAM_SIZE]>,
    /// Expected measurement of the initial contents of the TD.
    pub mrtd: [u8; BODY_MRTD_SIZE],
    /// Expected MRCONFIGID value, if pinned.
    pub mrconfigid: Option<[u8; BODY_MRCONFIGID_SIZE]>,
    /// Expected MROWNER value, if pinned.
    pub mrowner: Option<[u8; BODY_MROWNER_SIZE]>,
    /// Expected MROWNERCONFIG value, if pinned.
    pub mrownerconfig: Option<[u8; BODY_MROWNERCONFIG_SIZE]>,
    /// Expected RTMR values, each pinned individually.
    pub rtmrs: [Option<[u8; BODY_RTMR_SIZE]>; RTMR_COUNT],
    /// Expected REPORTDATA.
    pub report_data: [u8; BODY_REPORTDATA_SIZE],
}

fn optional<const N: usize>(
    input: &[u8],
    offset: usize,
    bitmap: u8,
    bit: u8,
) -> Result<Option<[u8; N]>, PolicyError> {
    let field: [u8; N] = input[offset..offset + N]
        .try_into()
        .expect("length checked by caller");
    if bitmap & bit != 0 {
        Ok(Some(field))
    } else if field.iter().all(|b| *b == 0) {
        Ok(None)
    } else {
        Err(PolicyError::NonCanonicalPolicy)
    }
}

impl TdReportPolicy {
    /// Parse a policy from its canonical byte encoding.
    pub fn from_bytes(input: &[u8]) -> Result<Self, PolicyError> {
        if input.len() != TD_REPORT_POLICY_SIZE {
            return Err(PolicyError::InvalidLength);
        }
        if input[POLICY_VERSION_OFFSET] != POLICY_VERSION_V1 {
            return Err(PolicyError::UnsupportedPolicyVersion);
        }
        let bitmap = input[POLICY_BITMAP_OFFSET];
        Ok(TdReportPolicy {
            xfam: optional(input, POLICY_XFAM_OFFSET, bitmap, POLICY_BIT_XFAM)?,
            mrtd: input[POLICY_MRTD_OFFSET..POLICY_MRCONFIGID_OFFSET]
                .try_into()
                .expect("length checked above"),
            mrconfigid: optional(
                input,
                POLICY_MRCONFIGID_OFFSET,
                bitmap,
                POLICY_BIT_MRCONFIGID,
            )?,
            mrowner: optional(input, POLICY_MROWNER_OFFSET, bitmap, POLICY_BIT_MROWNER)?,
            mrownerconfig: optional(
                input,
                POLICY_MROWNERCONFIG_OFFSET,
                bitmap,
                POLICY_BIT_MROWNERCONFIG,
            )?,
            rtmrs: [
                optional(input, POLICY_RTMR0_OFFSET, bitmap, POLICY_BIT_RTMR0)?,
                optional(input, POLICY_RTMR1_OFFSET, bitmap, POLICY_BIT_RTMR1)?,
                optional(input, POLICY_RTMR2_OFFSET, bitmap, POLICY_BIT_RTMR2)?,
                optional(input, POLICY_RTMR3_OFFSET, bitmap, POLICY_BIT_RTMR3)?,
            ],
            report_data: input[POLICY_REPORTDATA_OFFSET..TD_REPORT_POLICY_SIZE]
                .try_into()
                .expect("length checked above"),
        })
    }

    /// Serialize the policy to its canonical byte encoding.
    pub fn to_bytes(&self) -> [u8; TD_REPORT_POLICY_SIZE] {
        let mut out = [0u8; TD_REPORT_POLICY_SIZE];
        let mut bitmap = 0u8;
        out[POLICY_VERSION_OFFSET] = POLICY_VERSION_V1;
        if let Some(v) = self.xfam {
            bitmap |= POLICY_BIT_XFAM;
            out[POLICY_XFAM_OFFSET..POLICY_MRTD_OFFSET].copy_from_slice(&v);
        }
        out[POLICY_MRTD_OFFSET..POLICY_MRCONFIGID_OFFSET].copy_from_slice(&self.mrtd);
        if let Some(v) = self.mrconfigid {
            bitmap |= POLICY_BIT_MRCONFIGID;
            out[POLICY_MRCONFIGID_OFFSET..POLICY_MROWNER_OFFSET].copy_from_slice(&v);
        }
        if let Some(v) = self.mrowner {
            bitmap |= POLICY_BIT_MROWNER;
            out[POLICY_MROWNER_OFFSET..POLICY_MROWNERCONFIG_OFFSET].copy_from_slice(&v);
        }
        if let Some(v) = self.mrownerconfig {
            bitmap |= POLICY_BIT_MROWNERCONFIG;
            out[POLICY_MROWNERCONFIG_OFFSET..POLICY_RTMR0_OFFSET].copy_from_slice(&v);
        }
        if let Some(v) = self.rtmrs[0] {
            bitmap |= POLICY_BIT_RTMR0;
            out[POLICY_RTMR0_OFFSET..POLICY_RTMR1_OFFSET].copy_from_slice(&v);
        }
        if let Some(v) = self.rtmrs[1] {
            bitmap |= POLICY_BIT_RTMR1;
            out[POLICY_RTMR1_OFFSET..POLICY_RTMR2_OFFSET].copy_from_slice(&v);
        }
        if let Some(v) = self.rtmrs[2] {
            bitmap |= POLICY_BIT_RTMR2;
            out[POLICY_RTMR2_OFFSET..POLICY_RTMR3_OFFSET].copy_from_slice(&v);
        }
        if let Some(v) = self.rtmrs[3] {
            bitmap |= POLICY_BIT_RTMR3;
            out[POLICY_RTMR3_OFFSET..POLICY_REPORTDATA_OFFSET].copy_from_slice(&v);
        }
        out[POLICY_REPORTDATA_OFFSET..TD_REPORT_POLICY_SIZE].copy_from_slice(&self.report_data);
        out[POLICY_BITMAP_OFFSET] = bitmap;
        out
    }
}

#[cfg(test)]
mod should {
    use super::*;

    fn full_policy() -> TdReportPolicy {
        TdReportPolicy {
            xfam: Some([1u8; BODY_XFAM_SIZE]),
            mrtd: [2u8; BODY_MRTD_SIZE],
            mrconfigid: Some([3u8; BODY_MRCONFIGID_SIZE]),
            mrowner: Some([4u8; BODY_MROWNER_SIZE]),
            mrownerconfig: Some([5u8; BODY_MROWNERCONFIG_SIZE]),
            rtmrs: [
                Some([6u8; BODY_RTMR_SIZE]),
                None,
                Some([7u8; BODY_RTMR_SIZE]),
                None,
            ],
            report_data: [8u8; BODY_REPORTDATA_SIZE],
        }
    }

    fn minimal_policy() -> TdReportPolicy {
        TdReportPolicy {
            xfam: None,
            mrtd: [2u8; BODY_MRTD_SIZE],
            mrconfigid: None,
            mrowner: None,
            mrownerconfig: None,
            rtmrs: [None; RTMR_COUNT],
            report_data: [8u8; BODY_REPORTDATA_SIZE],
        }
    }

    #[test]
    fn round_trip() {
        for policy in [full_policy(), minimal_policy()] {
            let bytes = policy.to_bytes();
            assert_eq!(TdReportPolicy::from_bytes(&bytes).unwrap(), policy);
        }
    }

    #[test]
    fn reject_wrong_length() {
        let bytes = minimal_policy().to_bytes();
        assert_eq!(
            TdReportPolicy::from_bytes(&bytes[..TD_REPORT_POLICY_SIZE - 1]).unwrap_err(),
            PolicyError::InvalidLength
        );
        let longer = [bytes.as_slice(), &[0u8]].concat();
        assert_eq!(
            TdReportPolicy::from_bytes(&longer).unwrap_err(),
            PolicyError::InvalidLength
        );
    }

    #[test]
    fn reject_unsupported_version() {
        let mut bytes = minimal_policy().to_bytes();
        bytes[POLICY_VERSION_OFFSET] = 2;
        assert_eq!(
            TdReportPolicy::from_bytes(&bytes).unwrap_err(),
            PolicyError::UnsupportedPolicyVersion
        );
    }

    #[test]
    fn reject_non_zero_ignored_field() {
        let mut bytes = minimal_policy().to_bytes();
        bytes[POLICY_RTMR2_OFFSET] = 1; // rtmr2 not in the bitmap
        assert_eq!(
            TdReportPolicy::from_bytes(&bytes).unwrap_err(),
            PolicyError::NonCanonicalPolicy
        );
    }
}
