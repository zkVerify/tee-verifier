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

//! Canonical byte encoding of the Nitro attestation values a verifier expects.
//!
//! Layout (variable size, [`NITRO_POLICY_MIN_SIZE`]..=[`NITRO_POLICY_MAX_SIZE`] bytes):
//! `version ‖ pcr_bitmap ‖ flags ‖ pcr0..pcr15 ‖ [user_data_len ‖ user_data]`.
//! `pcr0` (the enclave image measurement) is always checked; each other PCR is checked
//! only if its bitmap bit is set, and its slot must be all zeros otherwise. `user_data`
//! is checked only if its flag bit is set, and the trailing length-prefixed bytes are
//! present only in that case, so every policy has exactly one encoding.

extern crate alloc;
use alloc::vec::Vec;

/// Size in bytes of a PCR value (SHA-384 digest).
pub const NITRO_PCR_SIZE: usize = 48;
/// Number of PCR registers a Nitro attestation document reports.
pub const NITRO_PCR_COUNT: usize = 16;
/// Maximum size in bytes of the pinned `user_data`.
pub const NITRO_MAX_USER_DATA_SIZE: usize = 1024;

/// Supported policy encoding version.
pub const NITRO_POLICY_VERSION_V1: u8 = 1;

/// Offset of the version byte.
pub const NITRO_POLICY_VERSION_OFFSET: usize = 0;
/// Offset of the little-endian `u16` PCR bitmap.
pub const NITRO_POLICY_BITMAP_OFFSET: usize = NITRO_POLICY_VERSION_OFFSET + 1;
/// Offset of the flags byte.
pub const NITRO_POLICY_FLAGS_OFFSET: usize = NITRO_POLICY_BITMAP_OFFSET + 2;
/// Offset of the first PCR slot.
pub const NITRO_POLICY_PCRS_OFFSET: usize = NITRO_POLICY_FLAGS_OFFSET + 1;
/// Offset of the little-endian `u16` `user_data` length (present only when pinned).
pub const NITRO_POLICY_USER_DATA_LEN_OFFSET: usize =
    NITRO_POLICY_PCRS_OFFSET + NITRO_PCR_COUNT * NITRO_PCR_SIZE;

/// Size in bytes of a policy that does not pin `user_data`.
pub const NITRO_POLICY_MIN_SIZE: usize = NITRO_POLICY_USER_DATA_LEN_OFFSET;
/// Maximum size in bytes of a policy encoding.
pub const NITRO_POLICY_MAX_SIZE: usize = NITRO_POLICY_MIN_SIZE + 2 + NITRO_MAX_USER_DATA_SIZE;

/// Flags-byte bit marking `user_data` as pinned.
pub const NITRO_POLICY_FLAG_USER_DATA: u8 = 1 << 0;

/// Errors that can occur when parsing or checking a Nitro attestation policy.
#[derive(Debug, PartialEq)]
pub enum NitroPolicyError {
    /// The policy has an invalid length.
    InvalidLength,
    /// The policy version is not supported.
    UnsupportedPolicyVersion,
    /// A field not marked in the bitmap/flags contains non-zero bytes, an unknown
    /// flag bit is set, or the encoding carries unexpected trailing bytes.
    NonCanonicalPolicy,
    /// PCR0 (the enclave image measurement) is not pinned.
    MissingPcr0,
    /// The attestation document does not match the policy.
    Mismatch,
}

/// Expected Nitro attestation values, parsed from the canonical byte encoding.
///
/// `None` means the field is not checked. Use [`crate::NitroAttestation::check_policy`]
/// to compare against a parsed attestation document.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct NitroPolicy {
    /// Expected PCR values, each pinned individually. PCR0 must always be pinned.
    pub pcrs: [Option<[u8; NITRO_PCR_SIZE]>; NITRO_PCR_COUNT],
    /// Expected `user_data`, if pinned. An absent `user_data` in the attestation
    /// document is treated as empty bytes.
    pub user_data: Option<Vec<u8>>,
}

impl NitroPolicy {
    /// Parse a policy from its canonical byte encoding.
    pub fn from_bytes(input: &[u8]) -> Result<Self, NitroPolicyError> {
        if input.len() < NITRO_POLICY_MIN_SIZE {
            return Err(NitroPolicyError::InvalidLength);
        }
        if input[NITRO_POLICY_VERSION_OFFSET] != NITRO_POLICY_VERSION_V1 {
            return Err(NitroPolicyError::UnsupportedPolicyVersion);
        }
        let bitmap = u16::from_le_bytes(
            input[NITRO_POLICY_BITMAP_OFFSET..NITRO_POLICY_FLAGS_OFFSET]
                .try_into()
                .expect("slice is 2 bytes long; qed"),
        );
        if bitmap & 1 == 0 {
            return Err(NitroPolicyError::MissingPcr0);
        }
        let flags = input[NITRO_POLICY_FLAGS_OFFSET];
        if flags & !NITRO_POLICY_FLAG_USER_DATA != 0 {
            return Err(NitroPolicyError::NonCanonicalPolicy);
        }

        let mut pcrs = [None; NITRO_PCR_COUNT];
        for (i, pcr) in pcrs.iter_mut().enumerate() {
            let offset = NITRO_POLICY_PCRS_OFFSET + i * NITRO_PCR_SIZE;
            let slot: [u8; NITRO_PCR_SIZE] = input[offset..offset + NITRO_PCR_SIZE]
                .try_into()
                .expect("length checked above");
            if bitmap & (1 << i) != 0 {
                *pcr = Some(slot);
            } else if slot.iter().any(|b| *b != 0) {
                return Err(NitroPolicyError::NonCanonicalPolicy);
            }
        }

        let user_data = if flags & NITRO_POLICY_FLAG_USER_DATA != 0 {
            if input.len() < NITRO_POLICY_USER_DATA_LEN_OFFSET + 2 {
                return Err(NitroPolicyError::InvalidLength);
            }
            let len = u16::from_le_bytes(
                input[NITRO_POLICY_USER_DATA_LEN_OFFSET..NITRO_POLICY_USER_DATA_LEN_OFFSET + 2]
                    .try_into()
                    .expect("slice is 2 bytes long; qed"),
            ) as usize;
            if len > NITRO_MAX_USER_DATA_SIZE
                || input.len() != NITRO_POLICY_USER_DATA_LEN_OFFSET + 2 + len
            {
                return Err(NitroPolicyError::InvalidLength);
            }
            Some(input[NITRO_POLICY_USER_DATA_LEN_OFFSET + 2..].to_vec())
        } else {
            if input.len() != NITRO_POLICY_MIN_SIZE {
                return Err(NitroPolicyError::NonCanonicalPolicy);
            }
            None
        };

        Ok(NitroPolicy { pcrs, user_data })
    }

    /// Serialize the policy to its canonical byte encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; NITRO_POLICY_MIN_SIZE];
        let mut bitmap = 0u16;
        out[NITRO_POLICY_VERSION_OFFSET] = NITRO_POLICY_VERSION_V1;
        for (i, pcr) in self.pcrs.iter().enumerate() {
            if let Some(v) = pcr {
                bitmap |= 1 << i;
                let offset = NITRO_POLICY_PCRS_OFFSET + i * NITRO_PCR_SIZE;
                out[offset..offset + NITRO_PCR_SIZE].copy_from_slice(v);
            }
        }
        out[NITRO_POLICY_BITMAP_OFFSET..NITRO_POLICY_FLAGS_OFFSET]
            .copy_from_slice(&bitmap.to_le_bytes());
        if let Some(user_data) = &self.user_data {
            out[NITRO_POLICY_FLAGS_OFFSET] |= NITRO_POLICY_FLAG_USER_DATA;
            out.extend_from_slice(&(user_data.len() as u16).to_le_bytes());
            out.extend_from_slice(user_data);
        }
        out
    }
}

#[cfg(test)]
mod should {
    use super::*;

    fn full_policy() -> NitroPolicy {
        let mut pcrs = [None; NITRO_PCR_COUNT];
        for (i, pcr) in pcrs.iter_mut().enumerate() {
            *pcr = Some([i as u8 + 1; NITRO_PCR_SIZE]);
        }
        NitroPolicy {
            pcrs,
            user_data: Some(alloc::vec![0xab; 32]),
        }
    }

    fn minimal_policy() -> NitroPolicy {
        let mut pcrs = [None; NITRO_PCR_COUNT];
        pcrs[0] = Some([1u8; NITRO_PCR_SIZE]);
        NitroPolicy {
            pcrs,
            user_data: None,
        }
    }

    #[test]
    fn round_trip() {
        for policy in [full_policy(), minimal_policy()] {
            let bytes = policy.to_bytes();
            assert_eq!(NitroPolicy::from_bytes(&bytes).unwrap(), policy);
        }
    }

    #[test]
    fn round_trip_empty_user_data() {
        let policy = NitroPolicy {
            user_data: Some(Vec::new()),
            ..minimal_policy()
        };
        let bytes = policy.to_bytes();
        assert_eq!(bytes.len(), NITRO_POLICY_MIN_SIZE + 2);
        assert_eq!(NitroPolicy::from_bytes(&bytes).unwrap(), policy);
    }

    #[test]
    fn reject_wrong_length() {
        let bytes = minimal_policy().to_bytes();
        assert_eq!(
            NitroPolicy::from_bytes(&bytes[..NITRO_POLICY_MIN_SIZE - 1]).unwrap_err(),
            NitroPolicyError::InvalidLength
        );

        // With user_data pinned, the declared length must match exactly.
        let mut bytes = full_policy().to_bytes();
        bytes.push(0);
        assert_eq!(
            NitroPolicy::from_bytes(&bytes).unwrap_err(),
            NitroPolicyError::InvalidLength
        );

        // Declared user_data length above the cap.
        let policy = NitroPolicy {
            user_data: Some(alloc::vec![0; NITRO_MAX_USER_DATA_SIZE + 1]),
            ..minimal_policy()
        };
        assert_eq!(
            NitroPolicy::from_bytes(&policy.to_bytes()).unwrap_err(),
            NitroPolicyError::InvalidLength
        );
    }

    #[test]
    fn reject_unsupported_version() {
        let mut bytes = minimal_policy().to_bytes();
        bytes[NITRO_POLICY_VERSION_OFFSET] = 2;
        assert_eq!(
            NitroPolicy::from_bytes(&bytes).unwrap_err(),
            NitroPolicyError::UnsupportedPolicyVersion
        );
    }

    #[test]
    fn reject_unpinned_pcr0() {
        let mut bytes = minimal_policy().to_bytes();
        bytes[NITRO_POLICY_BITMAP_OFFSET] &= !1;
        assert_eq!(
            NitroPolicy::from_bytes(&bytes).unwrap_err(),
            NitroPolicyError::MissingPcr0
        );
    }

    #[test]
    fn reject_non_zero_unpinned_pcr() {
        let mut bytes = minimal_policy().to_bytes();
        // PCR5 is not in the bitmap
        bytes[NITRO_POLICY_PCRS_OFFSET + 5 * NITRO_PCR_SIZE] = 1;
        assert_eq!(
            NitroPolicy::from_bytes(&bytes).unwrap_err(),
            NitroPolicyError::NonCanonicalPolicy
        );
    }

    #[test]
    fn reject_unknown_flag_bit() {
        let mut bytes = minimal_policy().to_bytes();
        bytes[NITRO_POLICY_FLAGS_OFFSET] |= 1 << 1;
        assert_eq!(
            NitroPolicy::from_bytes(&bytes).unwrap_err(),
            NitroPolicyError::NonCanonicalPolicy
        );
    }

    #[test]
    fn reject_trailing_bytes_without_user_data_flag() {
        let mut bytes = minimal_policy().to_bytes();
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(
            NitroPolicy::from_bytes(&bytes).unwrap_err(),
            NitroPolicyError::NonCanonicalPolicy
        );
    }
}
