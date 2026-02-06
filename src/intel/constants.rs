// Copyright 2025, Horizen Labs, Inc.
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

//! Constants for Intel SGX/TDX quote parsing and verification.

// =============================================================================
// Top-level structure sizes
// =============================================================================

pub const MAX_COLLATERAL_SIZE: usize = 8192;
pub const QE_REPORT_SIZE: usize = 384;
pub const ECDSA_SIGNATURE_SIZE: usize = 64;
pub const ATTESTATION_KEY_SIZE: usize = 64;
pub const QUOTE_HEADER_SIZE: usize = 48;
pub const QUOTE_BODY_SIZE: usize = 584;

// =============================================================================
// Certification data types
// =============================================================================

pub const CERT_DATA_TYPE_PCK_CHAIN: u16 = 5;
pub const CERT_DATA_TYPE_QE_REPORT: u16 = 6;

// =============================================================================
// Intel OIDs
// =============================================================================

pub const INTEL_SGX_OID: &str = "1.2.840.113741.1.13.1";
pub const INTEL_TCB_OID: &str = "1.2.840.113741.1.13.1.2";
pub const INTEL_FMSPC_OID: &str = "1.2.840.113741.1.13.1.4";

// =============================================================================
// Intel vendor ID
// =============================================================================

pub const INTEL_VENDOR_ID: [u8; 16] = hex_literal::hex!("939A7233F79C4CA9940A0DB3957F0607");

// =============================================================================
// QuoteHeader field sizes
// =============================================================================

pub const HEADER_VERSION_SIZE: usize = 2;
pub const HEADER_ATTESTATION_KEY_TYPE_SIZE: usize = 2;
pub const HEADER_TEE_TYPE_SIZE: usize = 4;
pub const HEADER_RESERVED1_SIZE: usize = 2;
pub const HEADER_RESERVED2_SIZE: usize = 2;
pub const HEADER_QE_VENDOR_ID_SIZE: usize = 16;
pub const HEADER_USER_DATA_SIZE: usize = 20;

// QuoteHeader field offsets (derived from sizes)
pub const HEADER_VERSION_OFFSET: usize = 0;
pub const HEADER_ATTESTATION_KEY_TYPE_OFFSET: usize = HEADER_VERSION_OFFSET + HEADER_VERSION_SIZE;
pub const HEADER_TEE_TYPE_OFFSET: usize =
    HEADER_ATTESTATION_KEY_TYPE_OFFSET + HEADER_ATTESTATION_KEY_TYPE_SIZE;
pub const HEADER_RESERVED1_OFFSET: usize = HEADER_TEE_TYPE_OFFSET + HEADER_TEE_TYPE_SIZE;
pub const HEADER_RESERVED2_OFFSET: usize = HEADER_RESERVED1_OFFSET + HEADER_RESERVED1_SIZE;
pub const HEADER_QE_VENDOR_ID_OFFSET: usize = HEADER_RESERVED2_OFFSET + HEADER_RESERVED2_SIZE;
pub const HEADER_USER_DATA_OFFSET: usize = HEADER_QE_VENDOR_ID_OFFSET + HEADER_QE_VENDOR_ID_SIZE;

// =============================================================================
// QuoteBodyV4 field sizes
// =============================================================================

pub const BODY_TEE_TCB_SVN_SIZE: usize = 16;
pub const BODY_MRSEAM_SIZE: usize = 48;
pub const BODY_MRSIGNERSEAM_SIZE: usize = 48;
pub const BODY_SEAMATTRIBUTES_SIZE: usize = 8;
pub const BODY_TDATTRIBUTES_SIZE: usize = 8;
pub const BODY_XFAM_SIZE: usize = 8;
pub const BODY_MRTD_SIZE: usize = 48;
pub const BODY_MRCONFIGID_SIZE: usize = 48;
pub const BODY_MROWNER_SIZE: usize = 48;
pub const BODY_MROWNERCONFIG_SIZE: usize = 48;
pub const BODY_RTMR_SIZE: usize = 48;
pub const BODY_REPORTDATA_SIZE: usize = 64;

// QuoteBodyV4 field offsets (derived from sizes)
pub const BODY_TEE_TCB_SVN_OFFSET: usize = 0;
pub const BODY_MRSEAM_OFFSET: usize = BODY_TEE_TCB_SVN_OFFSET + BODY_TEE_TCB_SVN_SIZE;
pub const BODY_MRSIGNERSEAM_OFFSET: usize = BODY_MRSEAM_OFFSET + BODY_MRSEAM_SIZE;
pub const BODY_SEAMATTRIBUTES_OFFSET: usize = BODY_MRSIGNERSEAM_OFFSET + BODY_MRSIGNERSEAM_SIZE;
pub const BODY_TDATTRIBUTES_OFFSET: usize = BODY_SEAMATTRIBUTES_OFFSET + BODY_SEAMATTRIBUTES_SIZE;
pub const BODY_XFAM_OFFSET: usize = BODY_TDATTRIBUTES_OFFSET + BODY_TDATTRIBUTES_SIZE;
pub const BODY_MRTD_OFFSET: usize = BODY_XFAM_OFFSET + BODY_XFAM_SIZE;
pub const BODY_MRCONFIGID_OFFSET: usize = BODY_MRTD_OFFSET + BODY_MRTD_SIZE;
pub const BODY_MROWNER_OFFSET: usize = BODY_MRCONFIGID_OFFSET + BODY_MRCONFIGID_SIZE;
pub const BODY_MROWNERCONFIG_OFFSET: usize = BODY_MROWNER_OFFSET + BODY_MROWNER_SIZE;
pub const BODY_RTMR0_OFFSET: usize = BODY_MROWNERCONFIG_OFFSET + BODY_MROWNERCONFIG_SIZE;
pub const BODY_RTMR1_OFFSET: usize = BODY_RTMR0_OFFSET + BODY_RTMR_SIZE;
pub const BODY_RTMR2_OFFSET: usize = BODY_RTMR1_OFFSET + BODY_RTMR_SIZE;
pub const BODY_RTMR3_OFFSET: usize = BODY_RTMR2_OFFSET + BODY_RTMR_SIZE;
pub const BODY_REPORTDATA_OFFSET: usize = BODY_RTMR3_OFFSET + BODY_RTMR_SIZE;

// =============================================================================
// QeAuthenticationData / QeCertificationData field sizes
// =============================================================================

pub const AUTH_DATA_SIZE_FIELD: usize = 2;
pub const CERT_DATA_TYPE_FIELD_SIZE: usize = 2;
pub const CERT_DATA_SIZE_FIELD: usize = 4;
pub const CERT_DATA_HEADER_SIZE: usize = CERT_DATA_TYPE_FIELD_SIZE + CERT_DATA_SIZE_FIELD;

// =============================================================================
// QeReportCertificationData constants
// =============================================================================

pub const REPORT_DATA_SIZE: usize = 64;
pub const HASH_PADDING_SIZE: usize = 32;

// =============================================================================
// QuoteV4 constants
// =============================================================================

pub const SIGNATURE_DATA_LEN_SIZE: usize = 4;

// =============================================================================
// Certificate / TCB extraction constants
// =============================================================================

pub const TCB_SVN_COUNT: usize = 16;
pub const FMSPC_SIZE: usize = 6;

// =============================================================================
// Attestation key types
// =============================================================================

/// ECDSA-256-with-P-256 curve attestation key type
pub const ATTESTATION_KEY_TYPE_ECDSA_256_P256: i16 = 2;

// =============================================================================
// TD Attributes
// =============================================================================

/// Index of the debug flag byte in TD attributes
pub const TDATTRIBUTES_DEBUG_INDEX: usize = 0;
/// Expected value when debug mode is disabled
pub const TDATTRIBUTES_DEBUG_DISABLED: u8 = 0;
