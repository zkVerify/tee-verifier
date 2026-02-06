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

//! TEE attestation quote verification library.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![deny(missing_docs)]

extern crate alloc;
use alloc::vec::Vec;

mod cert;
mod intel;

pub use crate::{
    cert::{CertificateError, Crl, RevokedCertId},
    intel::{CollateralError, ParseError, QuoteV4, TcbResponse, VerificationError},
};

// =============================================================================
// Generic 
// =============================================================================

/// Parse a CRL from PEM data and validates its signature.
/// Returns:
/// - the most recent issue date for all the included CRLs
/// - a Vec of revoked certificates, identified by the (issuer, serial_number) pair.
pub fn parse_crl(
    crl_pem: &Vec<u8>,
    pck_certificate_chain_pem: &Vec<u8>,
    root_cert: Option<&[u8]>,
    now: u64,
) -> Result<(u64, Crl), CertificateError> {
    cert::parse_crl(crl_pem, pck_certificate_chain_pem, root_cert, now)
}

// =============================================================================
// Intel Specific
// =============================================================================

/// Parse a TCB response from JSON bytes.
pub fn parse_tcb_response(input: &[u8]) -> Result<TcbResponse, CollateralError> {
    intel::parse_tcb_response(input)
}

/// Parse an Intel TDX quote from binary data.
pub fn parse_quote(input: &[u8]) -> Result<QuoteV4, ParseError> {
    intel::parse_quote(input)
}
