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

//! Integration tests for the tee-verifier crate.
//!
//! These tests verify the complete end-to-end workflow of parsing and
//! verifying Intel SGX/TDX attestation quotes, including certificate
//! chain validation, CRL checking, and TCB collateral verification.

use std::fs::File;
use std::io::Read;

use assert_ok::assert_ok;
use chrono::DateTime;

use tee_verifier::{parse_crl, parse_quote, parse_tcb_response, Crl, VerificationError};

/// Helper function to load a file into a byte vector
fn load_file(path: &str) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf
}

/// Helper function to load the Intel root certificate
fn load_root_cert() -> Vec<u8> {
    load_file("assets/Intel_SGX_Provisioning_Certification_RootCA.cer")
}

/// Helper function to parse a timestamp string to unix timestamp
fn parse_timestamp(ts: &str) -> u64 {
    DateTime::parse_from_rfc3339(ts).unwrap().timestamp() as u64
}

// =============================================================================
// End-to-End Quote Verification Tests
// =============================================================================

mod end_to_end {
    use super::*;

    #[test]
    fn verify_quote() {
        // Load quote data
        let quote_data = load_file("assets/tests/intel/quote_b0.dat");

        // Load tcb data
        let tcb_data = load_file("assets/tests/intel/tcb_info_b0.json");
        let tcb_chain = load_file("assets/tests/intel/tcb_info_b0.pem");

        // Load Certificate Revocation List data
        let crl_data = load_file("assets/tests/intel/crl.pem");
        let crl_chain = load_file("assets/tests/intel/crl_chain.pem");

        // Load Intel Root CA
        let root_cert = load_root_cert();

        let now = parse_timestamp("2026-02-03T09:32:53Z");

        let (_crl_time, crl) = parse_crl(&crl_data, &crl_chain, Some(&root_cert), now).unwrap();

        // Verify that the tcb data is valid and signed
        let tcb_response = parse_tcb_response(&tcb_data).unwrap();
        assert_ok!(tcb_response.verify(tcb_chain, &crl, now));

        // Verify the quote
        let quote = parse_quote(&quote_data).unwrap();
        assert_ok!(quote.verify(&tcb_response.tcb_info, &crl, now));
    }
}

// =============================================================================
// Quote Parsing Tests
// =============================================================================

mod quote_parsing {
    use super::*;

    #[test]
    fn parse_valid_quote_90() {
        let quote_data = load_file("assets/tests/intel/quote_90.dat");
        assert_ok!(parse_quote(&quote_data));
    }
}

// =============================================================================
// Quote Verification Error Tests
// =============================================================================

mod quote_verification_errors {
    use super::*;

    #[test]
    fn verify_quote_without_certificates_fails() {
        let quote_data = load_file("assets/tests/intel/quote_no_cert.dat");
        let tcb_data = load_file("assets/tests/intel/tcb_info_90.json");

        let quote = parse_quote(&quote_data).unwrap();
        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

        let crl: Crl = vec![];
        let now = parse_timestamp("2026-02-03T09:32:53Z");

        let result = quote.verify(&tcb_response.tcb_info, &crl, now);
        assert!(matches!(result, Err(VerificationError::PKCChain)));
    }

    #[test]
    fn verify_quote_with_mismatched_fmspc_fails() {
        // Load the quote for the FMSPC starting with 90...
        let quote_data = load_file("assets/tests/intel/quote_90.dat");

        // And the tcb data for the FMSPC starting with B0
        let tcb_data = load_file("assets/tests/intel/tcb_info_b0.json");

        let quote = parse_quote(&quote_data).unwrap();
        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

        let crl: Crl = vec![];
        let now = parse_timestamp("2026-02-03T09:32:53Z");

        let result = quote.verify(&tcb_response.tcb_info, &crl, now);
        assert!(matches!(result, Err(VerificationError::FmspcMismatch)));
    }
}
