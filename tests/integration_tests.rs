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
use tee_verifier::cert::{parse_crl, CertificateError, Crl};
use tee_verifier::intel::collaterals::{parse_tcb_response, CollateralError};
use tee_verifier::intel::quote::{parse_quote, ParseError, VerificationError};

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
    fn verify_quote_90() {
        let quote_data = load_file("assets/tests/intel/quote_90.dat");
        let crl_data = load_file("assets/tests/intel/crl.pem");
        let crl_chain = load_file("assets/tests/intel/crl_chain.pem");
        let tcb_data = load_file("assets/tests/intel/tcb_info_90.json");
        let root_cert = load_root_cert();

        let now = parse_timestamp("2026-02-03T09:32:53Z");

        let (_crl_time, crl) = parse_crl(&crl_data, &crl_chain, Some(&root_cert), now).unwrap();

        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

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

    #[test]
    fn parse_truncated_header_fails() {
        let result = parse_quote(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_header_fails() {
        let quote_data = load_file("assets/tests/intel/quote_90.dat");
        let mut invalid_data = quote_data.clone();
        invalid_data[2] = 0xFF;
        invalid_data[3] = 0xFF;

        let result = parse_quote(&invalid_data);
        assert!(matches!(
            result,
            Err(ParseError::UnsupportedAttestationKeyType)
        ));
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
        let quote_data = load_file("assets/tests/intel/quote_90.dat");
        let tcb_data = load_file("assets/tests/intel/tcb_info_b0.json");

        let quote = parse_quote(&quote_data).unwrap();
        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

        let crl: Crl = vec![];
        let now = parse_timestamp("2026-02-03T09:32:53Z");

        let result = quote.verify(&tcb_response.tcb_info, &crl, now);
        assert!(matches!(result, Err(VerificationError::FmspcMismatch)));
    }
}

// =============================================================================
// CRL Parsing and Verification Tests
// =============================================================================

mod crl_verification {
    use super::*;

    #[test]
    fn parse_valid_crl() {
        let crl_data = load_file("assets/tests/intel/crl.pem");
        let crl_chain = load_file("assets/tests/intel/crl_chain.pem");
        let root_cert = load_root_cert();
        let now = parse_timestamp("2026-02-03T09:32:53Z");

        let (crl_time, _crl) = assert_ok!(parse_crl(&crl_data, &crl_chain, Some(&root_cert), now));
        assert_eq!(crl_time, now);
    }

    #[test]
    fn crl_with_invalid_chain_fails() {
        let crl_data = load_file("assets/tests/intel/crl_platform.pem");
        let crl_chain = load_file("assets/tests/intel/crl_chain_platform_ko.pem");
        let root_cert = load_root_cert();
        let now = parse_timestamp("2026-02-03T10:55:02Z");

        let result = parse_crl(&crl_data, &crl_chain, Some(&root_cert), now);
        assert!(matches!(result, Err(CertificateError::KeyVerification)));
    }

    #[test]
    fn crl_before_certificate_validity_fails() {
        let crl_data = load_file("assets/tests/intel/crl.pem");
        let crl_chain = load_file("assets/tests/intel/crl_chain.pem");
        let root_cert = load_root_cert();
        let now = parse_timestamp("2018-01-01T00:00:00Z");

        let result = parse_crl(&crl_data, &crl_chain, Some(&root_cert), now);
        assert!(matches!(
            result,
            Err(CertificateError::CertificateNotYetValid)
        ));
    }

    #[test]
    fn crl_after_certificate_expiry_fails() {
        let crl_data = load_file("assets/tests/intel/crl.pem");
        let crl_chain = load_file("assets/tests/intel/crl_chain.pem");
        let root_cert = load_root_cert();
        let now = parse_timestamp("2034-01-01T00:00:00Z");

        let result = parse_crl(&crl_data, &crl_chain, Some(&root_cert), now);
        assert!(matches!(result, Err(CertificateError::CertificateExpired)));
    }
}

// =============================================================================
// TCB Collateral Verification Tests
// =============================================================================

mod tcb_verification {
    use super::*;

    #[test]
    fn parse_tcb_info_90() {
        let tcb_data = load_file("assets/tests/intel/tcb_info_90.json");
        assert_ok!(parse_tcb_response(&tcb_data));
    }

    #[test]
    fn verify_tcb_info_valid_timestamp() {
        let tcb_data = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

        let now = parse_timestamp("2026-01-23T16:43:44Z");
        assert_ok!(tcb_response.tcb_info.verify(now));
    }

    #[test]
    fn verify_tcb_info_too_early_fails() {
        let tcb_data = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

        let now = parse_timestamp("2026-01-03T16:43:44Z");
        let result = tcb_response.tcb_info.verify(now);
        assert!(matches!(result, Err(CollateralError::TooEarly)));
    }

    #[test]
    fn verify_tcb_info_expired_fails() {
        let tcb_data = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

        let now = parse_timestamp("2026-03-03T16:43:44Z");
        let result = tcb_response.tcb_info.verify(now);
        assert!(matches!(result, Err(CollateralError::Expired)));
    }

    #[test]
    fn verify_tcb_response_with_certificate_chain() {
        let tcb_data = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb_chain = load_file("assets/tests/intel/tcb_info_90.pem");

        let tcb_response = parse_tcb_response(&tcb_data).unwrap();

        let crl: Crl = vec![];
        let now = parse_timestamp("2026-01-23T16:43:44Z");

        assert_ok!(tcb_response.verify(tcb_chain, now, &crl));
    }
}
