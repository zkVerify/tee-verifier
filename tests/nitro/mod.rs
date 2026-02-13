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

//! Integration tests for Nitro attestation verification.
//!
//! These tests verify the parsing and verification of AWS Nitro Enclave
//! attestation documents using real attestation fixtures.

use std::fs::File;
use std::io::Read;

use assert_ok::assert_ok;

use tee_verifier::{
    parse_der_crl, parse_nitro_attestation, Crl, NitroParseError, NitroVerificationError,
};

/// Helper function to load a file into a byte vector
fn load_file(path: &str) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    buf
}

// =============================================================================
// Nitro Attestation Parsing Tests
// =============================================================================

mod nitro_parsing {
    use super::*;

    #[test]
    fn parse_empty_input_fails() {
        let result = parse_nitro_attestation(&[]);
        assert!(matches!(result, Err(NitroParseError::InvalidCoseSign1)));
    }

    #[test]
    fn parse_invalid_cbor_fails() {
        let result = parse_nitro_attestation(&[0xFF, 0xFF, 0xFF]);
        assert!(matches!(result, Err(NitroParseError::InvalidCoseSign1)));
    }

    #[test]
    fn parse_valid_attestation_doc() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = assert_ok!(parse_nitro_attestation(&data));

        assert_eq!(att.module_id, "i-04fd167167daacf3b-enc01845e97d0b3eb4e");
        assert_eq!(att.digest, "SHA384");
        // 2022-11-09T22:52:00.696Z
        assert_eq!(att.timestamp, 1668034320696);
        assert_eq!(att.pcrs.len(), 16);
        assert_eq!(att.cabundle.len(), 4);
        assert!(att.public_key.is_none());
        assert!(att.user_data.is_some());
        assert!(att.nonce.is_some());
    }

    #[test]
    fn parse_valid_attestation_doc_2() {
        let data = load_file("assets/tests/nitro/attestation_doc_2.bin");
        let att = assert_ok!(parse_nitro_attestation(&data));

        assert_eq!(att.module_id, "i-0a22e5c5f24d22174-enc0191cceb4289903f");
        assert_eq!(att.digest, "SHA384");
        // 2024-09-07T14:37:39.545Z
        assert_eq!(att.timestamp, 1725719859545);
        assert_eq!(att.pcrs.len(), 16);
        assert!(att.public_key.is_some());
        assert!(att.nonce.is_some());
    }
}

// =============================================================================
// End-to-End Nitro Attestation Verification Tests
// =============================================================================

mod end_to_end {
    use super::*;

    #[test]
    fn verify_attestation_doc() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = parse_nitro_attestation(&data).unwrap();

        // Use the document's own timestamp (converted from ms to seconds)
        // since the embedded certificates have a short validity window.
        // 2022-11-09T22:52:00Z
        let now = att.timestamp / 1000;
        assert_ok!(att.verify(None, now));
    }

    #[test]
    fn verify_attestation_doc_2() {
        let data = load_file("assets/tests/nitro/attestation_doc_2.bin");
        let att = parse_nitro_attestation(&data).unwrap();

        // 2024-09-07T14:37:39Z
        let now = att.timestamp / 1000;
        assert_ok!(att.verify(None, now));
    }

    #[test]
    fn verify_attestation_doc_with_crl() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let nitro_root = load_file("assets/aws_nitro_root_g1.der");
        let att = parse_nitro_attestation(&data).unwrap();

        // 2022-11-09T22:52:00Z
        let now = att.timestamp / 1000;

        // Parse CRLs using signing certificate chains from the attestation's cabundle.
        // Chains are concatenated DER: leaf-first, root-last.
        // Root CRL: signed by cabundle[0] (root).
        // Zonal CRL: signed by cabundle[1] (first intermediate),
        //   chain is cabundle[1] || cabundle[0].
        let root_crl_data = load_file("assets/tests/nitro/crl_root.der");
        let zonal_crl_data = load_file("assets/tests/nitro/crl_zonal.der");

        let zonal_chain: Vec<u8> = att.cabundle[0..2]
            .iter()
            .rev()
            .flat_map(|c| c.iter().copied())
            .collect();

        let (_time1, crl1) =
            parse_der_crl(&root_crl_data, &att.cabundle[0], Some(&nitro_root), now).unwrap();
        let (_time2, crl2) =
            parse_der_crl(&zonal_crl_data, &zonal_chain, Some(&nitro_root), now).unwrap();

        let mut crl: Crl = crl1;
        crl.extend(crl2);

        assert_ok!(att.verify(Some(&crl), now));
    }
}

// =============================================================================
// Nitro Attestation Verification Error Tests
// =============================================================================

mod verification_errors {
    use super::*;

    #[test]
    fn verify_bad_signature_fails() {
        let data = load_file("assets/tests/nitro/attestation_doc_bad_sig.bin");
        let att = parse_nitro_attestation(&data).unwrap();

        // 2022-11-09T22:52:00Z
        let now = att.timestamp / 1000;
        let result = att.verify(None, now);
        assert!(matches!(result, Err(NitroVerificationError::BadSignature)));
    }

    #[test]
    fn verify_with_expired_timestamp_fails() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = parse_nitro_attestation(&data).unwrap();

        // One year after the document timestamp — certificates will have expired.
        // ~2023-11-09
        let now = att.timestamp / 1000 + 365 * 24 * 3600;
        let result = att.verify(None, now);
        assert!(matches!(
            result,
            Err(NitroVerificationError::CertificateChain)
        ));
    }

    #[test]
    fn verify_with_past_timestamp_fails() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = parse_nitro_attestation(&data).unwrap();

        // 1970-01-01T00:00:00Z — certificates will not yet be valid.
        let now = 0;
        let result = att.verify(None, now);
        assert!(matches!(
            result,
            Err(NitroVerificationError::CertificateChain)
        ));
    }
}
