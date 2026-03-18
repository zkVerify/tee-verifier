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

//! Integration tests for Nitro attestation verification.
//!
//! These tests verify the parsing and verification of AWS Nitro Enclave
//! attestation documents using real attestation fixtures.

use std::fs::File;
use std::io::Read;

use assert_ok::assert_ok;

use tee_verifier::{
    nitro_parse_attestation, parse_crl_der, Crl,
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
    fn parse_valid_attestation_doc() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        assert_ok!(nitro_parse_attestation(&data));
    }
}

// =============================================================================
// End-to-End Nitro Attestation Verification Tests
// =============================================================================

mod end_to_end {
    use super::*;

    #[test]
    fn verify_attestation_doc_with_crl() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let nitro_root = load_file("assets/aws_nitro_root_g1.der");
        let att = nitro_parse_attestation(&data).unwrap();

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
            parse_crl_der(&root_crl_data, &att.cabundle[0], Some(&nitro_root), now).unwrap();
        let (_time2, crl2) =
            parse_crl_der(&zonal_crl_data, &zonal_chain, Some(&nitro_root), now).unwrap();

        let mut crl: Crl = crl1;
        crl.extend(crl2);

        assert_ok!(att.verify(Some(&crl), now));
    }
}


