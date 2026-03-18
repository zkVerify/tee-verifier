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

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use p384::ecdsa::signature::Verifier;
use x509_verify::x509_cert::Certificate;

/// Errors that can occur when parsing a Nitro attestation document.
#[derive(Debug)]
pub enum NitroParseError {
    /// The input is not a valid COSE_Sign1 structure.
    InvalidCoseSign1,
    /// The COSE_Sign1 payload is missing or invalid.
    InvalidPayload,
    /// A mandatory field is missing from the attestation document.
    MissingField(&'static str),
    /// A field has an unexpected type or value.
    InvalidField(&'static str),
    /// A certificate in the document could not be parsed.
    InvalidCertificate,
    /// The COSE protected header specifies an unsupported algorithm.
    UnsupportedAlgorithm,
}

/// Errors that can occur when verifying a Nitro attestation document.
#[derive(Debug)]
pub enum NitroVerificationError {
    /// The ECDSA signature over the COSE Sig_structure is invalid.
    BadSignature,
    /// The certificate chain verification failed.
    CertificateChain,
    /// A certificate in the chain has expired or is not yet valid.
    CertificateExpired,
    /// The enclave is running in debug mode.
    DebugMode,
    /// The leaf certificate's public key could not be extracted.
    InvalidPublicKey,
    /// The attestation document's digest algorithm is not "SHA384".
    UnsupportedDigest,
}

/// A parsed AWS Nitro Enclave attestation document.
pub struct NitroAttestation {
    /// The issuing Nitro enclave module ID.
    pub module_id: String,
    /// The digest algorithm used (must be "SHA384").
    pub digest: String,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp: u64,
    /// Platform Configuration Registers (index → value).
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    /// DER-encoded leaf certificate that signed this document.
    pub certificate: Vec<u8>,
    /// DER-encoded CA bundle certificates (root-first).
    pub cabundle: Vec<Vec<u8>>,
    /// Optional public key provided by the enclave.
    pub public_key: Option<Vec<u8>>,
    /// Optional user data provided by the enclave.
    pub user_data: Option<Vec<u8>>,
    /// Optional nonce for replay protection.
    pub nonce: Option<Vec<u8>>,

    // Internal fields for COSE_Sign1 verification
    protected_header_bytes: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

/// Parse a Nitro attestation document from binary COSE_Sign1 data.
pub fn parse_attestation(input: &[u8]) -> Result<NitroAttestation, NitroParseError> {
    // Decode COSE_Sign1 — accept both tagged (CBOR tag 18) and untagged forms
    let cose_sign1 = CoseSign1::from_tagged_slice(input)
        .or_else(|_| CoseSign1::from_slice(input))
        .map_err(|_| NitroParseError::InvalidCoseSign1)?;

    // Verify the algorithm is ES384
    let alg = cose_sign1
        .protected
        .header
        .alg
        .as_ref()
        .ok_or(NitroParseError::UnsupportedAlgorithm)?;
    match alg {
        coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES384) => {}
        _ => return Err(NitroParseError::UnsupportedAlgorithm),
    }

    // Extract payload
    let payload_bytes = cose_sign1
        .payload
        .as_ref()
        .ok_or(NitroParseError::InvalidPayload)?
        .clone();

    // Decode payload as CBOR map
    let payload_value: ciborium::Value = ciborium::from_reader(payload_bytes.as_slice())
        .map_err(|_| NitroParseError::InvalidPayload)?;

    let map = match &payload_value {
        ciborium::Value::Map(m) => m,
        _ => return Err(NitroParseError::InvalidPayload),
    };

    // Extract mandatory fields
    let module_id = get_text_field(map, "module_id")?;
    let digest = get_text_field(map, "digest")?;
    let timestamp = get_integer_field(map, "timestamp")?;
    let pcrs = get_pcrs(map)?;
    let certificate = get_bytes_field(map, "certificate")?;
    let cabundle = get_cabundle(map)?;

    // Extract optional fields
    let public_key = get_optional_bytes_field(map, "public_key");
    let user_data = get_optional_bytes_field(map, "user_data");
    let nonce = get_optional_bytes_field(map, "nonce");

    // Store internal COSE components for later verification
    let protected_header_bytes = cose_sign1
        .protected
        .original_data
        .as_deref()
        .unwrap_or(&[])
        .to_vec();
    let signature = cose_sign1.signature.clone();

    Ok(NitroAttestation {
        module_id,
        digest,
        timestamp,
        pcrs,
        certificate,
        cabundle,
        public_key,
        user_data,
        nonce,
        protected_header_bytes,
        payload: payload_bytes,
        signature,
    })
}

impl NitroAttestation {
    /// Verify the attestation document against the embedded AWS Nitro root CA.
    ///
    /// `crl` is an optional certificate revocation list to check against.
    /// `now` is the current time as seconds since Unix epoch.
    pub fn verify(
        &self,
        crl: Option<&crate::cert::Crl>,
        now: u64,
    ) -> Result<(), NitroVerificationError> {
        if self.digest != "SHA384" {
            return Err(NitroVerificationError::UnsupportedDigest);
        }

        // Build the certificate chain: cabundle (root → intermediates) + leaf
        // cabundle is root-first, so the chain for verification is:
        // leaf → last_intermediate → ... → first_intermediate → cabundle_root → embedded_root
        let mut chain_refs: Vec<&[u8]> = Vec::new();
        chain_refs.push(self.certificate.as_slice());
        for cert_der in self.cabundle.iter().rev() {
            chain_refs.push(cert_der.as_slice());
        }

        // Verify the certificate chain against the embedded AWS root
        let leaf = crate::cert::verify_cert_chain_der(
            &chain_refs,
            Some(crate::nitro::ROOT_CERT),
            crl,
            now,
        )
        .map_err(|_| NitroVerificationError::CertificateChain)?;

        // Build COSE Sig_structure for verification:
        // Sig_structure = ["Signature1", protected, external_aad, payload]
        let protected_header = coset::ProtectedHeader::from_cbor_bstr(
            coset::cbor::value::Value::Bytes(self.protected_header_bytes.clone()),
        )
        .map_err(|_| NitroVerificationError::BadSignature)?;
        let sig_structure = coset::sig_structure_data(
            coset::SignatureContext::CoseSign1,
            protected_header,
            None,
            &[],
            &self.payload,
        );

        // Extract the public key from the leaf certificate and verify the signature
        self.verify_es384_signature(&leaf, &sig_structure)?;

        Ok(())
    }

    fn verify_es384_signature(
        &self,
        cert: &Certificate,
        data: &[u8],
    ) -> Result<(), NitroVerificationError> {
        let pk_bytes = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(NitroVerificationError::InvalidPublicKey)?;

        let point = p384::EncodedPoint::from_bytes(pk_bytes)
            .map_err(|_| NitroVerificationError::InvalidPublicKey)?;
        let verifying_key = p384::ecdsa::VerifyingKey::from_encoded_point(&point)
            .map_err(|_| NitroVerificationError::InvalidPublicKey)?;

        // COSE signatures use raw (R || S) format, not DER
        let signature = p384::ecdsa::Signature::from_slice(&self.signature)
            .map_err(|_| NitroVerificationError::BadSignature)?;

        verifying_key
            .verify(data, &signature)
            .map_err(|_| NitroVerificationError::BadSignature)?;

        Ok(())
    }
}

// =============================================================================
// CBOR field extraction helpers
// =============================================================================

type CborMap = Vec<(ciborium::Value, ciborium::Value)>;

fn find_field<'a>(map: &'a CborMap, key: &str) -> Option<&'a ciborium::Value> {
    map.iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == key))
        .map(|(_, v)| v)
}

fn get_text_field(map: &CborMap, key: &'static str) -> Result<String, NitroParseError> {
    match find_field(map, key) {
        Some(ciborium::Value::Text(s)) => Ok(s.clone()),
        Some(_) => Err(NitroParseError::InvalidField(key)),
        None => Err(NitroParseError::MissingField(key)),
    }
}

fn get_integer_field(map: &CborMap, key: &'static str) -> Result<u64, NitroParseError> {
    match find_field(map, key) {
        Some(ciborium::Value::Integer(i)) => {
            let val: i128 = (*i).into();
            u64::try_from(val).map_err(|_| NitroParseError::InvalidField(key))
        }
        Some(_) => Err(NitroParseError::InvalidField(key)),
        None => Err(NitroParseError::MissingField(key)),
    }
}

fn get_bytes_field(map: &CborMap, key: &'static str) -> Result<Vec<u8>, NitroParseError> {
    match find_field(map, key) {
        Some(ciborium::Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(NitroParseError::InvalidField(key)),
        None => Err(NitroParseError::MissingField(key)),
    }
}

fn get_optional_bytes_field(map: &CborMap, key: &str) -> Option<Vec<u8>> {
    match find_field(map, key) {
        Some(ciborium::Value::Bytes(b)) => Some(b.clone()),
        Some(ciborium::Value::Null) => None,
        _ => None,
    }
}

fn get_pcrs(map: &CborMap) -> Result<BTreeMap<u32, Vec<u8>>, NitroParseError> {
    let pcrs_value = find_field(map, "pcrs").ok_or(NitroParseError::MissingField("pcrs"))?;
    let pcrs_map = match pcrs_value {
        ciborium::Value::Map(m) => m,
        _ => return Err(NitroParseError::InvalidField("pcrs")),
    };

    let mut result = BTreeMap::new();
    for (k, v) in pcrs_map {
        let index = match k {
            ciborium::Value::Integer(i) => {
                let val: i128 = (*i).into();
                u32::try_from(val).map_err(|_| NitroParseError::InvalidField("pcrs"))?
            }
            _ => return Err(NitroParseError::InvalidField("pcrs")),
        };
        let value = match v {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => return Err(NitroParseError::InvalidField("pcrs")),
        };
        result.insert(index, value);
    }
    Ok(result)
}

fn get_cabundle(map: &CborMap) -> Result<Vec<Vec<u8>>, NitroParseError> {
    let value = find_field(map, "cabundle").ok_or(NitroParseError::MissingField("cabundle"))?;
    let arr = match value {
        ciborium::Value::Array(a) => a,
        _ => return Err(NitroParseError::InvalidField("cabundle")),
    };

    arr.iter()
        .map(|v| match v {
            ciborium::Value::Bytes(b) => Ok(b.clone()),
            _ => Err(NitroParseError::InvalidField("cabundle")),
        })
        .collect()
}

#[cfg(test)]
mod should {
    use super::*;
    use assert_ok::assert_ok;
    use std::fs::File;
    use std::io::Read;

    /// Helper function to load a file into a byte vector
    fn load_file(path: &str) -> Vec<u8> {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    mod parse {
        use super::*;

        #[test]
        fn parse_empty_input_fails() {
            let result = parse_attestation(&[]);
            assert!(matches!(result, Err(NitroParseError::InvalidCoseSign1)));
        }

        #[test]
        fn parse_invalid_cbor_fails() {
            let result = parse_attestation(&[0xFF, 0xFF, 0xFF]);
            assert!(matches!(result, Err(NitroParseError::InvalidCoseSign1)));
        }

        #[test]
        fn parse_valid_attestation_doc() {
            let data = load_file("assets/tests/nitro/attestation_doc.bin");
            let att = assert_ok!(parse_attestation(&data));

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
            let att = assert_ok!(parse_attestation(&data));

            assert_eq!(att.module_id, "i-07a18ebd3db1ea8f6-enc019c28bed89f04b9");
            assert_eq!(att.digest, "SHA384");
            // 2026-02-13T16:29:13.369Z
            assert_eq!(att.timestamp, 1771000153369);
            assert_eq!(att.pcrs.len(), 16);
            assert!(att.public_key.is_some());
            assert!(att.user_data.is_some());
            assert!(att.nonce.is_none());
        }
    }

    mod verify {
        use super::*;

        #[test]
        fn verify_attestation_doc() {
            let data = load_file("assets/tests/nitro/attestation_doc.bin");
            let att = parse_attestation(&data).unwrap();

            // Use the document's own timestamp (converted from ms to seconds)
            // since the embedded certificates have a short validity window.
            // 2022-11-09T22:52:00Z
            let now = att.timestamp / 1000;
            assert_ok!(att.verify(None, now));
        }

        #[test]
        fn verify_attestation_doc_2() {
            let data = load_file("assets/tests/nitro/attestation_doc_2.bin");
            let att = parse_attestation(&data).unwrap();

            // 2026-02-13T16:29:13Z
            let now = att.timestamp / 1000;
            assert_ok!(att.verify(None, now));
        }
    }

    mod verification_errors {
        use super::*;

        #[test]
        fn verify_bad_signature_fails() {
            let data = load_file("assets/tests/nitro/attestation_doc_bad_sig.bin");
            let att = parse_attestation(&data).unwrap();

            // 2022-11-09T22:52:00Z
            let now = att.timestamp / 1000;
            let result = att.verify(None, now);
            assert!(matches!(result, Err(NitroVerificationError::BadSignature)));
        }

        #[test]
        fn verify_with_expired_timestamp_fails() {
            let data = load_file("assets/tests/nitro/attestation_doc.bin");
            let att = parse_attestation(&data).unwrap();

            // One year after the document timestamp certificates will have expired.
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
            let att = parse_attestation(&data).unwrap();

            // 1970-01-01T00:00:00Z certificates will not yet be valid.
            let now = 0;
            let result = att.verify(None, now);
            assert!(matches!(
                result,
                Err(NitroVerificationError::CertificateChain)
            ));
        }
    }
}
