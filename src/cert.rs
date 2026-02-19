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
use alloc::vec::Vec;

use asn1_der::typed::{DerDecodable, Sequence};
use p256::ecdsa::signature::Verifier;
use spki::ObjectIdentifier;
use x509_verify::{
    x509_cert::{
        crl::CertificateList,
        der::{Decode, Encode},
        Certificate,
    },
    Signature, VerifyInfo, VerifyingKey,
};

/// Errors that can occur during certificate operations.
#[derive(Debug)]
pub enum CertificateError {
    /// Failed to parse certificate data.
    Parse,
    /// Public key verification failed.
    KeyVerification,
    /// The certificate chain is empty.
    EmptyChain,
    /// The certificate has no extensions.
    NoExtensions,
    /// A required extension was not found.
    ExtensionNotFound,
    /// The signature is invalid.
    BadSignature,
    /// The certificate has been revoked.
    RevokedCertificate,
    /// The certificate is not yet valid.
    CertificateNotYetValid,
    /// The certificate has expired.
    CertificateExpired,
}

/// Identifies a revoked certificate by its issuer and serial number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedCertId {
    /// DER-encoded issuer name.
    pub issuer: Vec<u8>,
    /// Serial number bytes.
    pub serial_number: Vec<u8>,
}

/// A certificate revocation list as a list of revoked certificate identifiers.
pub type Crl = Vec<RevokedCertId>;

fn verify_crl(crl: &CertificateList, key: &VerifyingKey) -> Result<(), CertificateError> {
    let verify_info = VerifyInfo::new(
        crl.tbs_cert_list
            .to_der()
            .map_err(|_| CertificateError::Parse)?
            .into(),
        Signature::new(
            &crl.signature_algorithm,
            crl.signature
                .as_bytes()
                .ok_or(CertificateError::BadSignature)?,
        ),
    );
    key.verify(&verify_info)
        .map_err(|_| CertificateError::KeyVerification)
}

pub fn verify_pem_cert_chain(
    pck_certificate_chain_pem: &Vec<u8>,
    root_cert: Option<&[u8]>,
    crl: Option<&Crl>,
    now: u64,
) -> Result<Certificate, CertificateError> {
    let pems = pem::parse_many(pck_certificate_chain_pem).map_err(|_| CertificateError::Parse)?;
    let certs: Result<Vec<Certificate>, _> = pems
        .into_iter()
        .map(|pem| Certificate::from_der(pem.contents()))
        .collect();
    let mut certs = certs.map_err(|_| CertificateError::Parse)?;

    if certs.is_empty() {
        return Err(CertificateError::EmptyChain);
    }

    if let Some(r) = root_cert {
        let root = Certificate::from_der(r).map_err(|_| CertificateError::Parse)?;
        certs.push(root);
    }
    for c in 0..certs.len() - 1 {
        let key: VerifyingKey = certs[c + 1]
            .tbs_certificate
            .subject_public_key_info
            .clone()
            .try_into()
            .map_err(|_| CertificateError::KeyVerification)?;
        verify_certificate(&certs[c], &key, crl, now)?;
    }

    Ok(certs[0].clone())
}

fn verify_certificate(
    cert: &Certificate,
    key: &VerifyingKey,
    crl: Option<&Crl>,
    now: u64,
) -> Result<(), CertificateError> {
    // Check certificate validity period
    let not_before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();

    if now < not_before {
        return Err(CertificateError::CertificateNotYetValid);
    }
    if now > not_after {
        return Err(CertificateError::CertificateExpired);
    }

    if let Some(c) = crl {
        let issuer = cert
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(|_| CertificateError::Parse)?;
        let serial = cert.tbs_certificate.serial_number.as_bytes().to_vec();
        let cert_id = RevokedCertId {
            issuer,
            serial_number: serial,
        };
        if c.contains(&cert_id) {
            return Err(CertificateError::RevokedCertificate);
        }
    }

    let verify_info = VerifyInfo::new(
        cert.tbs_certificate
            .to_der()
            .map_err(|_| CertificateError::Parse)?
            .into(),
        Signature::new(
            &cert.signature_algorithm,
            cert.signature
                .as_bytes()
                .ok_or(CertificateError::BadSignature)?,
        ),
    );
    key.verify(&verify_info)
        .map_err(|_| CertificateError::KeyVerification)
}

pub fn get_ext(cert: &Certificate, oid: ObjectIdentifier) -> Result<&[u8], CertificateError> {
    if cert.tbs_certificate.extensions.is_none() {
        return Err(CertificateError::NoExtensions);
    }
    if let Some(ext) = &cert.tbs_certificate.extensions {
        for e in ext {
            if e.extn_id == oid {
                return Ok(e.extn_value.as_bytes());
            }
        }
    }
    Err(CertificateError::ExtensionNotFound)
}

pub fn extract_field(data: &[u8], oid: ObjectIdentifier) -> Result<&[u8], CertificateError> {
    let seq = Sequence::decode(data).map_err(|_| CertificateError::ExtensionNotFound)?;

    for i in 0..seq.len() {
        let Ok(elem) = seq.get(i) else { continue };
        let Ok(item) = Sequence::load(elem) else {
            continue;
        };
        if item.len() < 2 {
            continue;
        }
        let Ok(oid_obj) = item.get(0) else { continue };
        if oid_obj.value() == oid.as_bytes() {
            let Ok(val_obj) = item.get(1) else { continue };
            return Ok(val_obj.value());
        }
    }
    Err(CertificateError::ExtensionNotFound)
}

/// Parse an ASN.1 sequence containing an OID-value pair
/// Returns (value bytes, total sequence length in bytes)
pub fn parse_oid_value_pair<'a>(
    data: &'a [u8],
    oid: &ObjectIdentifier,
) -> Result<(&'a [u8], usize), CertificateError> {
    // Calculate the DER-encoded length from the header
    // Tag (1 byte) + Length field (variable) + Content
    if data.len() < 2 {
        return Err(CertificateError::ExtensionNotFound);
    }

    let (content_len, header_len) = if data[1] < 128 {
        // Short form: length byte directly encodes the length
        (data[1] as usize, 2)
    } else {
        // Long form: data[1] & 0x7F is the number of length bytes
        let num_len_bytes = (data[1] & 0x7F) as usize;
        if data.len() < 2 + num_len_bytes {
            return Err(CertificateError::ExtensionNotFound);
        }
        let mut len: usize = 0;
        for i in 0..num_len_bytes {
            len = (len << 8) | (data[2 + i] as usize);
        }
        (len, 2 + num_len_bytes)
    };

    let seq_len = header_len + content_len;

    // Now decode just this sequence
    let seq =
        Sequence::decode(&data[..seq_len]).map_err(|_| CertificateError::ExtensionNotFound)?;

    if seq.len() != 2 {
        return Err(CertificateError::ExtensionNotFound);
    }

    let name = seq
        .get(0)
        .map_err(|_| CertificateError::ExtensionNotFound)?
        .value();
    if name[..name.len() - 1] != *oid.as_bytes() {
        return Err(CertificateError::ExtensionNotFound);
    }

    let val_obj = seq
        .get(1)
        .map_err(|_| CertificateError::ExtensionNotFound)?;

    Ok((val_obj.value(), seq_len))
}

pub fn verify_signature(
    cert: &Certificate,
    data: &[u8],
    signature: &[u8],
) -> Result<(), CertificateError> {
    let point = p256::EncodedPoint::from_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(CertificateError::BadSignature)?,
    )
    .map_err(|_| CertificateError::BadSignature)?;
    let pck_verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map_err(|_| CertificateError::BadSignature)?;

    pck_verifying_key
        .verify(
            data,
            &p256::ecdsa::Signature::from_bytes(signature.into())
                .map_err(|_| CertificateError::BadSignature)?,
        )
        .map_err(|_| CertificateError::BadSignature)?;
    Ok(())
}

// PUBLIC INTERFACE
pub fn parse_crl(
    crl_pem: &Vec<u8>,
    pck_certificate_chain_pem: &Vec<u8>,
    root_cert: Option<&[u8]>,
    now: u64,
) -> Result<(u64, Crl), CertificateError> {
    let pems = pem::parse_many(crl_pem).map_err(|_| CertificateError::Parse)?;
    let crls: Result<Vec<CertificateList>, _> = pems
        .into_iter()
        .map(|pem| CertificateList::from_der(pem.contents()))
        .collect();
    let crls = crls.map_err(|_| CertificateError::Parse)?;

    let sign_cert = verify_pem_cert_chain(pck_certificate_chain_pem, root_cert, None, now)?;
    let sign_key: VerifyingKey = sign_cert
        .tbs_certificate
        .subject_public_key_info
        .clone()
        .try_into()
        .map_err(|_| CertificateError::KeyVerification)?;

    let mut revoked_certs: Crl = Vec::new();
    let mut latest_this_update: u64 = 0;

    for crl in &crls {
        verify_crl(crl, &sign_key)?;

        // Extract this_update and track the latest one
        let this_update_duration = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();

        latest_this_update = match this_update_duration {
            current if current > this_update_duration => current,
            _ => this_update_duration,
        };

        let issuer = crl
            .tbs_cert_list
            .issuer
            .to_der()
            .map_err(|_| CertificateError::Parse)?;

        if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
            for entry in revoked {
                revoked_certs.push(RevokedCertId {
                    issuer: issuer.clone(),
                    serial_number: entry.serial_number.as_bytes().to_vec(),
                });
            }
        }
    }

    Ok((latest_this_update, revoked_certs))
}

#[cfg(test)]
mod should {
    use crate::cert::{parse_crl, CertificateError};
    use chrono::DateTime;
    use rstest::rstest;
    use std::{fs::File, io::Read};

    fn load_file(path: &str) -> Vec<u8> {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    fn load_root_cert() -> Vec<u8> {
        load_file("assets/Intel_SGX_Provisioning_Certification_RootCA.cer")
    }

    #[rstest]
    #[case(
        "assets/tests/intel/crl.pem",
        "assets/tests/intel/crl_chain.pem",
        "2026-02-03T09:32:53Z"
    )]
    #[case(
        "assets/tests/intel/crl_platform.pem",
        "assets/tests/intel/crl_chain_platform.pem",
        "2026-02-03T10:55:02Z"
    )]
    #[should_panic(expected = "KeyVerification")]
    #[case(
        "assets/tests/intel/crl_platform.pem",
        "assets/tests/intel/crl_chain_platform_ko.pem",
        "2026-02-03T10:55:02Z"
    )]
    fn parse_quote(#[case] crl_path: &str, #[case] crl_chain_path: &str, #[case] exp_date: &str) {
        let crl_buf = load_file(crl_path);
        let crl_chain_buf = load_file(crl_chain_path);
        let root_buf = load_root_cert();

        let now = DateTime::parse_from_rfc3339(exp_date)
            .unwrap()
            .timestamp()
            .try_into()
            .unwrap();
        let (date, _crl) = parse_crl(&crl_buf, &crl_chain_buf, Some(&root_buf), now).unwrap();
        assert_eq!(date, now);
    }

    #[rstest]
    #[case(
        "assets/tests/intel/crl.pem",
        "assets/tests/intel/crl_chain.pem",
        // Before certificate notBefore (May 21 2018)
        "2018-01-01T00:00:00Z"
    )]
    fn reject_certificate_not_yet_valid(
        #[case] crl_path: &str,
        #[case] crl_chain_path: &str,
        #[case] timestamp: &str,
    ) {
        let crl_buf = load_file(crl_path);
        let crl_chain_buf = load_file(crl_chain_path);
        let root_buf = load_root_cert();

        let now = DateTime::parse_from_rfc3339(timestamp).unwrap().timestamp() as u64;

        let result = parse_crl(&crl_buf, &crl_chain_buf, Some(&root_buf), now);
        assert!(matches!(
            result,
            Err(CertificateError::CertificateNotYetValid)
        ));
    }

    #[rstest]
    #[case(
        "assets/tests/intel/crl.pem",
        "assets/tests/intel/crl_chain.pem",
        // After certificate notAfter (May 21 2033)
        "2034-01-01T00:00:00Z"
    )]
    fn reject_certificate_expired(
        #[case] crl_path: &str,
        #[case] crl_chain_path: &str,
        #[case] timestamp: &str,
    ) {
        let crl_buf = load_file(crl_path);
        let crl_chain_buf = load_file(crl_chain_path);
        let root_buf = load_root_cert();

        let now = DateTime::parse_from_rfc3339(timestamp).unwrap().timestamp() as u64;

        let result = parse_crl(&crl_buf, &crl_chain_buf, Some(&root_buf), now);
        assert!(matches!(result, Err(CertificateError::CertificateExpired)));
    }
}
