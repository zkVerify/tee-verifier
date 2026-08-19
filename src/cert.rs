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
        der::{Decode, Encode, Reader, SliceReader},
        ext::pkix::{BasicConstraints, KeyUsage, KeyUsages},
        Certificate,
    },
    Signature, VerifyInfo, VerifyingKey,
};

// RFC 5280 §4.2.1.9 BasicConstraints, §4.2.1.3 KeyUsage.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

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
    /// Expected exactly one CRL, but found multiple.
    MultipleCrls,
    /// An X.509 extension was present but could not be parsed.
    MalformedExtension,
    /// A non-leaf certificate is missing `BasicConstraints.cA = TRUE`.
    NotACertificateAuthority,
    /// A non-leaf certificate has a `KeyUsage` extension but lacks `keyCertSign`.
    MissingKeyCertSign,
    /// A CRL signer has a `KeyUsage` extension but lacks `cRLSign`.
    MissingCrlSign,
    /// `certs[i].issuer` does not equal `certs[i+1].subject` (DER-equal).
    IssuerSubjectMismatch,
    /// A `BasicConstraints.pathLenConstraint` is violated by the chain length.
    PathLenExceeded,
    /// The CRL's `issuer` field does not match the signing certificate's `subject`.
    CrlIssuerMismatch,
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

pub fn verify_cert_chain_pem(
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
    let certs = certs.map_err(|_| CertificateError::Parse)?;
    verify_cert_chain(certs, root_cert, crl, now)
}

pub fn verify_cert_chain_der(
    der_certs: &[&[u8]],
    root_cert: Option<&[u8]>,
    crl: Option<&Crl>,
    now: u64,
) -> Result<Certificate, CertificateError> {
    let certs: Result<Vec<Certificate>, _> = der_certs
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect();
    let certs = certs.map_err(|_| CertificateError::Parse)?;
    verify_cert_chain(certs, root_cert, crl, now)
}

fn verify_cert_chain(
    mut certs: Vec<Certificate>,
    root_cert: Option<&[u8]>,
    crl: Option<&Crl>,
    now: u64,
) -> Result<Certificate, CertificateError> {
    if certs.is_empty() {
        return Err(CertificateError::EmptyChain);
    }

    if let Some(r) = root_cert {
        let root = Certificate::from_der(r).map_err(|_| CertificateError::Parse)?;
        // The PEM/DER chain may already include the root (typical of Intel
        // PCK chains). Appending again would inflate path-length counts and
        // double-check the same signature, so skip if subject+SPKI match.
        let already_present = certs.last().is_some_and(|last| {
            last.tbs_certificate.subject == root.tbs_certificate.subject
                && last.tbs_certificate.subject_public_key_info
                    == root.tbs_certificate.subject_public_key_info
        });
        if !already_present {
            certs.push(root);
        }
    }

    // Walk the certificate chain from the root down to the leaf, so that the Root CA domain is
    // enforced immediately.
    for c in (0..certs.len() - 1).rev() {
        let parent = &certs[c + 1];

        // RFC 5280 §4.1.2.4 / §4.1.2.6: name chaining.
        let child_issuer = certs[c]
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(|_| CertificateError::Parse)?;
        let parent_subject = parent
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|_| CertificateError::Parse)?;
        if child_issuer != parent_subject {
            return Err(CertificateError::IssuerSubjectMismatch);
        }

        // RFC 5280 §4.2.1.9 / §4.2.1.3: the issuing cert must be a CA (a
        // missing BasicConstraints extension or `cA = FALSE` is equivalent
        // here), and (if KeyUsage is present) must assert keyCertSign.
        let bc = basic_constraints(parent)?;
        if !bc.as_ref().map(|b| b.ca).unwrap_or(false) {
            return Err(CertificateError::NotACertificateAuthority);
        }
        if let Some(ku) = key_usage(parent)? {
            if !ku.0.contains(KeyUsages::KeyCertSign) {
                return Err(CertificateError::MissingKeyCertSign);
            }
        }
        // RFC 5280 §4.2.1.9: pathLenConstraint bounds the number of
        // non-self-issued intermediate CAs that may follow this cert toward
        // the end-entity. With certs[0] as the end-entity, intermediates
        // strictly between `parent` (index c+1) and the end-entity are at
        // indices 1..=c, i.e. `c` of them.
        if let Some(path_len) = bc.and_then(|b| b.path_len_constraint) {
            if c > path_len as usize {
                return Err(CertificateError::PathLenExceeded);
            }
        }

        let key: VerifyingKey = parent
            .tbs_certificate
            .subject_public_key_info
            .clone()
            .try_into()
            .map_err(|_| CertificateError::KeyVerification)?;
        verify_certificate(&certs[c], &key, crl, now)?;
    }

    Ok(certs[0].clone())
}

fn find_ext(cert: &Certificate, oid: ObjectIdentifier) -> Option<&[u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

fn basic_constraints(cert: &Certificate) -> Result<Option<BasicConstraints>, CertificateError> {
    find_ext(cert, OID_BASIC_CONSTRAINTS)
        .map(|raw| {
            BasicConstraints::from_der(raw).map_err(|_| CertificateError::MalformedExtension)
        })
        .transpose()
}

fn key_usage(cert: &Certificate) -> Result<Option<KeyUsage>, CertificateError> {
    find_ext(cert, OID_KEY_USAGE)
        .map(|raw| KeyUsage::from_der(raw).map_err(|_| CertificateError::MalformedExtension))
        .transpose()
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
        if num_len_bytes == 0
            || num_len_bytes > core::mem::size_of::<usize>()
            || data.len() < 2 + num_len_bytes
        {
            return Err(CertificateError::ExtensionNotFound);
        }
        let mut len: usize = 0;
        for i in 0..num_len_bytes {
            len = (len << 8) | (data[2 + i] as usize);
        }
        (len, 2 + num_len_bytes)
    };

    if content_len > data.len() - header_len {
        return Err(CertificateError::ExtensionNotFound);
    }
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
    if name.is_empty() || name[..name.len() - 1] != *oid.as_bytes() {
        return Err(CertificateError::ExtensionNotFound);
    }

    let val_obj = seq
        .get(1)
        .map_err(|_| CertificateError::ExtensionNotFound)?;

    Ok((val_obj.value(), seq_len))
}

/// Decode a non-negative DER `INTEGER`: big-endian, with a leading `0x00` sign pad.
pub fn der_uint(bytes: &[u8]) -> Result<u64, CertificateError> {
    let Some(first) = bytes.first() else {
        return Err(CertificateError::MalformedExtension);
    };
    if first & 0x80 != 0 {
        return Err(CertificateError::MalformedExtension);
    }
    let magnitude = bytes.strip_prefix(&[0x00]).unwrap_or(bytes);
    if magnitude.len() > 8 {
        return Err(CertificateError::MalformedExtension);
    }
    Ok(magnitude
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
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

/// Verify a CRL's signature and extract its revoked certificate entries.
fn process_crl(
    crl: &CertificateList,
    sign_cert: &Certificate,
) -> Result<(u64, Crl), CertificateError> {
    // RFC 5280 §5.1.2.3: the CRL's issuer must equal the signing cert's subject.
    let crl_issuer_der = crl
        .tbs_cert_list
        .issuer
        .to_der()
        .map_err(|_| CertificateError::Parse)?;
    let sign_subject_der = sign_cert
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|_| CertificateError::Parse)?;
    if crl_issuer_der != sign_subject_der {
        return Err(CertificateError::CrlIssuerMismatch);
    }

    // RFC 5280 §4.2.1.3: if the signer has a KeyUsage extension, it must
    // assert cRLSign. (Either a CA cert with cRLSign, or a delegated CRL
    // signer; we don't require cA here so both are accepted.)
    if let Some(ku) = key_usage(sign_cert)? {
        if !ku.0.contains(KeyUsages::CRLSign) {
            return Err(CertificateError::MissingCrlSign);
        }
    }

    let sign_key = signing_key_from_cert(sign_cert)?;
    verify_crl(crl, &sign_key)?;

    let issuer = crl_issuer_der;

    let mut revoked_certs: Crl = Vec::new();
    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
        for entry in revoked {
            revoked_certs.push(RevokedCertId {
                issuer: issuer.clone(),
                serial_number: entry.serial_number.as_bytes().to_vec(),
            });
        }
    }

    let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
    Ok((this_update, revoked_certs))
}

fn signing_key_from_cert(cert: &Certificate) -> Result<VerifyingKey, CertificateError> {
    cert.tbs_certificate
        .subject_public_key_info
        .clone()
        .try_into()
        .map_err(|_| CertificateError::KeyVerification)
}

// PUBLIC INTERFACE

pub fn parse_crl_pem(
    crl_pem: &Vec<u8>,
    pck_certificate_chain_pem: &Vec<u8>,
    root_cert: Option<&[u8]>,
    now: u64,
) -> Result<(u64, Crl), CertificateError> {
    let pems = pem::parse_many(crl_pem).map_err(|_| CertificateError::Parse)?;
    if pems.is_empty() {
        return Err(CertificateError::Parse);
    }
    if pems.len() > 1 {
        return Err(CertificateError::MultipleCrls);
    }
    let crl = CertificateList::from_der(pems[0].contents()).map_err(|_| CertificateError::Parse)?;

    let sign_cert = verify_cert_chain_pem(pck_certificate_chain_pem, root_cert, None, now)?;

    process_crl(&crl, &sign_cert)
}

pub fn parse_crl_der(
    crl_der: &[u8],
    signing_cert_chain_der: &[u8],
    root_cert: Option<&[u8]>,
    now: u64,
) -> Result<(u64, Crl), CertificateError> {
    let crl = CertificateList::from_der(crl_der).map_err(|_| CertificateError::Parse)?;
    let certs = parse_concat_der_certs(signing_cert_chain_der)?;
    let sign_cert = verify_cert_chain(certs, root_cert, None, now)?;
    process_crl(&crl, &sign_cert)
}

fn parse_concat_der_certs(data: &[u8]) -> Result<Vec<Certificate>, CertificateError> {
    let mut reader = SliceReader::new(data).map_err(|_| CertificateError::Parse)?;
    let mut certs = Vec::new();
    while !reader.is_finished() {
        let cert = Certificate::decode(&mut reader).map_err(|_| CertificateError::Parse)?;
        certs.push(cert);
    }
    Ok(certs)
}

#[cfg(test)]
mod should {
    use crate::cert::{
        der_uint, parse_crl_der, parse_crl_pem, verify_cert_chain_der, CertificateError,
    };
    use crate::nitro;
    use chrono::DateTime;
    use rstest::rstest;
    use std::{fs::File, io::Read};

    /// Attestation doc 1 timestamp as seconds since epoch (2022-11-09T22:52:00Z).
    const NITRO_ATT_DOC_1_TIMESTAMP: u64 = 1668034320;

    fn load_file(path: &str) -> Vec<u8> {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    #[rstest]
    #[case(&[0x00], 0)]
    #[case(&[0x05], 5)]
    #[case(&[0x0d], 13)]
    #[case(&[0x7f], 127)]
    #[case(&[0x00, 0x80], 128)]
    #[case(&[0x00, 0xff], 255)]
    #[case(&[0x01, 0x2c], 300)]
    #[case(&[0x00, 0xff, 0xff], 65535)]
    #[case(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], u64::MAX)]
    #[case(&[0x00, 0x00, 0x05], 5)]
    fn decode_der_unsigned_integers(#[case] content: &[u8], #[case] expected: u64) {
        assert_eq!(der_uint(content).unwrap(), expected);
    }

    #[rstest]
    #[case(&[])]
    #[case(&[0x80])]
    #[case(&[0xff])]
    #[case(&[0xff, 0x00])]
    #[case(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])]
    fn reject_malformed_der_integers(#[case] content: &[u8]) {
        assert!(matches!(
            der_uint(content),
            Err(CertificateError::MalformedExtension)
        ));
    }

    fn load_intel_root_cert() -> Vec<u8> {
        load_file("assets/Intel_SGX_Provisioning_Certification_RootCA.cer")
    }

    fn load_nitro_root_cert() -> Vec<u8> {
        load_file("assets/aws_nitro_root_g1.der")
    }

    /// Parse the Nitro attestation doc and return the DER cert chain
    /// (leaf first, then cabundle reversed) ready for verify_cert_chain_der.
    fn nitro_cert_chain() -> Vec<Vec<u8>> {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = nitro::parse_attestation(&data).unwrap();
        let mut chain = vec![att.certificate];
        chain.extend(att.cabundle.into_iter().rev());
        chain
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
        let root_buf = load_intel_root_cert();

        let now = DateTime::parse_from_rfc3339(exp_date)
            .unwrap()
            .timestamp()
            .try_into()
            .unwrap();
        let (date, _crl) = parse_crl_pem(&crl_buf, &crl_chain_buf, Some(&root_buf), now).unwrap();
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
        let root_buf = load_intel_root_cert();

        let now = DateTime::parse_from_rfc3339(timestamp).unwrap().timestamp() as u64;

        let result = parse_crl_pem(&crl_buf, &crl_chain_buf, Some(&root_buf), now);
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
        let root_buf = load_intel_root_cert();

        let now = DateTime::parse_from_rfc3339(timestamp).unwrap().timestamp() as u64;

        let result = parse_crl_pem(&crl_buf, &crl_chain_buf, Some(&root_buf), now);
        assert!(matches!(result, Err(CertificateError::CertificateExpired)));
    }

    #[test]
    fn reject_multiple_crls() {
        let crl_buf = load_file("assets/tests/intel/crl.pem");
        let crl_chain_buf = load_file("assets/tests/intel/crl_chain.pem");
        let root_buf = load_intel_root_cert();
        let now = DateTime::parse_from_rfc3339("2026-02-03T09:32:53Z")
            .unwrap()
            .timestamp() as u64;

        // Concatenate two copies of the same CRL PEM
        let mut double_crl = crl_buf.clone();
        double_crl.extend_from_slice(&crl_buf);

        let result = parse_crl_pem(&double_crl, &crl_chain_buf, Some(&root_buf), now);
        assert!(matches!(result, Err(CertificateError::MultipleCrls)));
    }

    #[test]
    fn verify_nitro_der_cert_chain() {
        let chain = nitro_cert_chain();
        let refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();
        let nitro_root = load_nitro_root_cert();
        let now = NITRO_ATT_DOC_1_TIMESTAMP;
        let leaf = verify_cert_chain_der(&refs, Some(&nitro_root), None, now).unwrap();
        assert!(leaf
            .tbs_certificate
            .subject
            .to_string()
            .contains("i-04fd167167daacf3b"));
    }

    #[test]
    fn reject_nitro_chain_with_wrong_root() {
        let chain = nitro_cert_chain();
        let refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();
        let now = NITRO_ATT_DOC_1_TIMESTAMP;
        // Use the Intel root cert instead of the Nitro one. The Nitro chain
        // already ends in the Nitro root; appending the Intel root therefore
        // produces a name-chaining mismatch at the last step.
        let intel_root = load_intel_root_cert();
        let result = verify_cert_chain_der(&refs, Some(&intel_root), None, now);
        assert!(matches!(
            result,
            Err(CertificateError::IssuerSubjectMismatch)
        ));
    }

    /// Concatenate DER certs into a flat byte buffer.
    fn concat_der(certs: &[&[u8]]) -> Vec<u8> {
        certs.iter().flat_map(|c| c.iter().copied()).collect()
    }

    #[test]
    fn parse_nitro_der_crl() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = nitro::parse_attestation(&data).unwrap();
        let nitro_root = load_nitro_root_cert();
        let now = NITRO_ATT_DOC_1_TIMESTAMP;

        // Zonal CRL signed by cabundle[1] (first intermediate);
        // its signing chain is cabundle[1] → cabundle[0] → root.
        let crl_buf = load_file("assets/tests/nitro/crl_zonal.der");
        let sign_chain = concat_der(&[&att.cabundle[1], &att.cabundle[0]]);
        let (date, crl) = parse_crl_der(&crl_buf, &sign_chain, Some(&nitro_root), now).unwrap();
        // 2022-11-12T00:21:29Z
        assert_eq!(date, 1668212489);
        assert!(crl.is_empty());
    }

    #[test]
    fn reject_nitro_crl_with_wrong_signer() {
        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = nitro::parse_attestation(&data).unwrap();
        let nitro_root = load_nitro_root_cert();
        let now = NITRO_ATT_DOC_1_TIMESTAMP;

        // Zonal CRL with the wrong signer chain (cabundle[0] = root, not the
        // intermediate that actually issued the CRL). The CRL's `issuer` DN
        // is the zonal CA, not the root, so the issuer-vs-signer check
        // rejects this before signature verification.
        let crl_buf = load_file("assets/tests/nitro/crl_zonal.der");
        let result = parse_crl_der(&crl_buf, &att.cabundle[0], Some(&nitro_root), now);
        assert!(matches!(result, Err(CertificateError::CrlIssuerMismatch)));
    }

    /// Replace the first (and only expected) occurrence of `find` in `data`
    /// with `replace`. Both slices must be the same length so DER offsets
    /// are preserved.
    fn patch_bytes(data: &[u8], find: &[u8], replace: &[u8]) -> Vec<u8> {
        assert_eq!(find.len(), replace.len());
        let pos = data
            .windows(find.len())
            .position(|w| w == find)
            .expect("pattern not found in cert");
        let mut out = data.to_vec();
        out[pos..pos + find.len()].copy_from_slice(replace);
        out
    }

    /// Build [intermediate, patched_root] from the Intel CRL chain PEM,
    /// applying `patch` to the root DER bytes. Returns owned DER buffers
    /// so the caller can take references for `verify_cert_chain_der`.
    fn intel_chain_with_patched_root(find: &[u8], replace: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let chain_pem = load_file("assets/tests/intel/crl_chain.pem");
        let pems = pem::parse_many(&chain_pem).unwrap();
        let intermediate = pems[0].contents().to_vec();
        let root = pems[1].contents().to_vec();
        let patched_root = patch_bytes(&root, find, replace);
        (intermediate, patched_root)
    }

    const INTEL_NOW: u64 = 1738578773; // 2026-02-03T09:32:53Z, within Intel cert validity

    // Intel root BasicConstraints DER: SEQUENCE { cA TRUE, pathLen 1 }
    // → `30 06  01 01 FF  02 01 01`. The signature/SPKI of the patched
    // root are unchanged, so the intermediate's signature still verifies
    // against it and the new structural check is what fires.

    #[test]
    fn reject_chain_with_root_ca_false() {
        // Flip cA TRUE → FALSE on the in-chain root.
        let (intermediate, patched_root) = intel_chain_with_patched_root(
            &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01],
            &[0x30, 0x06, 0x01, 0x01, 0x00, 0x02, 0x01, 0x01],
        );
        let refs: [&[u8]; 2] = [&intermediate, &patched_root];
        let result = verify_cert_chain_der(&refs, None, None, INTEL_NOW);
        assert!(matches!(
            result,
            Err(CertificateError::NotACertificateAuthority)
        ));
    }

    #[test]
    fn process_crl_rejects_spoofed_issuer() {
        // Isolated test of the issuer↔signer-subject check in `process_crl`.
        // Starts from a real CRL/signer pair that would otherwise pass the
        // full verification (signature, KeyUsage, issuer DN), then mutates
        // the parsed CRL's `issuer` field in memory. The mutation makes the
        // CRL signature no longer verify, but the CrlIssuerMismatch check
        // fires before signature verification — so a positive result here
        // demonstrates the check is what's gating acceptance, not the
        // signature check that would otherwise reject the same input.
        use super::process_crl;
        use x509_verify::x509_cert::{crl::CertificateList, der::Decode, Certificate};

        let data = load_file("assets/tests/nitro/attestation_doc.bin");
        let att = nitro::parse_attestation(&data).unwrap();

        let crl_buf = load_file("assets/tests/nitro/crl_zonal.der");
        let mut crl = CertificateList::from_der(crl_buf.as_slice()).unwrap();
        let zonal_ca = Certificate::from_der(&att.cabundle[1]).unwrap();
        let root = Certificate::from_der(&att.cabundle[0]).unwrap();

        // Sanity: with the matching signer, the CRL is accepted.
        process_crl(&crl, &zonal_ca).expect("matching issuer/signer should be accepted");

        // Spoof the CRL's issuer field to claim the root's DN.
        crl.tbs_cert_list.issuer = root.tbs_certificate.subject.clone();
        assert!(matches!(
            process_crl(&crl, &zonal_ca),
            Err(CertificateError::CrlIssuerMismatch)
        ));
    }

    #[test]
    fn reject_chain_with_root_missing_key_cert_sign() {
        // Patch the root KeyUsage BIT STRING from {keyCertSign, cRLSign}
        // (0x06) to {cRLSign} (0x02) only. cA stays TRUE, so the cA check
        // passes and we land on the keyCertSign check.
        let (intermediate, patched_root) = intel_chain_with_patched_root(
            &[0x04, 0x04, 0x03, 0x02, 0x01, 0x06],
            &[0x04, 0x04, 0x03, 0x02, 0x01, 0x02],
        );
        let refs: [&[u8]; 2] = [&intermediate, &patched_root];
        let result = verify_cert_chain_der(&refs, None, None, INTEL_NOW);
        assert!(matches!(result, Err(CertificateError::MissingKeyCertSign)));
    }
}
