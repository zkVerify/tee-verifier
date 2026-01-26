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

extern crate alloc;
use alloc::vec::Vec;

use crate::intel::constants::{ASN1_OID_VALUE_PAIR_LEN, TCB_SVN_COUNT};
use crate::intel::quote::{PceSvn, TcbSvn};
use asn1_der::typed::{DerDecodable, Sequence};
pub use p256::ecdsa::signature::Verifier;
use spki::ObjectIdentifier;
use x509_verify::{
    x509_cert::{
        der::{Decode, Encode},
        Certificate,
    },
    Signature, VerifyInfo, VerifyingKey,
};

#[derive(Debug)]
pub enum CertificateError {
    Parse,
    KeyVerification,
    EmptyChain,
    NoExtensions,
    ExtensionNotFound,
    BadSignature,
}

pub fn verify_pem_cert_chain(
    pck_certificate_chain_pem: &Vec<u8>,
    root_cert: &[u8],
) -> Result<Certificate, CertificateError> {
    let root = Certificate::from_der(root_cert).unwrap();
    let pems = pem::parse_many(pck_certificate_chain_pem).map_err(|_| CertificateError::Parse)?;
    let mut certs: Vec<Certificate> = pems
        .into_iter()
        .map(|pem| Certificate::from_der(&pem.contents().to_vec()).unwrap())
        .collect();

    if certs.is_empty() {
        return Err(CertificateError::EmptyChain);
    }

    certs.push(root);
    for c in 0..certs.len() - 1 {
        let key: VerifyingKey = certs[c + 1]
            .tbs_certificate
            .subject_public_key_info
            .clone()
            .try_into()
            .unwrap();
        let _ = verify_certificate(&certs[c], key)?;
    }

    Ok(certs[0].clone())
}

fn verify_certificate(cert: &Certificate, key: VerifyingKey) -> Result<(), CertificateError> {
    let verify_info = VerifyInfo::new(
        cert.tbs_certificate.to_der().unwrap().into(),
        Signature::new(
            &cert.signature_algorithm,
            cert.signature.as_bytes().unwrap(),
        ),
    );
    Ok(key
        .verify(&verify_info)
        .map_err(|_| CertificateError::KeyVerification)?)
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
        if let Ok(item) = Sequence::load(seq.get(i).expect("This should not happen")) {
            if item.len() >= ASN1_OID_VALUE_PAIR_LEN {
                if let Ok(oid_obj) = item.get(0) {
                    if oid_obj.value() == oid.as_bytes() {
                        let val_obj = item.get(1).expect("This should not happen");
                        return Ok(val_obj.value());
                    }
                }
            }
        }
    }
    Err(CertificateError::ExtensionNotFound)
}

pub fn extract_tcb_info(
    data: &[u8],
    oid: ObjectIdentifier,
) -> Result<(TcbSvn, PceSvn), CertificateError> {
    let mut tcb = [0u8; TCB_SVN_COUNT];
    let mut offset = 0;

    // The data is 17 concatenated ASN.1 sequences (16 TCB SVN + 1 PCE SVN)
    // Each sequence contains an OID and an integer value
    // Parse each sequence, advancing by the actual encoded length

    // TCB SVN values (first 16 sequences)
    for i in 0..TCB_SVN_COUNT {
        let (value, seq_len) = parse_oid_value_pair(&data[offset..], &oid)?;
        tcb[i] = value[0];
        offset += seq_len;
    }

    // PCE SVN (17th sequence)
    let (pce_buf, _) = parse_oid_value_pair(&data[offset..], &oid)?;

    let pce: u16 = match pce_buf.len() {
        1 => pce_buf[0].into(),
        2 => u16::from_le_bytes(
            pce_buf[0..2]
                .try_into()
                .map_err(|_| CertificateError::ExtensionNotFound)?,
        ),
        _ => return Err(CertificateError::ExtensionNotFound),
    };
    Ok((tcb, pce))
}

/// Parse an ASN.1 sequence containing an OID-value pair
/// Returns (value bytes, total sequence length in bytes)
fn parse_oid_value_pair<'a>(
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

    if seq.len() != ASN1_OID_VALUE_PAIR_LEN {
        return Err(CertificateError::ExtensionNotFound);
    }

    let name = seq.get(0).expect("Failed to get OID").value();
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
            .unwrap(),
    )
    .map_err(|_| CertificateError::BadSignature)?;
    let pck_verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map_err(|_| CertificateError::BadSignature)?;

    let _ = pck_verifying_key
        .verify(
            data.into(),
            &p256::ecdsa::Signature::from_bytes(signature.into()).unwrap(),
        )
        .map_err(|_| CertificateError::BadSignature)?;
    Ok(())
}
