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

//! Intel TDX Quote v4 parsing and verification.
//!
//! Implements the TD Quote v4 format from "Intel® Trust Domain Extensions Data Center
//! Attestation Primitives (Intel® TDX DCAP): Quote Generation Library and Quote
//! Verification Library", Rev 0.9, April 2026, Appendix A.3 "Version 4 Quote Format".
//! <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf>

extern crate alloc;
use alloc::vec::Vec;

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use spki::ObjectIdentifier;

use crate::intel::collaterals::{TcbInfo, TcbLevel, TcbStatus};
use crate::intel::constants::*;
use crate::intel::policy::{PolicyError, TdReportPolicy};

/// Errors that can occur when parsing a quote.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// The quote header is invalid or too short.
    InvalidHeader,
    /// The QE authentication data is invalid.
    InvalidAuthenticationData,
    /// The QE report is invalid.
    InvalidQeReport,
    /// The QE report signature is invalid.
    InvalidQeReportSignature,
    /// The quote body is invalid or too short.
    InvalidBody,
    /// The certification data is invalid.
    InvalidCertificationData,
    /// The signature data is invalid.
    InvalidSignatureData,
    /// The attestation key type is not supported.
    UnsupportedAttestationKeyType,
    /// The certification data type is not supported.
    UnsupportedCertificationDataType,
    /// The QE vendor ID is not recognized.
    UnsupportedVendorId,
    /// The quote version is not supported.
    UnsupportedQuoteVersion,
    /// The TEE type is not supported.
    UnsupportedTeeType,
}

/// Errors that can occur when verifying a quote.
#[derive(Debug, PartialEq)]
pub enum VerificationError {
    /// Quote verification failed.
    FailedVerification,
    /// The verification type is not supported.
    UnsupportedVerificationType,
    /// P-256 elliptic curve error.
    P256Error,
    /// PCK certificate chain verification failed.
    PKCChain,
    /// Failed to extract Intel SGX extensions from the certificate.
    CannotExtractIntelExtensions,
    /// Failed to extract the FMSPC value.
    CannotExtractFmspc,
    /// The FMSPC value does not match the expected value.
    FmspcMismatch,
    /// The TD is running in debug mode.
    DebugModeEnabled,
    /// The TCB status is not acceptable.
    BadTcbStatus(TcbStatus),
    /// The PCE SVN status is not acceptable.
    BadPceStatus,
    /// The signature is invalid.
    BadSignature,
    /// The QE report data is invalid.
    InvalidQeReportData,
}

#[derive(Debug)]
struct QuoteHeader {
    /// Version of the quote data structure.
    version: u16,
    /// Type of the Attestation Key used by the Quoting Enclave.
    /// Supported values:
    /// 2 (ECDSA-256-with-P-256 curve)
    /// 3 (ECDSA-384-with-P-384 curve) (Note: currently not supported)
    /// (Note: 0 and 1 are reserved, for when EPID is moved to version 4 quotes.)
    attestation_key_type: u16,
    /// TEE for this Attestation
    /// 0x00000000: SGX
    /// 0x00000081: TDX
    tee_type: u32,
    /// reserved
    reserved1: [u8; HEADER_RESERVED1_SIZE],
    /// reserved
    reserved2: [u8; HEADER_RESERVED2_SIZE],
    /// Unique identifier of the QE Vendor.
    /// Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
    qe_vendor_id: [u8; HEADER_QE_VENDOR_ID_SIZE],
    /// Custom user-defined data. For the Intel® SGX and
    /// TDX DCAP Quote Generation Libraries, the first 16
    /// bytes contain a Platform Identifier that is used to
    /// link a PCK Certificate to an Enc(PPID). This
    /// identifier is consistent for every quote generated
    /// with this QE on this platform.
    user_data: [u8; HEADER_USER_DATA_SIZE],
}

impl QuoteHeader {
    fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < QUOTE_HEADER_SIZE {
            return Err(ParseError::InvalidHeader);
        }
        Ok(QuoteHeader {
            version: u16::from_le_bytes(
                input[HEADER_VERSION_OFFSET..HEADER_ATTESTATION_KEY_TYPE_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidHeader)?,
            ),
            attestation_key_type: u16::from_le_bytes(
                input[HEADER_ATTESTATION_KEY_TYPE_OFFSET..HEADER_TEE_TYPE_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidHeader)?,
            ),
            tee_type: u32::from_le_bytes(
                input[HEADER_TEE_TYPE_OFFSET..HEADER_RESERVED1_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidHeader)?,
            ),
            reserved1: input[HEADER_RESERVED1_OFFSET..HEADER_RESERVED2_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidHeader)?,
            reserved2: input[HEADER_RESERVED2_OFFSET..HEADER_QE_VENDOR_ID_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidHeader)?,
            qe_vendor_id: input[HEADER_QE_VENDOR_ID_OFFSET..HEADER_USER_DATA_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidHeader)?,
            user_data: input[HEADER_USER_DATA_OFFSET..QUOTE_HEADER_SIZE]
                .try_into()
                .map_err(|_| ParseError::InvalidHeader)?,
        })
    }

    fn to_bytes(&self, output: &mut [u8]) {
        output[HEADER_VERSION_OFFSET..HEADER_ATTESTATION_KEY_TYPE_OFFSET]
            .copy_from_slice(&self.version.to_le_bytes());
        output[HEADER_ATTESTATION_KEY_TYPE_OFFSET..HEADER_TEE_TYPE_OFFSET]
            .copy_from_slice(&self.attestation_key_type.to_le_bytes());
        output[HEADER_TEE_TYPE_OFFSET..HEADER_RESERVED1_OFFSET]
            .copy_from_slice(&self.tee_type.to_le_bytes());
        output[HEADER_RESERVED1_OFFSET..HEADER_RESERVED2_OFFSET].copy_from_slice(&self.reserved1);
        output[HEADER_RESERVED2_OFFSET..HEADER_QE_VENDOR_ID_OFFSET]
            .copy_from_slice(&self.reserved2);
        output[HEADER_QE_VENDOR_ID_OFFSET..HEADER_USER_DATA_OFFSET]
            .copy_from_slice(&self.qe_vendor_id);
        output[HEADER_USER_DATA_OFFSET..QUOTE_HEADER_SIZE].copy_from_slice(&self.user_data);
    }
}

#[derive(Debug)]
struct QeAuthenticationData {
    _size: u16,
    data: Vec<u8>,
}

impl QeAuthenticationData {
    fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < AUTH_DATA_SIZE_FIELD {
            return Err(ParseError::InvalidAuthenticationData);
        }
        let size = u16::from_le_bytes(
            input[..AUTH_DATA_SIZE_FIELD]
                .try_into()
                .expect("length checked above"),
        );
        let end = AUTH_DATA_SIZE_FIELD + usize::from(size);
        if input.len() < end {
            return Err(ParseError::InvalidAuthenticationData);
        }
        let data = input[AUTH_DATA_SIZE_FIELD..end].to_vec();
        Ok(QeAuthenticationData { _size: size, data })
    }
}

#[derive(Debug)]
struct QeReportCertificationData {
    /// GX Report of the Quoting Enclave that generated an Attestation Key.
    /// Report Data: SHA256(ECDSA Attestation Key || QE Authentication Data) || 32-0x00’s
    qe_report: [u8; QE_REPORT_SIZE], // expands to EnclaveReportBody
    /// ECDSA signature over the QE Report calculated using the Provisioning Certification Key (PCK).
    qe_report_signature: [u8; ECDSA_SIGNATURE_SIZE], //Signature,
    /// Variable-length data chosen by the Quoting Enclave and signed by the
    /// Provisioning Certification Key (as a part of the Report Data in the QE Report)
    qe_authentication_data: QeAuthenticationData,
    qe_certification_data: QeCertificationData,
}

impl QeReportCertificationData {
    fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < QE_REPORT_SIZE + ECDSA_SIGNATURE_SIZE {
            return Err(ParseError::InvalidQeReport);
        }
        let qe_report = input[..QE_REPORT_SIZE]
            .try_into()
            .expect("length checked above");
        let qe_report_signature = input[QE_REPORT_SIZE..QE_REPORT_SIZE + ECDSA_SIGNATURE_SIZE]
            .try_into()
            .expect("length checked above");
        let qe_authentication_data =
            QeAuthenticationData::from_bytes(&input[QE_REPORT_SIZE + ECDSA_SIGNATURE_SIZE..])?;
        // The nested certification data must be a PCK chain (spec Appendix A.3.12)
        let qe_certification_data = QeCertificationData::from_bytes(
            &input[QE_REPORT_SIZE
                + ECDSA_SIGNATURE_SIZE
                + AUTH_DATA_SIZE_FIELD
                + qe_authentication_data.data.len()..],
            CERT_DATA_TYPE_PCK_CHAIN,
        )?;
        Ok(QeReportCertificationData {
            qe_report,
            qe_report_signature,
            qe_authentication_data,
            qe_certification_data,
        })
    }

    fn verify(
        &self,
        attestation_key: &[u8],
        tcb: &TcbInfo,
        crl: &crate::cert::Crl,
        now: u64,
    ) -> Result<(), VerificationError> {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(attestation_key);
            hasher.update(self.qe_authentication_data.data.as_slice());
            hasher.finalize()
        };

        let actual = [&hash[..], &[0u8; HASH_PADDING_SIZE]].concat();
        let expected = &self.qe_report[QE_REPORT_SIZE - REPORT_DATA_SIZE..];

        if actual != *expected {
            return Err(VerificationError::FailedVerification);
        }

        self.qe_certification_data.verify(
            &self.qe_report,
            &self.qe_report_signature,
            attestation_key,
            tcb,
            crl,
            now,
        )
    }
}

pub type TcbSvn = [u8; TCB_SVN_COUNT];
pub type PceSvn = u16;

#[derive(Debug)]
struct QuoteBodyV4 {
    /// Describes the TCB of TDX
    tee_tcb_svn: TcbSvn,
    /// Measurement of the TDX Module.
    _mrseam: [u8; BODY_MRSEAM_SIZE],
    /// Zero for the Intel® TDX Module.
    _mrsignerseam: [u8; BODY_MRSIGNERSEAM_SIZE],
    /// Must be zero for TDX 1.0
    _seamattributes: [u8; BODY_SEAMATTRIBUTES_SIZE],
    /// TD Attributes
    tdattributes: [u8; BODY_TDATTRIBUTES_SIZE],
    /// XFAM (eXtended Features Available Mask) is
    /// defined as a 64b bitmap, which has the same
    /// format as XCR0 or IA32_XSS MSR.
    xfam: [u8; BODY_XFAM_SIZE],
    /// Measurement of the initial contents of the TD.
    mrtd: [u8; BODY_MRTD_SIZE],
    /// Software-defined ID for non-owner-defined
    /// configuration of the TD, e.g., runtime or OS configuration.
    mrconfigid: [u8; BODY_MRCONFIGID_SIZE],
    /// Software-defined ID for the TD's owner
    mrowner: [u8; BODY_MROWNER_SIZE],
    /// Software-defined ID for owner-defined
    /// configuration of the TD, e.g., specific to the
    /// workload rather than the runtime or OS.
    mrownerconfig: [u8; BODY_MROWNERCONFIG_SIZE],
    /// Runtime extendable measurement registers
    rtmrs: [[u8; BODY_RTMR_SIZE]; RTMR_COUNT],
    /// Each TD Quote is based on a TD Report. The
    /// TD is free to provide 64 bytes of custom data
    /// to a TD Report. For instance, this space can be
    /// used to hold a nonce, a public key, or a hash
    /// of a larger block of data.
    reportdata: [u8; BODY_REPORTDATA_SIZE],
}

impl QuoteBodyV4 {
    fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < QUOTE_BODY_SIZE {
            return Err(ParseError::InvalidBody);
        }
        Ok(QuoteBodyV4 {
            tee_tcb_svn: input[BODY_TEE_TCB_SVN_OFFSET..BODY_MRSEAM_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _mrseam: input[BODY_MRSEAM_OFFSET..BODY_MRSIGNERSEAM_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _mrsignerseam: input[BODY_MRSIGNERSEAM_OFFSET..BODY_SEAMATTRIBUTES_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _seamattributes: input[BODY_SEAMATTRIBUTES_OFFSET..BODY_TDATTRIBUTES_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            tdattributes: input[BODY_TDATTRIBUTES_OFFSET..BODY_XFAM_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            xfam: input[BODY_XFAM_OFFSET..BODY_MRTD_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            mrtd: input[BODY_MRTD_OFFSET..BODY_MRCONFIGID_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            mrconfigid: input[BODY_MRCONFIGID_OFFSET..BODY_MROWNER_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            mrowner: input[BODY_MROWNER_OFFSET..BODY_MROWNERCONFIG_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            mrownerconfig: input[BODY_MROWNERCONFIG_OFFSET..BODY_RTMR0_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            rtmrs: [
                input[BODY_RTMR0_OFFSET..BODY_RTMR1_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidBody)?,
                input[BODY_RTMR1_OFFSET..BODY_RTMR2_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidBody)?,
                input[BODY_RTMR2_OFFSET..BODY_RTMR3_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidBody)?,
                input[BODY_RTMR3_OFFSET..BODY_REPORTDATA_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidBody)?,
            ],
            reportdata: input[BODY_REPORTDATA_OFFSET..QUOTE_BODY_SIZE]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
        })
    }

    fn to_bytes(&self, output: &mut [u8]) {
        output[BODY_TEE_TCB_SVN_OFFSET..BODY_MRSEAM_OFFSET].copy_from_slice(&self.tee_tcb_svn);
        output[BODY_MRSEAM_OFFSET..BODY_MRSIGNERSEAM_OFFSET].copy_from_slice(&self._mrseam);
        output[BODY_MRSIGNERSEAM_OFFSET..BODY_SEAMATTRIBUTES_OFFSET]
            .copy_from_slice(&self._mrsignerseam);
        output[BODY_SEAMATTRIBUTES_OFFSET..BODY_TDATTRIBUTES_OFFSET]
            .copy_from_slice(&self._seamattributes);
        output[BODY_TDATTRIBUTES_OFFSET..BODY_XFAM_OFFSET].copy_from_slice(&self.tdattributes);
        output[BODY_XFAM_OFFSET..BODY_MRTD_OFFSET].copy_from_slice(&self.xfam);
        output[BODY_MRTD_OFFSET..BODY_MRCONFIGID_OFFSET].copy_from_slice(&self.mrtd);
        output[BODY_MRCONFIGID_OFFSET..BODY_MROWNER_OFFSET].copy_from_slice(&self.mrconfigid);
        output[BODY_MROWNER_OFFSET..BODY_MROWNERCONFIG_OFFSET].copy_from_slice(&self.mrowner);
        output[BODY_MROWNERCONFIG_OFFSET..BODY_RTMR0_OFFSET].copy_from_slice(&self.mrownerconfig);
        output[BODY_RTMR0_OFFSET..BODY_RTMR1_OFFSET].copy_from_slice(&self.rtmrs[0]);
        output[BODY_RTMR1_OFFSET..BODY_RTMR2_OFFSET].copy_from_slice(&self.rtmrs[1]);
        output[BODY_RTMR2_OFFSET..BODY_RTMR3_OFFSET].copy_from_slice(&self.rtmrs[2]);
        output[BODY_RTMR3_OFFSET..BODY_REPORTDATA_OFFSET].copy_from_slice(&self.rtmrs[3]);
        output[BODY_REPORTDATA_OFFSET..QUOTE_BODY_SIZE].copy_from_slice(&self.reportdata);
    }
}

/// A parsed Intel TDX Quote v4.
#[derive(Debug)]
pub struct QuoteV4 {
    header: QuoteHeader,
    body: QuoteBodyV4,
    /// Size of the Quote Signature Data structure
    _quote_signature_data_len: u32,
    /// Version 4 of the ECDSA 256Bit Signature Data Structure
    quote_signature_data: QuoteSignatureData,
}

#[derive(Debug)]
struct QeCertificationData {
    certification_data_type: u16,
    _size: u32,
    certification_data: Vec<u8>,
}

impl QeCertificationData {
    fn from_bytes(input: &[u8], expected_type: u16) -> Result<Self, ParseError> {
        if input.len() < CERT_DATA_HEADER_SIZE {
            return Err(ParseError::InvalidCertificationData);
        }
        let certification_data_type = u16::from_le_bytes(
            input[..CERT_DATA_TYPE_FIELD_SIZE]
                .try_into()
                .expect("length checked above"),
        );
        let size = u32::from_le_bytes(
            input[CERT_DATA_TYPE_FIELD_SIZE..CERT_DATA_HEADER_SIZE]
                .try_into()
                .expect("length checked above"),
        );
        if input.len() < CERT_DATA_HEADER_SIZE + (size as usize) {
            return Err(ParseError::InvalidCertificationData);
        }
        let certification_data =
            input[CERT_DATA_HEADER_SIZE..CERT_DATA_HEADER_SIZE + (size as usize)].to_vec();
        if certification_data_type != expected_type {
            return Err(ParseError::UnsupportedCertificationDataType);
        }

        Ok(QeCertificationData {
            certification_data_type,
            _size: size,
            certification_data,
        })
    }

    fn extract_tcb_info(
        data: &[u8],
        oid: ObjectIdentifier,
    ) -> Result<(TcbSvn, PceSvn), crate::cert::CertificateError> {
        let mut tcb = [0u8; TCB_SVN_COUNT];
        let mut offset = 0;

        // The data is 17 concatenated ASN.1 sequences (16 TCB SVN + 1 PCE SVN)
        // Each sequence contains an OID and an integer value
        // Parse each sequence, advancing by the actual encoded length

        // TCB SVN values (first 16 sequences)
        for t in tcb.iter_mut() {
            let (value, seq_len) = crate::cert::parse_oid_value_pair(&data[offset..], &oid)?;
            *t = value[0];
            offset += seq_len;
        }

        // PCE SVN (17th sequence)
        let (pce_buf, _) = crate::cert::parse_oid_value_pair(&data[offset..], &oid)?;

        let pce: u16 = match pce_buf.len() {
            1 => pce_buf[0].into(),
            2 => u16::from_le_bytes(
                pce_buf[0..2]
                    .try_into()
                    .map_err(|_| crate::cert::CertificateError::ExtensionNotFound)?,
            ),
            _ => return Err(crate::cert::CertificateError::ExtensionNotFound),
        };
        Ok((tcb, pce))
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        attestation_key: &[u8],
        tcb: &TcbInfo,
        crl: &crate::cert::Crl,
        now: u64,
    ) -> Result<(), VerificationError> {
        match self.certification_data_type {
            CERT_DATA_TYPE_PCK_CHAIN => {
                let cert = crate::cert::verify_cert_chain_pem(
                    &self.certification_data,
                    Some(crate::intel::ROOT_CERT),
                    Some(crl),
                    now,
                )
                .map_err(|_| VerificationError::PKCChain)?;

                let sgx_ext = crate::cert::get_ext(
                    &cert,
                    spki::ObjectIdentifier::new(INTEL_SGX_OID).expect("Cannot decode OID"),
                )
                .map_err(|_| VerificationError::CannotExtractIntelExtensions)?;

                let fmspc = crate::cert::extract_field(
                    sgx_ext,
                    spki::ObjectIdentifier::new(INTEL_FMSPC_OID).expect("Cannot decode OID"),
                )
                .map_err(|_| VerificationError::CannotExtractIntelExtensions)?;

                let mut tcb_buf = [0u8; FMSPC_SIZE];
                hex::decode_to_slice(tcb.fmspc.clone(), &mut tcb_buf)
                    .map_err(|_| VerificationError::FmspcMismatch)?;
                if tcb_buf != fmspc {
                    return Err(VerificationError::FmspcMismatch);
                }

                let tcb_oid =
                    spki::ObjectIdentifier::new(INTEL_TCB_OID).expect("Cannot decode OID");
                let cert_tcb = crate::cert::extract_field(sgx_ext, tcb_oid)
                    .map_err(|_| VerificationError::CannotExtractIntelExtensions)?;
                let (cert_tcb, cert_pce) = Self::extract_tcb_info(cert_tcb, tcb_oid)
                    .map_err(|_| VerificationError::CannotExtractIntelExtensions)?;
                let (tcb_status, pce_svn) =
                    crate::intel::collaterals::compare_sgx_tcb_levels(&cert_tcb, &tcb.tcb_levels);
                if tcb_status >= TcbStatus::Revoked {
                    return Err(VerificationError::BadTcbStatus(tcb_status));
                }
                if cert_pce < pce_svn {
                    return Err(VerificationError::BadPceStatus);
                }

                crate::cert::verify_signature(&cert, data, signature)
                    .map_err(|_| VerificationError::BadSignature)?;
            }

            CERT_DATA_TYPE_QE_REPORT => {
                let qe_report_certification_data =
                    QeReportCertificationData::from_bytes(&self.certification_data[..])
                        .map_err(|_| VerificationError::InvalidQeReportData)?;
                qe_report_certification_data.verify(attestation_key, tcb, crl, now)?;
            }
            _ => {
                return Err(VerificationError::UnsupportedVerificationType);
            }
        };

        Ok(())
    }
}

#[derive(Debug)]
struct QuoteSignatureData {
    quote_signature: [u8; ECDSA_SIGNATURE_SIZE],
    ecdsa_attestation_key: [u8; ATTESTATION_KEY_SIZE],
    qe_certification_data: QeCertificationData,
}

impl QuoteSignatureData {
    fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < ECDSA_SIGNATURE_SIZE + ATTESTATION_KEY_SIZE {
            return Err(ParseError::InvalidSignatureData);
        }
        let quote_signature: [u8; ECDSA_SIGNATURE_SIZE] = input[..ECDSA_SIGNATURE_SIZE]
            .try_into()
            .expect("length checked above");
        let ecdsa_attestation_key: [u8; ATTESTATION_KEY_SIZE] = input
            [ECDSA_SIGNATURE_SIZE..ECDSA_SIGNATURE_SIZE + ATTESTATION_KEY_SIZE]
            .try_into()
            .expect("length checked above");
        // The top-level certification data of a v4 quote is always a QE report (spec Appendix A.3.12)
        let qe_certification_data = QeCertificationData::from_bytes(
            &input[ECDSA_SIGNATURE_SIZE + ATTESTATION_KEY_SIZE..],
            CERT_DATA_TYPE_QE_REPORT,
        )?;
        Ok(QuoteSignatureData {
            quote_signature,
            ecdsa_attestation_key,
            qe_certification_data,
        })
    }

    fn verify(
        &self,
        signed_data: &[u8],
        tcb: &TcbInfo,
        crl: &crate::cert::Crl,
        now: u64,
    ) -> Result<(), VerificationError> {
        let key =
            VerifyingKey::from_sec1_bytes(&[&[4], &self.ecdsa_attestation_key[..]].concat()[..])
                .map_err(|_| VerificationError::P256Error)?;
        key.verify(
            signed_data,
            &Signature::from_bytes(&self.quote_signature.into())
                .map_err(|_| VerificationError::BadSignature)?,
        )
        .map_err(|_| VerificationError::P256Error)?;
        self.qe_certification_data.verify(
            signed_data,
            &self.quote_signature,
            &self.ecdsa_attestation_key,
            tcb,
            crl,
            now,
        )
    }
}

impl QuoteV4 {
    fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        // HEADER
        let header = QuoteHeader::from_bytes(input)?;
        // The body below is parsed with the v4 TD-report layout
        if header.version != QUOTE_VERSION_V4 {
            return Err(ParseError::UnsupportedQuoteVersion);
        }
        if header.tee_type != TEE_TYPE_TDX {
            return Err(ParseError::UnsupportedTeeType);
        }
        if header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA_256_P256 {
            return Err(ParseError::UnsupportedAttestationKeyType);
        }
        if header.qe_vendor_id != INTEL_VENDOR_ID {
            return Err(ParseError::UnsupportedVendorId);
        }

        // BODY
        let body = QuoteBodyV4::from_bytes(&input[QUOTE_HEADER_SIZE..])?;
        let signature_data_offset = QUOTE_HEADER_SIZE + QUOTE_BODY_SIZE;
        if input.len() < signature_data_offset + SIGNATURE_DATA_LEN_SIZE {
            return Err(ParseError::InvalidSignatureData);
        }
        let quote_signature_data_len = u32::from_le_bytes(
            input[signature_data_offset..signature_data_offset + SIGNATURE_DATA_LEN_SIZE]
                .try_into()
                .expect("length checked above"),
        );
        let signature_data_start = signature_data_offset + SIGNATURE_DATA_LEN_SIZE;
        let signature_data_end = signature_data_start + (quote_signature_data_len as usize);
        if input.len() < signature_data_end {
            return Err(ParseError::InvalidSignatureData);
        }
        let quote_signature_data: QuoteSignatureData =
            QuoteSignatureData::from_bytes(&input[signature_data_start..signature_data_end])?;

        Ok(QuoteV4 {
            header,
            body,
            _quote_signature_data_len: quote_signature_data_len,
            quote_signature_data,
        })
    }

    /// The 64 bytes of REPORTDATA chosen by the TD; covered by the AK signature.
    pub fn report_data(&self) -> &[u8; BODY_REPORTDATA_SIZE] {
        &self.body.reportdata
    }

    /// Measurement of the initial contents of the TD.
    pub fn mrtd(&self) -> &[u8; BODY_MRTD_SIZE] {
        &self.body.mrtd
    }

    /// Software-defined ID for non-owner-defined configuration of the TD.
    pub fn mrconfigid(&self) -> &[u8; BODY_MRCONFIGID_SIZE] {
        &self.body.mrconfigid
    }

    /// Software-defined ID for the TD's owner.
    pub fn mrowner(&self) -> &[u8; BODY_MROWNER_SIZE] {
        &self.body.mrowner
    }

    /// Software-defined ID for owner-defined configuration of the TD.
    pub fn mrownerconfig(&self) -> &[u8; BODY_MROWNERCONFIG_SIZE] {
        &self.body.mrownerconfig
    }

    /// The runtime extendable measurement registers (RTMR0..=RTMR3).
    pub fn rtmrs(&self) -> &[[u8; BODY_RTMR_SIZE]; RTMR_COUNT] {
        &self.body.rtmrs
    }

    /// XFAM (eXtended Features Available Mask), a 64-bit bitmap in XCR0/IA32_XSS format.
    pub fn xfam(&self) -> &[u8; BODY_XFAM_SIZE] {
        &self.body.xfam
    }

    /// Check the TD report against a policy; every pinned field must match exactly.
    ///
    /// Equality only — the quote's signatures still have to be checked with [`Self::verify`].
    pub fn check_policy(&self, policy: &TdReportPolicy) -> Result<(), PolicyError> {
        let matches = policy.mrtd == *self.mrtd()
            && policy.report_data == *self.report_data()
            && policy.xfam.is_none_or(|v| v == *self.xfam())
            && policy.mrconfigid.is_none_or(|v| v == *self.mrconfigid())
            && policy.mrowner.is_none_or(|v| v == *self.mrowner())
            && policy
                .mrownerconfig
                .is_none_or(|v| v == *self.mrownerconfig())
            && policy
                .rtmrs
                .iter()
                .zip(self.rtmrs())
                .all(|(p, r)| p.is_none_or(|v| v == *r));
        if matches {
            Ok(())
        } else {
            Err(PolicyError::Mismatch)
        }
    }

    fn extended_checks(&self) -> Result<(), VerificationError> {
        // Section 2.3.2 "Extended TD Checks" of the Intel TDX DCAP Quoting Library API (see module docs)

        // Verify that all TD Under Debug flags are set to zero.
        if self.body.tdattributes[TDATTRIBUTES_DEBUG_INDEX] != TDATTRIBUTES_DEBUG_DISABLED {
            return Err(VerificationError::DebugModeEnabled);
        }
        Ok(())
    }

    fn check_tcb_level(&self, levels: &Vec<TcbLevel>) -> TcbStatus {
        let (status, _) =
            crate::intel::collaterals::compare_tcb_levels(&self.body.tee_tcb_svn, levels);
        status
    }

    /// Verify the quote against the provided TCB info and CRL.
    pub fn verify(
        &self,
        tcb: &TcbInfo,
        crl: &crate::cert::Crl,
        now: u64,
    ) -> Result<(), VerificationError> {
        // As per Intel documentation this needs to:
        // - Check the PCK Cert (signature chain).
        // - Check if the PCK Cert is on the CRL.
        // - Check the verification collaterals' cert signature chain, including PCK Cert Chain, TCB info chain and QE identity chain
        // - Check if verification collaterals are on the CRL.
        // - Check the TDQE Report signature and the contained AK hash using the PCK Cert.
        // - (NOT IMPLEMENTED!) Check the measurements of the TDQE contained in the TDQE Report.
        // - Check the signature of the TD Quote using the public key–part of the AK. Implicitly, this validated
        // the TD and TDX Module measurements.
        // - Evaluate the TDX TCB information contained in the TD Quote.

        let mut signed_data = [0u8; QUOTE_HEADER_SIZE + QUOTE_BODY_SIZE];
        self.header.to_bytes(&mut signed_data);
        self.body.to_bytes(&mut signed_data[QUOTE_HEADER_SIZE..]);

        self.quote_signature_data
            .verify(&signed_data[..], tcb, crl, now)?;

        let tcb_status = self.check_tcb_level(&tcb.tcb_levels);
        if tcb_status >= TcbStatus::Revoked {
            return Err(VerificationError::BadTcbStatus(tcb_status));
        }

        self.extended_checks()?;
        Ok(())
    }
}

/// Parse a quote from raw bytes.
pub fn parse_quote(input: &[u8]) -> Result<QuoteV4, ParseError> {
    QuoteV4::from_bytes(input)
}

#[cfg(test)]
mod should {
    use crate::intel::collaterals::parse_tcb_response;
    use crate::intel::constants::{
        CERT_DATA_TYPE_QE_REPORT, ECDSA_SIGNATURE_SIZE, QE_REPORT_SIZE, QUOTE_BODY_SIZE,
        QUOTE_HEADER_SIZE,
    };
    use crate::intel::policy::{PolicyError, TdReportPolicy};
    use crate::intel::quote::{
        parse_quote, ParseError, QeReportCertificationData, QuoteV4, VerificationError,
    };
    use assert_ok::assert_ok;
    use rstest::rstest;
    use std::{fs::File, io::Read};

    fn load_file(path: &str) -> Vec<u8> {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    #[rstest]
    #[case("assets/tests/intel/quote_b0.dat")]
    #[case("assets/tests/intel/quote_90.dat")]
    #[case("assets/tests/intel/quote_no_cert.dat")]
    fn parses_quote(#[case] path: &str) {
        let buf = load_file(path);
        assert_ok!(parse_quote(&buf));
    }

    #[rstest]
    #[should_panic(expected = "InvalidHeader")]
    fn parse_truncated_header_fails() {
        assert_ok!(parse_quote(&[0u8; 1]));
    }

    #[rstest]
    #[should_panic(expected = "UnsupportedAttestationKeyType")]
    fn parse_invalid_header_fails() {
        let quote_data = load_file("assets/tests/intel/quote_90.dat");
        let mut invalid_data = quote_data.clone();
        invalid_data[2] = 0xFF;
        invalid_data[3] = 0xFF;

        assert_ok!(parse_quote(&invalid_data));
    }

    #[rstest]
    fn verify_quote() {
        let quote_buf = load_file("assets/tests/intel/quote_b0.dat");
        let q = parse_quote(&quote_buf).unwrap();

        let tcb_buf = load_file("assets/tests/intel/tcb_info_b0.json");
        let tcb = parse_tcb_response(&tcb_buf).unwrap();
        let crl: crate::cert::Crl = vec![];
        let now: u64 = 1769529377; // Tue Jan 27 2026 15:56:17 GMT+0000
        assert_ok!(q.verify(&tcb.tcb_info, &crl, now));
    }

    #[rstest]
    #[should_panic(expected = "BadTcbStatus")]
    fn verify_quote_with_bad_tcb_status() {
        let quote_buf = load_file("assets/tests/intel/quote_90.dat");
        let q = parse_quote(&quote_buf).unwrap();

        let tcb_buf = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb = parse_tcb_response(&tcb_buf).unwrap();
        let crl: crate::cert::Crl = vec![];
        let now: u64 = 1769529377; // Tue Jan 27 2026 15:56:17 GMT+0000
        assert_ok!(q.verify(&tcb.tcb_info, &crl, now));
    }

    #[test]
    fn body_round_trips_exactly() {
        let raw = load_file("assets/tests/intel/quote_b0.dat");
        let q = parse_quote(&raw).unwrap();
        let mut out = [0u8; QUOTE_HEADER_SIZE + QUOTE_BODY_SIZE];
        q.header.to_bytes(&mut out);
        q.body.to_bytes(&mut out[QUOTE_HEADER_SIZE..]);
        assert_eq!(&out[..], &raw[..QUOTE_HEADER_SIZE + QUOTE_BODY_SIZE]);
    }

    #[test]
    fn exposes_report_data() {
        let raw = load_file("assets/tests/intel/quote_b0.dat");
        let q = parse_quote(&raw).unwrap();
        assert_eq!(
            q.report_data(),
            &hex_literal::hex!(
                "9a9d48e7f6799642d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9
                 eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20"
            )
        );
    }

    #[test]
    fn reject_unsupported_version() {
        let mut buf = load_file("assets/tests/intel/quote_b0.dat");
        buf[0] = 5;
        assert_eq!(
            parse_quote(&buf).unwrap_err(),
            ParseError::UnsupportedQuoteVersion
        );
    }

    #[test]
    fn reject_unsupported_tee_type() {
        let mut buf = load_file("assets/tests/intel/quote_b0.dat");
        buf[4] = 0x00; // SGX
        assert_eq!(
            parse_quote(&buf).unwrap_err(),
            ParseError::UnsupportedTeeType
        );
    }

    #[test]
    fn reject_nested_qe_report_certification_data() {
        let mut data = vec![0u8; QE_REPORT_SIZE + ECDSA_SIGNATURE_SIZE];
        data.extend_from_slice(&0u16.to_le_bytes()); // empty auth data
        data.extend_from_slice(&CERT_DATA_TYPE_QE_REPORT.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            QeReportCertificationData::from_bytes(&data).unwrap_err(),
            ParseError::UnsupportedCertificationDataType
        );
    }

    #[test]
    fn reject_truncated_qe_report() {
        assert_eq!(
            QeReportCertificationData::from_bytes(&[0u8; QE_REPORT_SIZE]).unwrap_err(),
            ParseError::InvalidQeReport
        );
    }

    #[test]
    fn reject_oversized_authentication_data() {
        let mut data = vec![0u8; QE_REPORT_SIZE + ECDSA_SIGNATURE_SIZE];
        data.extend_from_slice(&16u16.to_le_bytes()); // claims 16 bytes, none present
        assert_eq!(
            QeReportCertificationData::from_bytes(&data).unwrap_err(),
            ParseError::InvalidAuthenticationData
        );
    }

    fn policy_of(q: &QuoteV4) -> TdReportPolicy {
        TdReportPolicy {
            xfam: Some(*q.xfam()),
            mrtd: *q.mrtd(),
            mrconfigid: Some(*q.mrconfigid()),
            mrowner: Some(*q.mrowner()),
            mrownerconfig: Some(*q.mrownerconfig()),
            rtmrs: q.rtmrs().map(Some),
            report_data: *q.report_data(),
        }
    }

    #[test]
    fn accept_matching_policy() {
        let raw = load_file("assets/tests/intel/quote_b0.dat");
        let q = parse_quote(&raw).unwrap();
        let policy = policy_of(&q);
        assert_ok!(q.check_policy(&policy));
        // and through the canonical byte encoding
        let parsed = TdReportPolicy::from_bytes(&policy.to_bytes()).unwrap();
        assert_ok!(q.check_policy(&parsed));
    }

    #[test]
    fn accept_matching_minimal_policy() {
        let raw = load_file("assets/tests/intel/quote_b0.dat");
        let q = parse_quote(&raw).unwrap();
        let mut policy = policy_of(&q);
        policy.xfam = None;
        policy.mrconfigid = None;
        policy.mrowner = None;
        policy.mrownerconfig = None;
        policy.rtmrs = [None; 4];
        assert_ok!(q.check_policy(&policy));
    }

    #[test]
    fn reject_mismatched_policy() {
        let raw = load_file("assets/tests/intel/quote_b0.dat");
        let q = parse_quote(&raw).unwrap();

        let mut policy = policy_of(&q);
        policy.mrtd[0] ^= 1;
        assert_eq!(q.check_policy(&policy).unwrap_err(), PolicyError::Mismatch);

        let mut policy = policy_of(&q);
        policy.report_data[63] ^= 1;
        assert_eq!(q.check_policy(&policy).unwrap_err(), PolicyError::Mismatch);

        let mut policy = policy_of(&q);
        policy.rtmrs[2].as_mut().unwrap()[0] ^= 1;
        assert_eq!(q.check_policy(&policy).unwrap_err(), PolicyError::Mismatch);
    }

    #[test]
    fn reject_quote_wo_certificates() {
        let quote_buf = load_file("assets/tests/intel/quote_no_cert.dat");
        let q = parse_quote(&quote_buf).unwrap();

        let tcb_buf = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb = parse_tcb_response(&tcb_buf).unwrap();
        let crl: crate::cert::Crl = vec![];
        let now: u64 = 1769529377; // Tue Jan 27 2026 15:56:17 GMT+0000
        assert_eq!(
            q.verify(&tcb.tcb_info, &crl, now),
            Err(VerificationError::PKCChain)
        );
    }
}
