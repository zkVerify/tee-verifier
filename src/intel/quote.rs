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

pub use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::intel::collaterals::{TcbInfo, TcbLevel, TcbStatus};
use crate::intel::constants::*;

#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidHeader,
    InvalidAuthenticationData,
    InvalidQeReport,
    InvalidQeReportSignature,
    InvalidBody,
    UnsupportedAttestationKeyType,
    UnsupportedCertificationDataType,
    UnsupportedVendorId,
}

#[derive(Debug, PartialEq)]
pub enum VerificationError {
    FailedVerification,
    UnsupportedVerificationType,
    P256Error,
    PKCChain,
    CannotExtractIntelExtensions,
    CannotExtractFmspc,
    FmspcMismatch,
    DebugModeEnabled,
    BadTcbStatus(TcbStatus),
    BadPceStatus,
    BadSignature,
}

#[derive(Debug)]
struct QuoteHeader {
    /// Version of the quote_no_cert.data structure.
    version: i16,
    /// Type of the Attestation Key used by the Quoting Enclave.
    /// Supported values:
    /// 2 (ECDSA-256-with-P-256 curve)
    /// 3 (ECDSA-384-with-P-384 curve) (Note: currently not supported)
    /// (Note: 0 and 1 are reserved, for when EPID is moved to version 4 quotes.)
    attestation_key_type: i16,
    /// TEE for this Attestation
    /// 0x00000000: SGX
    /// 0x00000081: TDX
    tee_type: i32,
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
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        Ok(QuoteHeader {
            version: i16::from_le_bytes(
                input[HEADER_VERSION_OFFSET..HEADER_ATTESTATION_KEY_TYPE_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidHeader)?,
            ),
            attestation_key_type: i16::from_le_bytes(
                input[HEADER_ATTESTATION_KEY_TYPE_OFFSET..HEADER_TEE_TYPE_OFFSET]
                    .try_into()
                    .map_err(|_| ParseError::InvalidHeader)?,
            ),
            tee_type: i32::from_le_bytes(
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

    pub fn to_bytes(&self, output: &mut [u8]) {
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
    _size: i16,
    data: Vec<u8>,
}

impl QeAuthenticationData {
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        let size = i16::from_le_bytes(
            input[..AUTH_DATA_SIZE_FIELD]
                .try_into()
                .map_err(|_| ParseError::InvalidAuthenticationData)?,
        );
        let data = input[AUTH_DATA_SIZE_FIELD..AUTH_DATA_SIZE_FIELD + size as usize].to_vec();
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
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        let qe_report = &input[..QE_REPORT_SIZE];
        let qe_report_signature = &input[QE_REPORT_SIZE..QE_REPORT_SIZE + ECDSA_SIGNATURE_SIZE];
        // TODO: check the signature!!!
        let qe_authentication_data =
            QeAuthenticationData::from_bytes(&input[QE_REPORT_SIZE + ECDSA_SIGNATURE_SIZE..])?;
        let qe_certification_data = QeCertificationData::from_bytes(
            &input[QE_REPORT_SIZE
                + ECDSA_SIGNATURE_SIZE
                + AUTH_DATA_SIZE_FIELD
                + qe_authentication_data.data.len()..],
        )?;
        Ok(QeReportCertificationData {
            qe_report: qe_report
                .try_into()
                .map_err(|_| ParseError::InvalidQeReport)?,
            qe_report_signature: qe_report_signature
                .try_into()
                .map_err(|_| ParseError::InvalidQeReportSignature)?,
            qe_authentication_data,
            qe_certification_data,
        })
    }

    pub fn verify(
        &self,
        attestation_key: &[u8],
        tcb: &Option<TcbInfo>,
    ) -> Result<(), VerificationError> {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(&attestation_key);
            hasher.update(&self.qe_authentication_data.data.as_slice());
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
    _xfam: [u8; BODY_XFAM_SIZE],
    /// Measurement of the initial contents of the TD.
    _mrtd: [u8; BODY_MRTD_SIZE],
    /// Software-defined ID for non-owner-defined
    /// configuration of the TD, e.g., runtime or OS configuration.
    _mrconfigid: [u8; BODY_MRCONFIGID_SIZE],
    /// Software-defined ID for the TD's owner
    _mrowner: [u8; BODY_MROWNER_SIZE],
    /// Software-defined ID for owner-defined
    /// configuration of the TD, e.g., specific to the
    /// workload rather than the runtime or OS.
    _mrownerconfig: [u8; BODY_MROWNERCONFIG_SIZE],
    /// Runtime extendable measurement register
    _rtmr0: [u8; BODY_RTMR_SIZE],
    /// Runtime extendable measurement register
    _rtmr1: [u8; BODY_RTMR_SIZE],
    /// Runtime extendable measurement register
    _rtmr2: [u8; BODY_RTMR_SIZE],
    /// Runtime extendable measurement register
    _rtmr3: [u8; BODY_RTMR_SIZE],
    /// Each TD Quote is based on a TD Report. The
    /// TD is free to provide 64 bytes of custom data
    /// to a TD Report. For instance, this space can be
    /// used to hold a nonce, a public key, or a hash
    /// of a larger block of data.
    _reportdata: [u8; BODY_REPORTDATA_SIZE],
}

impl QuoteBodyV4 {
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
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
            _xfam: input[BODY_XFAM_OFFSET..BODY_MRTD_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _mrtd: input[BODY_MRTD_OFFSET..BODY_MRCONFIGID_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _mrconfigid: input[BODY_MRCONFIGID_OFFSET..BODY_MROWNER_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _mrowner: input[BODY_MROWNER_OFFSET..BODY_MROWNERCONFIG_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _mrownerconfig: input[BODY_MROWNERCONFIG_OFFSET..BODY_RTMR0_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _rtmr0: input[BODY_RTMR0_OFFSET..BODY_RTMR1_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _rtmr1: input[BODY_RTMR1_OFFSET..BODY_RTMR2_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _rtmr2: input[BODY_RTMR2_OFFSET..BODY_RTMR3_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _rtmr3: input[BODY_RTMR3_OFFSET..BODY_REPORTDATA_OFFSET]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
            _reportdata: input[BODY_REPORTDATA_OFFSET..QUOTE_BODY_SIZE]
                .try_into()
                .map_err(|_| ParseError::InvalidBody)?,
        })
    }

    pub fn to_bytes(&self, output: &mut [u8]) {
        output[BODY_TEE_TCB_SVN_OFFSET..BODY_MRSEAM_OFFSET].copy_from_slice(&self.tee_tcb_svn);
        output[BODY_MRSEAM_OFFSET..BODY_MRSIGNERSEAM_OFFSET].copy_from_slice(&self._mrseam);
        output[BODY_MRSIGNERSEAM_OFFSET..BODY_SEAMATTRIBUTES_OFFSET]
            .copy_from_slice(&self._mrsignerseam);
        output[BODY_SEAMATTRIBUTES_OFFSET..BODY_TDATTRIBUTES_OFFSET]
            .copy_from_slice(&self._seamattributes);
        output[BODY_TDATTRIBUTES_OFFSET..BODY_XFAM_OFFSET].copy_from_slice(&self.tdattributes);
        output[BODY_XFAM_OFFSET..BODY_MRTD_OFFSET].copy_from_slice(&self._xfam);
        output[BODY_MRTD_OFFSET..BODY_MRCONFIGID_OFFSET].copy_from_slice(&self._mrtd);
        output[BODY_MRCONFIGID_OFFSET..BODY_MROWNER_OFFSET].copy_from_slice(&self._mrconfigid);
        output[BODY_MROWNER_OFFSET..BODY_MROWNERCONFIG_OFFSET].copy_from_slice(&self._mrowner);
        output[BODY_MROWNERCONFIG_OFFSET..BODY_RTMR0_OFFSET].copy_from_slice(&self._mrownerconfig);
        output[BODY_RTMR0_OFFSET..BODY_RTMR1_OFFSET].copy_from_slice(&self._rtmr0);
        output[BODY_RTMR1_OFFSET..BODY_RTMR2_OFFSET].copy_from_slice(&self._rtmr1);
        output[BODY_RTMR2_OFFSET..BODY_RTMR3_OFFSET].copy_from_slice(&self._rtmr2);
        output[BODY_RTMR3_OFFSET..BODY_REPORTDATA_OFFSET].copy_from_slice(&self._rtmr3);
        output[BODY_REPORTDATA_OFFSET..QUOTE_BODY_SIZE].copy_from_slice(&self._reportdata);
    }
}

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
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        let certification_data_type =
            u16::from_le_bytes(input[..CERT_DATA_TYPE_FIELD_SIZE].try_into().unwrap());
        let size = u32::from_le_bytes(
            input[CERT_DATA_TYPE_FIELD_SIZE..CERT_DATA_HEADER_SIZE]
                .try_into()
                .unwrap(),
        );
        let certification_data =
            input[CERT_DATA_HEADER_SIZE..CERT_DATA_HEADER_SIZE + (size as usize)].to_vec();
        if certification_data_type != CERT_DATA_TYPE_PCK_CHAIN
            && certification_data_type != CERT_DATA_TYPE_QE_REPORT
        {
            return Err(ParseError::UnsupportedCertificationDataType);
        }

        Ok(QeCertificationData {
            certification_data_type,
            _size: size,
            certification_data,
        })
    }

    pub fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        attestation_key: &[u8],
        tcb: &Option<TcbInfo>,
    ) -> Result<(), VerificationError> {
        match self.certification_data_type {
            CERT_DATA_TYPE_PCK_CHAIN => {
                let cert = crate::cert::verify_pem_cert_chain(
                    &self.certification_data,
                    crate::intel::ROOT_CERT,
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

                if let Some(t) = tcb {
                    let mut tcb_buf = [0u8; FMSPC_SIZE];
                    hex::decode_to_slice(t.fmspc.clone(), &mut tcb_buf)
                        .map_err(|_| VerificationError::FmspcMismatch)?;
                    if tcb_buf != fmspc {
                        return Err(VerificationError::FmspcMismatch);
                    }

                    let tcb_oid =
                        spki::ObjectIdentifier::new(INTEL_TCB_OID).expect("Cannot decode OID");
                    let cert_tcb = crate::cert::extract_field(sgx_ext, tcb_oid)
                        .map_err(|_| VerificationError::CannotExtractIntelExtensions)?;
                    let (cert_tcb, cert_pce) = crate::cert::extract_tcb_info(cert_tcb, tcb_oid)
                        .map_err(|_| VerificationError::CannotExtractIntelExtensions)?;
                    let (tcb_status, pce_svn) =
                        crate::intel::collaterals::compare_tcb_levels(&cert_tcb, &t.tcb_levels);
                    if tcb_status >= TcbStatus::Revoked {
                        return Err(VerificationError::BadTcbStatus(tcb_status));
                    }
                    if cert_pce < pce_svn {
                        return Err(VerificationError::BadPceStatus);
                    }
                }

                let _ = crate::cert::verify_signature(&cert, data, signature)
                    .map_err(|_| VerificationError::BadSignature)?;
            }

            CERT_DATA_TYPE_QE_REPORT => {
                let qe_report_certification_data =
                    QeReportCertificationData::from_bytes(&self.certification_data[..]).unwrap();
                let _ = qe_report_certification_data.verify(attestation_key, tcb)?;
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
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        let quote_signature: [u8; ECDSA_SIGNATURE_SIZE] =
            input[..ECDSA_SIGNATURE_SIZE].try_into().unwrap();
        let ecdsa_attestation_key: [u8; ATTESTATION_KEY_SIZE] = input
            [ECDSA_SIGNATURE_SIZE..ECDSA_SIGNATURE_SIZE + ATTESTATION_KEY_SIZE]
            .try_into()
            .unwrap();
        let qe_certification_data =
            QeCertificationData::from_bytes(&input[ECDSA_SIGNATURE_SIZE + ATTESTATION_KEY_SIZE..])
                .unwrap();
        Ok(QuoteSignatureData {
            quote_signature,
            ecdsa_attestation_key,
            qe_certification_data,
        })
    }

    pub fn verify(
        &self,
        signed_data: &[u8],
        tcb: &Option<TcbInfo>,
    ) -> Result<(), VerificationError> {
        let key =
            VerifyingKey::from_sec1_bytes(&[&[4], &self.ecdsa_attestation_key[..]].concat()[..])
                .unwrap();
        key.verify(
            &signed_data,
            &Signature::from_bytes(&self.quote_signature.into()).unwrap(),
        )
        .map_err(|_| VerificationError::P256Error)?;
        self.qe_certification_data.verify(
            &signed_data,
            &self.quote_signature,
            &self.ecdsa_attestation_key,
            tcb,
        )
    }
}

impl QuoteV4 {
    pub fn from_bytes(input: &[u8]) -> Result<Self, ParseError> {
        // HEADER
        let header = QuoteHeader::from_bytes(&input)?;
        if header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA_256_P256 {
            return Err(ParseError::UnsupportedAttestationKeyType);
        }
        if header.qe_vendor_id != INTEL_VENDOR_ID {
            return Err(ParseError::UnsupportedVendorId);
        }

        // BODY
        let body = QuoteBodyV4::from_bytes(&input[QUOTE_HEADER_SIZE..])?;
        let signature_data_offset = QUOTE_HEADER_SIZE + QUOTE_BODY_SIZE;
        let quote_signature_data_len = u32::from_le_bytes(
            input[signature_data_offset..signature_data_offset + SIGNATURE_DATA_LEN_SIZE]
                .try_into()
                .unwrap(),
        );
        let signature_data_start = signature_data_offset + SIGNATURE_DATA_LEN_SIZE;
        let quote_signature_data: QuoteSignatureData = QuoteSignatureData::from_bytes(
            input[signature_data_start..signature_data_start + (quote_signature_data_len as usize)]
                .into(),
        )
        .unwrap();

        Ok(QuoteV4 {
            header,
            body,
            _quote_signature_data_len: quote_signature_data_len,
            quote_signature_data,
        })
    }

    fn extended_checks(&self) -> Result<(), VerificationError> {
        // Section 2.3.2 Extended TD Checks

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

    pub fn verify(&self, tcb: Option<TcbInfo>) -> Result<(), VerificationError> {
        // As per Intel documentation this needs to:
        // - Check the PCK Cert (signature chain).
        // - Check if the PCK Cert is on the CRL.
        // - Check the verification collaterals’ cert signature chain, including PCK Cert Chain, TCB info chain and QE identity chain
        // - Check if verification collaterals are on the CRL.
        // - Check the TDQE Report signature and the contained AK hash using the PCK Cert.
        // - Check the measurements of the TDQE contained in the TDQE Report.
        // - Check the signature of the TD Quote using the public key–part of the AK. Implicitly, this validated
        // the TD and TDX Module measurements.
        // - Evaluate the TDX TCB information contained in the TD Quote.

        let mut signed_data = [0u8; QUOTE_HEADER_SIZE + QUOTE_BODY_SIZE];
        self.header.to_bytes(&mut signed_data);
        self.body.to_bytes(&mut signed_data[QUOTE_HEADER_SIZE..]);

        let _ = self.quote_signature_data.verify(&signed_data[..], &tcb)?;

        if let Some(t) = &tcb {
            let tcb_status = self.check_tcb_level(&t.tcb_levels);
            if tcb_status >= TcbStatus::Revoked {
                return Err(VerificationError::BadTcbStatus(tcb_status));
            }
        }

        let _ = self.extended_checks()?;
        Ok(())
    }
}

#[cfg(test)]
mod should {
    use crate::intel::{
        collaterals::TcbResponse,
        quote::{QuoteV4, VerificationError},
    };
    use assert_ok::assert_ok;
    use rstest::rstest;
    use std::{fs::File, io::Read};

    #[rstest]
    #[case("assets/tests/intel/quote_b0.dat")]
    #[case("assets/tests/intel/quote_90.dat")]
    #[case("assets/tests/intel/quote_no_cert.dat")] // no certificates
    fn parse_quote(#[case] path: &str) {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::<u8>::new();
        let _ = f.read_to_end(&mut buf);
        assert_ok!(QuoteV4::from_bytes(&buf[..]));
    }

    #[rstest]
    #[case("assets/tests/intel/quote_b0.dat")]
    #[case("assets/tests/intel/quote_90.dat")]
    fn verify_quote(#[case] path: &str) {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::<u8>::new();
        let _ = f.read_to_end(&mut buf);
        let q = QuoteV4::from_bytes(&buf[..]).unwrap();
        assert_ok!(q.verify(None));
    }

    #[rstest]
    #[case(
        "assets/tests/intel/quote_90.dat",
        "assets/tests/intel/tcb_info_90.json"
    )]
    #[case(
        "assets/tests/intel/quote_b0.dat",
        "assets/tests/intel/tcb_info_b0.json"
    )]
    fn verify_quote_w_tcbinfo(#[case] quote_path: &str, #[case] coll_path: &str) {
        let mut f = File::open(quote_path).unwrap();
        let mut buf = Vec::<u8>::new();
        let _ = f.read_to_end(&mut buf);
        let q = QuoteV4::from_bytes(&buf[..]).unwrap();

        let mut f = File::open(coll_path).unwrap();
        let mut buf = Vec::<u8>::new();
        let _ = f.read_to_end(&mut buf);

        let (tcb, _used): (TcbResponse, usize) = serde_json_core::from_slice(&buf[..]).unwrap();
        assert_ok!(q.verify(Some(tcb.tcb_info)));
    }

    #[rstest]
    #[case("assets/tests/intel/quote_no_cert.dat")] // no certificates
    fn reject_quote_wo_certificates(#[case] path: &str) {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::<u8>::new();
        let _ = f.read_to_end(&mut buf);
        let q = QuoteV4::from_bytes(&buf[..]).unwrap();
        assert_eq!(q.verify(None), Err(VerificationError::PKCChain));
    }
}
