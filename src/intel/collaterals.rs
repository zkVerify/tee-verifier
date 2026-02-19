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
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::intel::constants::{ECDSA_SIGNATURE_SIZE, MAX_COLLATERAL_SIZE};
use crate::intel::quote::{PceSvn, TcbSvn};

/// Errors that can occur during collateral verification.
#[derive(Debug)]
pub enum CollateralError {
    /// Failed to parse collateral data.
    Parse,
    /// The TCB info is invalid.
    InvalidTcb,
    /// The collateral is not yet valid.
    TooEarly,
    /// The collateral has expired.
    Expired,
    /// PCK certificate chain verification failed.
    PKCChain,
    /// The signature is invalid.
    BadSignature,
}

/// A signed TCB info response from Intel.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbResponse {
    /// The TCB info payload.
    pub tcb_info: TcbInfo,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub id: String,
    pub version: u8,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u32,
    pub tcb_evaluation_data_number: u32,
    pub tdx_module: TdxModule,
    pub tdx_module_identities: Vec<TdxModuleIdentity>,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    pub id: String,
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: String,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    #[serde(rename = "isvsvn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isv_svn: Option<u16>, // from the docs, "integer"
    #[serde(rename = "sgxtcbcomponents")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sgx_components: Option<Vec<TcbComponents>>,
    #[serde(rename = "pcesvn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pce_svn: Option<u16>,
    #[serde(rename = "tdxtcbcomponents", default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_components: Option<Vec<TcbComponents>>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct TcbComponents {
    pub svn: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttype: Option<String>,
}

impl PartialEq<u8> for TcbComponents {
    fn eq(&self, other: &u8) -> bool {
        self.svn == *other
    }
}

impl PartialOrd<u8> for TcbComponents {
    fn partial_cmp(&self, other: &u8) -> Option<core::cmp::Ordering> {
        Some(self.svn.cmp(other))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd)]
pub enum TcbStatus {
    UpToDate = 0,
    OutOfDateConfigurationNeeded = 1,
    OutOfDate = 2,
    ConfigurationAndSWHardeningNeeded = 3,
    ConfigurationNeeded = 4,
    SWHardeningNeeded = 5,
    Revoked = 6,
}

impl TcbResponse {
    /// Verify the TCB response signature and validity period.
    pub fn verify(
        &self,
        certs: Vec<u8>,
        crl: &crate::cert::Crl,
        now: u64,
    ) -> Result<(), CollateralError> {
        let cert = crate::cert::verify_pem_cert_chain(
            &certs,
            Some(crate::intel::ROOT_CERT),
            Some(crl),
            now,
        )
        .map_err(|_| CollateralError::PKCChain)?;
        let data: serde_json_core::heapless::Vec<u8, MAX_COLLATERAL_SIZE> =
            serde_json_core::to_vec(&self.tcb_info).map_err(|_| CollateralError::PKCChain)?;
        let mut signature_bytes = [0u8; ECDSA_SIGNATURE_SIZE];
        hex::decode_to_slice(&self.signature, &mut signature_bytes)
            .map_err(|_| CollateralError::PKCChain)?;
        crate::cert::verify_signature(&cert, data.as_slice(), &signature_bytes)
            .map_err(|_| CollateralError::BadSignature)?;
        self.tcb_info.verify(now)
    }
}

impl TcbInfo {
    pub fn verify(&self, now: u64) -> Result<(), CollateralError> {
        let issue = chrono::DateTime::parse_from_rfc3339(&self.issue_date)
            .map_err(|_| CollateralError::InvalidTcb)?
            .timestamp() as u64;
        if now < issue {
            return Err(CollateralError::TooEarly);
        }
        let next = chrono::DateTime::parse_from_rfc3339(&self.next_update)
            .map_err(|_| CollateralError::InvalidTcb)?
            .timestamp() as u64;
        if now > next {
            return Err(CollateralError::Expired);
        }

        Ok(())
    }
}

/// Parse a TCB response from JSON bytes.
pub fn parse_tcb_response(input: &[u8]) -> Result<TcbResponse, CollateralError> {
    let (tcb_response, _): (TcbResponse, usize) =
        serde_json_core::from_slice(input).map_err(|_| CollateralError::Parse)?;
    Ok(tcb_response)
}

pub fn compare_tcb_levels(quote_tcb: &TcbSvn, levels: &Vec<TcbLevel>) -> (TcbStatus, PceSvn) {
    // Compare SVNs in TEE TCB SVN array retrieved from TD Report in Quote (from index 0 to 15 if TEE TCB SVN at index 1 is set to 0, or from index 2 to 15 otherwise) with the corresponding values of SVNs in tdxtcbcomponents array of TCB Level. If all TEE TCB SVNs in the TD Report are greater or equal to the corresponding values in TCB Level, read tcbStatus assigned to this TCB level. Otherwise, move to the next item on TCB Levels list.
    for tcb_level in levels {
        if tcb_level.tcb.tdx_components.is_none() {
            continue;
        }
        let coll_tcb = &tcb_level
            .tcb
            .tdx_components
            .as_ref()
            .expect("tdx_components checked for Some above");
        if quote_tcb.len() != coll_tcb.len() {
            continue;
        }
        let mut t = match quote_tcb[1] {
            0 => 0,
            _ => 2, // as per documentation
        };
        while t < quote_tcb.len() {
            if coll_tcb[t] > quote_tcb[t] {
                break;
            }
            t += 1;
        }
        if t < quote_tcb.len() {
            continue;
        }
        return (tcb_level.tcb_status.clone(), 0);
    }
    (TcbStatus::Revoked, 0)
}

/// Compare SGX TCB SVNs extracted from the PCK certificate against the
/// sgxtcbcomponents in each TCB level of the collateral.
pub fn compare_sgx_tcb_levels(cert_tcb: &TcbSvn, levels: &Vec<TcbLevel>) -> (TcbStatus, PceSvn) {
    for tcb_level in levels {
        let Some(coll_tcb) = tcb_level.tcb.sgx_components.as_ref() else {
            continue;
        };
        if cert_tcb.len() != coll_tcb.len() {
            continue;
        }
        let mut t = 0;
        while t < cert_tcb.len() {
            if coll_tcb[t] > cert_tcb[t] {
                break;
            }
            t += 1;
        }
        if t < cert_tcb.len() {
            continue;
        }
        let pce = tcb_level.tcb.pce_svn.unwrap_or(0);
        return (tcb_level.tcb_status.clone(), pce);
    }
    (TcbStatus::Revoked, 0)
}

#[cfg(test)]
mod should {
    use super::parse_tcb_response;
    use assert_ok::assert_ok;
    use std::{fs::File, io::Read};

    fn load_file(path: &str) -> Vec<u8> {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn parse_tcb_info() {
        let buf = load_file("assets/tests/intel/tcb_info_90.json");
        assert_ok!(parse_tcb_response(&buf));
    }

    #[test]
    fn verify_tcb_response() {
        let tcb_buf = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb = parse_tcb_response(&tcb_buf).unwrap();

        let chain_buf = load_file("assets/tests/intel/tcb_info_90.pem");

        let time = chrono::DateTime::parse_from_rfc3339("2026-01-23T16:43:44Z")
            .unwrap()
            .timestamp() as u64;
        let crl: crate::cert::Crl = vec![];
        assert_ok!(tcb.verify(chain_buf, &crl, time));
    }

    #[test]
    fn verify_at_exact_issue_date() {
        let buf = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb = parse_tcb_response(&buf).unwrap();

        let issue_date = chrono::DateTime::parse_from_rfc3339(&tcb.tcb_info.issue_date)
            .unwrap()
            .timestamp() as u64;

        assert_ok!(tcb.tcb_info.verify(issue_date));
    }

    #[test]
    fn verify_at_exact_next_update() {
        let buf = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb = parse_tcb_response(&buf).unwrap();

        let next_update = chrono::DateTime::parse_from_rfc3339(&tcb.tcb_info.next_update)
            .unwrap()
            .timestamp() as u64;

        assert_ok!(tcb.tcb_info.verify(next_update));
    }

    #[test]
    fn reject_one_second_before_issue_date() {
        let buf = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb = parse_tcb_response(&buf).unwrap();

        let issue_date = chrono::DateTime::parse_from_rfc3339(&tcb.tcb_info.issue_date)
            .unwrap()
            .timestamp() as u64;

        assert!(matches!(
            tcb.tcb_info.verify(issue_date - 1),
            Err(super::CollateralError::TooEarly)
        ));
    }

    #[test]
    fn reject_one_second_after_next_update() {
        let buf = load_file("assets/tests/intel/tcb_info_90.json");
        let tcb = parse_tcb_response(&buf).unwrap();

        let next_update = chrono::DateTime::parse_from_rfc3339(&tcb.tcb_info.next_update)
            .unwrap()
            .timestamp() as u64;

        assert!(matches!(
            tcb.tcb_info.verify(next_update + 1),
            Err(super::CollateralError::Expired)
        ));
    }
}
