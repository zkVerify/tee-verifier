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

static ROOT_CERT: &[u8] =
    include_bytes!("../assets/Intel_SGX_Provisioning_Certification_RootCA.cer");

mod collaterals;
mod constants;
mod quote;

pub use collaterals::{CollateralError, TcbResponse};
pub use quote::{ParseError, QuoteV4, VerificationError};

/// Parse a TCB response from JSON bytes.
pub fn parse_tcb_response(input: &[u8]) -> Result<TcbResponse, CollateralError> {
    collaterals::parse_tcb_response(input)
}

pub fn parse_quote(input: &[u8]) -> Result<QuoteV4, ParseError> {
    quote::parse_quote(input)
}
