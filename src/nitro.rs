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

static ROOT_CERT: &[u8] = include_bytes!("../assets/aws_nitro_root_g1.der");

mod attestation;

pub use attestation::{NitroAttestation, NitroParseError, NitroVerificationError};

/// Parse a Nitro attestation document from binary COSE_Sign1 data.
pub fn parse_nitro_attestation(input: &[u8]) -> Result<NitroAttestation, NitroParseError> {
    attestation::parse_nitro_attestation(input)
}
