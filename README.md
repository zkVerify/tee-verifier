# tee-verifier

A Rust library for TEE (Trusted Execution Environment) attestation quote verification. Designed to support multiple TEE platforms through a modular architecture.

## Supported platforms

- **Intel TDX / SGX** — Quote v4 parsing and ECDSA-P256 signature verification, X.509 certificate chain validation with CRL support, TCB collateral verification
- **AWS Nitro Enclaves** — COSE_Sign1 attestation document parsing with ECDSA-P384 signature verification, certificate chain validation against AWS Nitro root CA

## Features

- **`no_std` compatible** — works in bare-metal and embedded environments
- **Modular design** — each TEE platform is implemented as a self-contained module

## Usage

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
tee-verifier = { git = "https://github.com/zkVerify/tee-verifier" }
```

### Intel TDX/SGX quote verification

```rust
use tee_verifier::{intel_parse_quote, intel_parse_tcb_response, parse_crl_pem};

// 1. Parse the CRL and validate its signature against the certificate chain
let (crl_issue_time, crl) = parse_crl_pem(
    &crl_pem,
    &pck_certificate_chain_pem,
    Some(&intel_root_cert_der),
    now_unix_timestamp,
).unwrap();

// 2. Parse and verify TCB collateral
let tcb_response = intel_parse_tcb_response(&tcb_json).unwrap();
tcb_response.verify(tcb_signing_chain_pem, &crl, now_unix_timestamp).unwrap();

// 3. Parse and verify the attestation quote
let quote = intel_parse_quote(&raw_quote_bytes).unwrap();
quote.verify(&tcb_response.tcb_info, &crl, now_unix_timestamp).unwrap();
```

### AWS Nitro Enclaves attestation verification

```rust
use tee_verifier::nitro_parse_attestation;

// 1. Parse the COSE_Sign1 attestation document
let attestation = nitro_parse_attestation(&raw_attestation_bytes).unwrap();

// 2. Verify the signature and certificate chain against the AWS Nitro root CA
attestation.verify(None, now_unix_timestamp).unwrap();

// 3. Access attestation fields
let module_id = &attestation.module_id;
let pcrs = &attestation.pcrs;
let user_data = &attestation.user_data;
```

### `no_std`

Disable default features to use in a `no_std` environment:

```toml
[dependencies]
tee-verifier = { git = "https://github.com/zkVerify/tee-verifier", default-features = false }
```

## Building

```bash
cargo build
```

With [cargo-make](https://github.com/sagiegurari/cargo-make):

```bash
cargo make build     # Build
cargo make test      # Run tests (release mode)
cargo make clippy    # Lint
cargo make format    # Format code
cargo make ci        # Full CI suite
```

## License

This project is licensed under the Apache License, Version 2.0 — see the [LICENSE-APACHE2](LICENSE-APACHE2) file for details.
