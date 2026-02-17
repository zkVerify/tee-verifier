# tee-verifier

A Rust library for TEE (Trusted Execution Environment) attestation quote verification. Designed to support multiple TEE platforms through a modular architecture.

## Supported platforms

- **Intel TDX / SGX** — Quote v4 parsing and ECDSA-P256 signature verification, X.509 certificate chain validation with CRL support, TCB collateral verification

## Features

- **`no_std` compatible** — works in bare-metal and embedded environments
- **Modular design** — each TEE platform is implemented as a self-contained module

## Usage

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
tee-verifier = { git = "https://github.com/zkVerify/tee-verifier" }
```

### Example: Intel TDX/SGX quote verification

```rust
use tee_verifier::{parse_crl, parse_quote, parse_tcb_response};

// 1. Parse the CRL and validate its signature against the certificate chain
let (crl_issue_time, crl) = parse_crl(
    &crl_pem,
    &pck_certificate_chain_pem,
    Some(&intel_root_cert_der),
    now_unix_timestamp,
).unwrap();

// 2. Parse and verify TCB collateral
let tcb_response = parse_tcb_response(&tcb_json).unwrap();
tcb_response.verify(tcb_signing_chain_pem, &crl, now_unix_timestamp).unwrap();

// 3. Parse and verify the attestation quote
let quote = parse_quote(&raw_quote_bytes).unwrap();
quote.verify(&tcb_response.tcb_info, &crl, now_unix_timestamp).unwrap();
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
