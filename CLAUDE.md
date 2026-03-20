# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a monorepo of a Rust library that implements verification functionalities for various TEE frameworks (currently limited to Intel TDX, but open to expansions).

## Rust Toolchain

This repo is meant to be compiled with a stable Rust toolchain. The nightly toolchain is only used for checking unneeded dependencies with udeps. This is a no_std crate, and to help verify that we are not unintentionally importing indirect std dependencies, we test the compilation on a bare metal configuration.

## Build Commands

```bash
# Build the library
cargo build --release

# Build bare metal
cargo make build-bare-metal
```

## Formatting and linting

```bash
cargo fmt
cargo clippy --release
```

## Check dependencies

```bash
cargo make udeps
```

## Testing

```bash
cargo test --release
```

## Development Guidelines

The main usage of this repo is to implement TEE verification pallets in zkVerify (https://github.com/zkVerify/zkVerify, for now only in the `dr/add_tee_verifier_crl` branch.)

In that regard, we want to minimize the size of the resulting runtime wasm, and to minimize the chances of indirectly pulling in dependencies on std, for example caused by shared sub-dependencies with other crates used by zkVerify, where std is not disabled (features are additive!). Long story short, try to minimize the number of external crates imported, and alway try to pick the smallest/simplest external crate when needed.

Always check that the bare metal build works, that tests pass, and that the format/linting is accepted before finishing any coding task.
