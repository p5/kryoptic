# Kryoptic Build Configurations

This document explains the different build configurations available for Kryoptic, focusing on the differences between dynamic and FIPS builds.

## Quick Reference

| Configuration | Command | Use Case |
|--------------|---------|----------|
| **Default (Dynamic)** | `cargo build` | Development, non-FIPS systems |
| **Dynamic + Jitterentropy** | `cargo build --features jitterentropy` | FIPS-grade entropy on non-FIPS systems |
| **FIPS Provider** | `cargo build --no-default-features --features "standard,fips,jitterentropy"` | Full FIPS 140-3 certification |

## Build Modes

### Dynamic Mode (Default)

Links against the system's installed OpenSSL shared library (`libcrypto.so`).

```bash
# Uses default features: standard + dynamic
cargo build

# With jitterentropy for better entropy
cargo build --features jitterentropy
```

**Characteristics:**
- Fast compilation (no OpenSSL build)
- Uses system OpenSSL (3.0.7+ required)
- Suitable for development and testing
- NOT suitable for FIPS certification (uses system crypto)

**When to use:**
- Local development
- Testing on non-FIPS systems
- Quick iteration during development
- Systems where OpenSSL is already installed and maintained

### FIPS Mode

Builds OpenSSL's FIPS provider (`libfips.a`) from source and statically links it.

```bash
# Set OpenSSL source path
export KRYOPTIC_OPENSSL_SOURCES=/path/to/openssl

# Build with FIPS (must disable default features to avoid dynamic)
cargo build --no-default-features --features "standard,fips,jitterentropy"
```

**Characteristics:**
- Requires OpenSSL 3.5.0+ source code
- Statically links `libfips.a`
- Includes post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA)
- Suitable for FIPS 140-3 certification
- Longer build time (compiles OpenSSL)

**When to use:**
- FIPS 140-3 certified deployments
- Environments requiring post-quantum cryptography
- Standalone cryptographic modules
- Air-gapped or controlled build environments

## Why FIPS and Dynamic are Mutually Exclusive

```rust
// From build.rs
#[cfg(all(feature = "fips", feature = "dynamic"))]
compile_error!("FIPS builds are incompatible with dynamic linking to OpenSSL");
```

**Reasons:**

1. **Cryptographic Module Boundary**: FIPS 140-3 requires a defined cryptographic boundary. Dynamic linking to a system library means the boundary includes code outside your control.

2. **Integrity Verification**: The FIPS module must verify its own integrity at startup. This is only possible with static linking where the code is known at build time.

3. **Algorithm Restrictions**: FIPS mode restricts which algorithms are available. A dynamically linked OpenSSL might have non-approved algorithms enabled.

4. **Version Control**: FIPS certification is for a specific version. Dynamic linking could load a different (uncertified) version at runtime.

## Feature Breakdown

### Cryptographic Algorithm Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `aes` | AES encryption/decryption | - |
| `rsa` | RSA operations | - |
| `ecc` | Elliptic curve base support | - |
| `ecdsa` | ECDSA signatures | `ecc` |
| `ecdh` | ECDH key agreement | `ecc` |
| `eddsa` | EdDSA (Ed25519, Ed448) | `ecc`, `ossl320` |
| `ec_montgomery` | X25519, X448 | `ecc` |
| `ffdh` | Finite-field Diffie-Hellman | - |
| `hash` | Hash functions (SHA-2, SHA-3) | - |
| `hmac` | HMAC operations | `hash` |

### Key Derivation Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `hkdf` | HKDF (RFC 5869) | `hmac` |
| `pbkdf2` | PBKDF2 | `hmac` |
| `sp800_108` | SP800-108 KDF | - |
| `sshkdf` | SSH KDF | - |
| `tlskdf` | TLS 1.2/1.3 KDF | - |
| `simplekdf` | Simple concatenation KDFs | - |

### Post-Quantum Cryptography Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `mlkem` | ML-KEM (Kyber) | `ossl350` |
| `mldsa` | ML-DSA (Dilithium) | `hash`, `ossl350` |
| `slhdsa` | SLH-DSA (SPHINCS+) | `hash`, `ossl350` |
| `pqc` | All post-quantum algorithms | `mlkem`, `mldsa`, `slhdsa` |

### Database Storage Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `memorydb` | In-memory storage (testing) | `aes`, `hkdf`, `pbkdf2` |
| `sqlitedb` | SQLite-based storage | `rusqlite`, `aes`, `hkdf`, `pbkdf2` |
| `nssdb` | NSS database compatibility | `rusqlite`, `aes`, `hmac`, `pbkdf2` |

### Build Mode Features

| Feature | Description | Effect |
|---------|-------------|--------|
| `dynamic` | Dynamic linking | Links to system `libcrypto.so` |
| `fips` | FIPS mode | Builds and links `libfips.a` from source |
| `jitterentropy` | Jitterentropy entropy | Dynamic: links to system `libjitterentropy.so`; FIPS: compiles from source |

### OpenSSL Version Features

| Feature | Minimum Version | Enables |
|---------|-----------------|---------|
| `ossl320` | OpenSSL 3.2.0 | EdDSA support |
| `ossl350` | OpenSSL 3.5.0 | PQC algorithms, FIPS mode |
| `ossl400` | OpenSSL 4.0.0 | Future features |

### Convenience Feature Sets

| Feature | Includes | Purpose |
|---------|----------|---------|
| `ecc_min` | `ecdsa`, `ecdh` | Minimal ECC support |
| `ecc_all` | `ecc_min`, `ec_montgomery`, `eddsa` | Full ECC support |
| `hash_all` | `hash`, `hmac` | All hash operations |
| `kdf_all` | All KDF features | All key derivation |
| `standard` | `sqlitedb`, `ecc_all`, `ffdh`, `hash_all`, `kdf_all`, `rsa` | Standard build |
| `minimal` | `sqlitedb`, `aes`, `ecc_min`, `hash_all`, `rsa` | Minimal build |

### Default Features

```toml
default = ["standard", "dynamic"]
```

The default build includes:
- All standard cryptographic algorithms
- SQLite database storage
- Dynamic linking to system OpenSSL

## Build Examples

### Development Build (Fastest)

```bash
cargo build
```

Features: `standard` + `dynamic`

### Development with Jitterentropy

```bash
cargo build --features jitterentropy
```

Features: `standard` + `dynamic` + `jitterentropy`

### Minimal Build

```bash
cargo build --no-default-features --features "minimal,dynamic"
```

Features: `minimal` + `dynamic` (smaller binary, fewer algorithms)

### FIPS Build (Full)

```bash
export KRYOPTIC_OPENSSL_SOURCES=/path/to/openssl-3.6.1
cargo build --no-default-features --features "standard,fips,jitterentropy"
```

Features: `standard` + `fips` + `jitterentropy` (includes PQC)

### FIPS Build (Release)

```bash
export KRYOPTIC_OPENSSL_SOURCES=/path/to/openssl-3.6.1
cargo build --release --no-default-features --features "standard,fips,jitterentropy"
```

### FIPS Build with Logging

```bash
export KRYOPTIC_OPENSSL_SOURCES=/path/to/openssl-3.6.1
cargo build --no-default-features --features "standard,fips,jitterentropy,log"
```

## Container Builds

Using the provided Containerfile:

```bash
# Build container
podman build -t kryoptic-build -f Containerfile .

# Dynamic build
podman run --rm -v $(pwd):/workspace:Z -w /workspace/kryoptic kryoptic-build \
    cargo build --features jitterentropy

# FIPS build (requires OpenSSL sources in workspace)
podman run --rm -v $(pwd):/workspace:Z -w /workspace/kryoptic \
    -e KRYOPTIC_OPENSSL_SOURCES=/workspace/openssl \
    kryoptic-build \
    cargo build --no-default-features --features "standard,fips,jitterentropy"
```

## Environment Variables

| Variable | Purpose | Required For |
|----------|---------|--------------|
| `KRYOPTIC_OPENSSL_SOURCES` | Path to OpenSSL source directory | FIPS builds |
| `KRYOPTIC_JITTERENTROPY_SOURCES` | Path to jitterentropy-library sources | FIPS builds with jitterentropy |
| `KRYOPTIC_FIPS_VENDOR` | Vendor name for FIPS module | FIPS branding |
| `KRYOPTIC_FIPS_VERSION` | Version for FIPS module | FIPS versioning |
| `KRYOPTIC_FIPS_BUILD` | Build identifier | FIPS build tracking |

## Feature Compatibility Matrix

| Feature A | Feature B | Compatible | Notes |
|-----------|-----------|------------|-------|
| `dynamic` | `fips` | No | Mutually exclusive |
| `fips` | `jitterentropy` | Yes | Recommended for FIPS |
| `dynamic` | `jitterentropy` | Yes | Works for non-FIPS |
| `fips` | `pqc` | Yes | PQC included in FIPS |
| `eddsa` | `ossl320` | Required | EdDSA needs OpenSSL 3.2+ |
| `pqc` | `ossl350` | Required | PQC needs OpenSSL 3.5+ |

## Comparison: Dynamic vs FIPS

| Aspect | Dynamic | FIPS |
|--------|---------|------|
| **Build Time** | Fast (~30s) | Slow (~3-5 min) |
| **OpenSSL** | System shared library | Built from source |
| **OpenSSL Version** | 3.0.7+ | 3.5.0+ (3.6.1 recommended) |
| **Linking** | Dynamic (`libcrypto.so`) | Static (`libfips.a`) |
| **Binary Size** | Smaller | Larger |
| **PQC Algorithms** | Optional | Included |
| **FIPS Certification** | Not suitable | Suitable |
| **Entropy Source** | System (`getrandom`) | Configurable (jitterentropy) |
| **Integrity Check** | None | FIPS self-test |
| **Algorithm Restrictions** | None | FIPS-approved only |

## Troubleshooting

### "FIPS builds are incompatible with dynamic linking"

You're trying to use both `fips` and `dynamic` features. Use `--no-default-features`:

```bash
cargo build --no-default-features --features "standard,fips,jitterentropy"
```

### "KRYOPTIC_OPENSSL_SOURCES is not defined"

Set the environment variable to point to OpenSSL source code:

```bash
export KRYOPTIC_OPENSSL_SOURCES=/path/to/openssl
```

### "OpenSSL 3.5.0 or later is required"

Your OpenSSL sources are too old. Use OpenSSL 3.5.0 or later (3.6.1 recommended):

```bash
git clone --depth 1 --branch openssl-3.6.1 https://github.com/openssl/openssl.git
```

### Build is very slow

FIPS builds compile OpenSSL from source. This is expected. Use `--release` for production builds:

```bash
cargo build --release --no-default-features --features "standard,fips,jitterentropy"
```

## See Also

- [Jitterentropy Documentation](jitterentropy.md) - Understanding the entropy source
- [Jitterentropy Implementation](jitterentropy-implementation.md) - Developer details
