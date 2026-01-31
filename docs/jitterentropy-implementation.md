# Jitterentropy Integration: Developer Guide

This document describes the implementation details of the jitterentropy integration in Kryoptic, intended for developers who need to understand, maintain, or extend the code.

## Architecture Overview

The jitterentropy integration adds a pluggable entropy source abstraction to Kryoptic's FIPS provider, allowing different entropy sources to be used interchangeably.

```text
┌─────────────────────────────────────────────────────────────────┐
│                         ossl crate                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    fips.rs                              │    │
│  │  - ENTROPY_SOURCE: RwLock<Box<dyn EntropySource>>       │    │
│  │  - set_entropy_source()                                 │    │
│  │  - fips_get_entropy() ──────────────────────┐           │    │
│  │  - fips_get_nonce()                         │           │    │
│  └─────────────────────────────────────────────│───────────┘    │
│                                                │                │
│                                                ▼                │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  entropy/mod.rs                         │    │
│  │  - EntropySource trait                                  │    │
│  │  - GetrandomSource                                      │    │
│  │  - create_fips_entropy()                                │    │
│  └─────────────────────────────────────────────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │            entropy/jitterentropy.rs                     │    │
│  │  - FFI bindings to libjitterentropy                     │    │
│  │  - JitterentropySource                                  │    │
│  │  - JitterentropyConfig                                  │    │
│  │  - JitterentropyError                                   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                          │                                      │
└──────────────────────────│──────────────────────────────────────┘
                           │
                           ▼ (links to)
┌─────────────────────────────────────────────────────────────────┐
│                   libjitterentropy.a                            │
│              (built from jitterentropy-library)                 │
└─────────────────────────────────────────────────────────────────┘
```

## Files Changed/Added

| File | Type | Description |
| ---- | ---- | ----------- |
| `ossl/src/entropy/mod.rs` | New | Entropy source trait and implementations |
| `ossl/src/entropy/jitterentropy.rs` | New | Jitterentropy FFI and wrapper |
| `ossl/src/lib.rs` | Modified | Added `pub mod entropy` |
| `ossl/src/fips.rs` | Modified | Integrated entropy abstraction |
| `ossl/build.rs` | Modified | Added jitterentropy build |
| `ossl/Cargo.toml` | Modified | Added feature and dependencies |
| `Cargo.toml` | Modified | Added workspace feature |
| `src/config.rs` | Modified | Added `EntropySourceConfig` enum and `apply()` |
| `src/lib.rs` | Modified | Wired up entropy config during initialization |
| `Containerfile` | New | Build environment |
| `docs/jitterentropy.md` | New | User documentation |
| `docs/jitterentropy-implementation.md` | New | This document |
| `docs/build-configurations.md` | New | Build mode documentation |

## Detailed Implementation

### 1. Entropy Source Trait (`ossl/src/entropy/mod.rs`)

The core abstraction is the `EntropySource` trait:

```rust
pub trait EntropySource: Send + Sync + std::fmt::Debug {
    /// Returns the name of this entropy source
    fn name(&self) -> &'static str;

    /// Fills the buffer with entropy
    fn get_entropy(&self, buf: &mut [u8]) -> Result<usize, Error>;

    /// Fills the buffer with a nonce, optionally mixing in salt
    fn get_nonce(&self, buf: &mut [u8], salt: Option<&[u8]>) -> Result<usize, Error> {
        // Default implementation calls get_entropy and XORs with salt
    }

    /// Performs a health check
    fn health_check(&self) -> Result<(), Error> {
        Ok(())  // Default: no-op
    }

    /// Returns whether this source is available
    fn is_available(&self) -> bool {
        true  // Default: always available
    }
}
```

**Key design decisions:**

- **`Send + Sync`**: Required for thread-safe global storage
- **`Debug`**: Allows logging/debugging of entropy sources
- **Default implementations**: Reduce boilerplate for simple sources
- **`&'static str` for name**: Avoids allocation, safe for logging

### 2. GetrandomSource

Wraps the `getrandom` crate:

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct GetrandomSource;

impl EntropySource for GetrandomSource {
    fn name(&self) -> &'static str { "getrandom" }

    fn get_entropy(&self, buf: &mut [u8]) -> Result<usize, Error> {
        getrandom::fill(buf).map_err(|_| Error::new(ErrorKind::OsslError))?;
        Ok(buf.len())
    }
}
```

### 3. Jitterentropy FFI (`ossl/src/entropy/jitterentropy.rs`)

#### FFI Bindings

```rust
#[repr(C)]
pub struct rand_data {
    _opaque: [u8; 0],  // Opaque type
}

unsafe extern "C" {
    fn jent_entropy_init_ex(osr: c_uint, flags: c_uint) -> c_int;
    fn jent_entropy_collector_alloc(osr: c_uint, flags: c_uint) -> *mut rand_data;
    fn jent_entropy_collector_free(ec: *mut rand_data);
    fn jent_read_entropy(ec: *mut rand_data, data: *mut c_char, len: usize) -> isize;
    fn jent_read_entropy_safe(ec: *mut *mut rand_data, data: *mut c_char, len: usize) -> isize;
    fn jent_version() -> c_uint;
}
```

#### Thread-Safe Initialization

Uses `OnceLock` for guaranteed single initialization:

```rust
static JENT_INIT_RESULT: OnceLock<Result<(), c_int>> = OnceLock::new();

fn ensure_initialized(flags: c_uint) -> Result<(), JitterentropyError> {
    let result = JENT_INIT_RESULT.get_or_init(|| {
        let ret = unsafe { jent_entropy_init_ex(0, flags) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    });

    match result {
        Ok(()) => Ok(()),
        Err(code) => Err(JitterentropyError::InitFailed(*code)),
    }
}
```

**Why `OnceLock`?**

- Guarantees initialization happens exactly once
- Thread-safe without explicit locking
- All threads see the same result
- Better than atomics (no race window)

#### Thread-Local Collectors

Each thread gets its own entropy collector:

```rust
thread_local! {
    static THREAD_COLLECTOR: RefCell<Option<JitterentropyCollector>> =
        const { RefCell::new(None) };
}

impl JitterentropySource {
    fn with_collector<F, R>(&self, f: F) -> Result<R, JitterentropyError>
    where
        F: FnOnce(&mut JitterentropyCollector) -> Result<R, JitterentropyError>,
    {
        THREAD_COLLECTOR.with(|cell| {
            let mut collector_opt = cell.borrow_mut();

            if collector_opt.is_none() {
                *collector_opt = Some(JitterentropyCollector::new(self.config)?);
            }

            if let Some(ref mut collector) = *collector_opt {
                f(collector)
            } else {
                Err(JitterentropyError::NullCollector)
            }
        })
    }
}
```

**Why thread-local?**

- Jitterentropy collectors are not thread-safe
- Avoids lock contention
- Each thread manages its own collector lifecycle

#### Error Handling

Detailed error types for debugging:

```rust
pub enum JitterentropyError {
    InitFailed(c_int),      // Library init failed
    CollectorAllocFailed,   // Memory/timer issues
    NullCollector,          // Programming error
    RctFailed,              // Health test (temporary)
    AptFailed,              // Health test (temporary)
    TimerFailed,            // Timer issue
    LagFailed,              // Health test (temporary)
    RctPermanent,           // Health test (permanent)
    AptPermanent,           // Health test (permanent)
    LagPermanent,           // Health test (permanent)
    Unknown(isize),         // Unknown error
}

impl JitterentropyError {
    pub fn is_permanent(&self) -> bool {
        matches!(self,
            Self::RctPermanent | Self::AptPermanent | Self::LagPermanent)
    }

    pub fn is_health_test_failure(&self) -> bool {
        matches!(self,
            Self::RctFailed | Self::AptFailed | Self::LagFailed |
            Self::RctPermanent | Self::AptPermanent | Self::LagPermanent)
    }
}
```

### 4. FIPS Integration (`ossl/src/fips.rs`)

#### Global Entropy Source

```rust
static ENTROPY_SOURCE: LazyLock<RwLock<Box<dyn EntropySource>>> =
    LazyLock::new(|| RwLock::new(Box::new(GetrandomSource::new())));

pub fn set_entropy_source(source: Box<dyn EntropySource>) {
    if let Ok(mut guard) = ENTROPY_SOURCE.write() {
        *guard = source;
    }
}
```

**Why `LazyLock<RwLock<...>>`?**

- `LazyLock`: Lazy initialization, avoids startup cost if unused
- `RwLock`: Allows concurrent reads, exclusive writes
- `Box<dyn EntropySource>`: Type erasure for any entropy source

#### OpenSSL Callbacks

The FIPS provider calls these to get entropy:

```rust
unsafe extern "C" fn fips_get_entropy(
    _handle: *const OSSL_CORE_HANDLE,
    pout: *mut *mut c_uchar,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
) -> usize {
    // Allocate buffer
    let out = fips_malloc(len, null(), 0);

    // Get entropy from configured source
    let r = slice::from_raw_parts_mut(out as *mut u8, len);
    if get_entropy_internal(r).is_err() {
        fips_clear_free(out, len, null(), 0);
        return 0;
    }

    *pout = out as *mut u8;
    len
}
```

### 5. Build System (`ossl/build.rs`)

Jitterentropy is handled similarly to OpenSSL - it links differently depending on the build mode:

| Build Mode | Jitterentropy Handling |
|------------|----------------------|
| **Dynamic** | Links to system `libjitterentropy.so` |
| **FIPS** | Compiles from source, statically linked |

#### Dynamic Mode: System Library

```rust
#[cfg(feature = "jitterentropy")]
fn use_system_jitterentropy() {
    // Searches standard library paths for libjitterentropy.so
    // Requires jitterentropy-devel package to be installed
    println!("cargo:rustc-link-lib=jitterentropy");
    println!("cargo:rustc-link-lib=pthread");
}
```

**Requirements:**
- Install `jitterentropy-devel` package (Fedora/RHEL) or equivalent
- Provides `/usr/lib64/libjitterentropy.so` and `/usr/include/jitterentropy.h`

#### FIPS Mode: Compile from Source

```rust
#[cfg(feature = "jitterentropy")]
fn build_jitterentropy_from_source() {
    let jent_path = std::env::var("KRYOPTIC_JITTERENTROPY_SOURCES")
        .unwrap_or_else(|_| "../jitterentropy".into());

    let source_files = [
        "src/jitterentropy-base.c",
        "src/jitterentropy-gcd.c",
        "src/jitterentropy-health.c",
        "src/jitterentropy-noise.c",
        "src/jitterentropy-sha3.c",
        "src/jitterentropy-timer.c",
    ];

    let mut build = cc::Build::new();
    for src in &source_files {
        build.file(jent_path.join(src));
    }

    // CRITICAL: -O0 preserves timing jitter
    build.opt_level(0);
    build.flag("-O0");

    build.define("JENT_CONF_ENABLE_INTERNAL_TIMER", None);
    build.compile("jitterentropy");
}
```

**Critical: `-O0` optimization**

The jitterentropy library MUST be compiled with `-O0` (no optimization). Compiler optimizations can:

- Remove or reorder timing-sensitive operations
- Eliminate "useless" memory accesses that generate jitter
- Break the entropy collection mechanism

**Why static linking for FIPS?**

- Reproducible builds for certification
- Known, auditable source code
- No dependency on system package version

### 6. Cargo Configuration

#### `ossl/Cargo.toml`

```toml
[features]
jitterentropy = []  # Enable jitterentropy-based entropy source

[build-dependencies]
cc = "1.0"  # For compiling jitterentropy C code
```

#### Root `Cargo.toml`

```toml
[features]
jitterentropy = ["ossl/jitterentropy"]
```

## Testing

### Test Categories

| Category | Count | Purpose |
|----------|-------|---------|
| Unit tests | ~15 | Individual component testing |
| Integration tests | ~8 | Multi-component interaction |
| FIPS compliance tests | ~6 | SP800-90B validation |
| **Total** | **~29** | (in ossl crate with FIPS+jitterentropy) |

Note: Test counts vary based on features enabled. The FIPS build with jitterentropy runs the most tests.

### Running Tests

```bash
# All entropy tests (dynamic build)
cargo test -p ossl --features "dynamic,jitterentropy" entropy

# FIPS entropy tests
cargo test --no-default-features --features "standard,fips,jitterentropy" entropy_config

# Full test suite (dynamic)
cargo test --features "dynamic,jitterentropy"

# Full test suite (FIPS)
cargo test --no-default-features --features "standard,fips,jitterentropy"
```

### Key Test Functions

```rust
// Verify jitterentropy FIPS mode works
#[test]
fn test_jitterentropy_fips_compliance() {
    let source = JitterentropySource::try_new(JitterentropyConfig::fips())?;
    assert!(source.health_check().is_ok());
}

// Verify concurrent access works
#[test]
fn test_concurrent_entropy_generation() {
    // 10 threads, 100 iterations each
}
```

## Build Environment

### Containerfile

A Fedora-based container provides all build dependencies:

```dockerfile
FROM registry.fedoraproject.org/fedora:41

RUN dnf install -y \
    rust cargo rustfmt clippy \
    openssl-devel pkg-config \
    clang-devel clang llvm-devel \
    gcc make \
    sqlite-devel \
    # ... testing tools
    && dnf clean all

# Install nightly for edition2024 support
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain nightly
```

### Building

```bash
# Build container
podman build -t kryoptic-build -f Containerfile .

# Run build
podman run --rm -v $(pwd):/workspace:Z -w /workspace kryoptic-build \
    cargo build --features "dynamic,jitterentropy"

# Run tests
podman run --rm -v $(pwd):/workspace:Z -w /workspace kryoptic-build \
    cargo test --features "dynamic,jitterentropy"
```

## Common Development Tasks

### Adding a New Entropy Source

1. Implement `EntropySource` trait in `ossl/src/entropy/mod.rs` or a new file
2. Add to public exports
3. Add convenience function if appropriate
4. Add tests

```rust
pub struct MyEntropySource { /* ... */ }

impl EntropySource for MyEntropySource {
    fn name(&self) -> &'static str { "my-source" }

    fn get_entropy(&self, buf: &mut [u8]) -> Result<usize, Error> {
        // Implementation
    }
}
```

### Modifying Health Test Behavior

Health tests are handled by the jitterentropy library. To modify behavior:

1. Adjust `JitterentropyConfig` flags
2. Use `use_safe_api: true` for auto-recovery
3. Handle `JitterentropyError` variants appropriately

### Debugging Entropy Issues

```rust
// Check system capabilities
let caps = query_capabilities();
println!("{:?}", caps);

// Get detailed error information
match JitterentropySource::try_new_fips() {
    Ok(_) => println!("OK"),
    Err(e) => println!("Failed: {} (permanent: {})",
        e.description(), e.is_permanent()),
}

// Check kernel FIPS mode
let fips = std::fs::read_to_string("/proc/sys/crypto/fips_enabled")
    .map(|s| s.trim() == "1")
    .unwrap_or(false);
```

## Security Considerations

### Memory Handling

- Temporary buffers are zeroed with `crate::zeromem()`
- Uses OpenSSL's `OPENSSL_cleanse` for secure zeroing
- Collectors are properly freed on drop

### Thread Safety

- Global state protected by `RwLock`
- Initialization uses `OnceLock` (no races)
- Thread-local collectors avoid contention

### Error Handling

- Health test failures are not silently ignored
- Permanent failures require collector recreation
- Errors propagate to caller (no silent fallback)

## Performance Notes

### Initialization Cost

- `jent_entropy_init_ex`: ~10-100ms (runs health tests)
- Collector allocation: ~1ms
- Thread-local lookup: negligible

### Generation Cost

- Per-byte cost decreases with larger buffers
- 32 bytes: ~1-10ms depending on system
- Dominated by timing measurements, not computation

### Optimization Opportunities

1. **Pre-initialize at startup**: Call `ensure_initialized()` early
2. **Batch requests**: Prefer one 1024-byte request over 32 32-byte requests
3. **Async generation**: Generate entropy in background thread for latency-sensitive paths

## Future Improvements

Potential enhancements:

1. **Secure memory allocation**: Use mlock'd memory for collectors
2. **Runtime health monitoring**: Periodic health checks with metrics
3. **Entropy estimation**: Track estimated entropy bits
4. **HSM integration**: Additional entropy source from hardware

Note: Configuration file support for entropy source selection has been implemented via the `entropy_source` option in the TOML config file.

## References

- [Jitterentropy Library](https://github.com/smuellerDD/jitterentropy-library)
- [SP800-90B](https://csrc.nist.gov/publications/detail/sp/800-90b/final)
- [Rust FFI Guide](https://doc.rust-lang.org/nomicon/ffi.html)
- [OpenSSL Provider Interface](https://www.openssl.org/docs/man3.0/man7/provider.html)
