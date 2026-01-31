# Jitterentropy: CPU Timing Jitter Entropy Source

## Overview

Jitterentropy is a hardware random number generator (RNG) that collects entropy from CPU execution timing variations. It is designed to be SP800-90B compliant, making it suitable for use in FIPS 140-3 validated cryptographic modules.

This document explains how jitterentropy works, why it's needed for FIPS certification, and how to use it in Kryoptic.

## Why Jitterentropy?

### The FIPS Entropy Problem

FIPS 140-3 requires that cryptographic modules use entropy sources that meet SP800-90B requirements. On Linux systems, the typical entropy source is the kernel's `getrandom()` syscall, which draws from `/dev/urandom`. However:

1. **Kernel FIPS Mode Required**: `getrandom()` is only considered FIPS-approved when the Linux kernel is booted in FIPS mode (`fips=1` kernel parameter)
2. **Not Always Available**: Many systems don't run in kernel FIPS mode
3. **Certification Complexity**: Certifying the kernel's entropy source requires additional testing

### Jitterentropy Solution

Jitterentropy provides a **user-space entropy source** that:

- Is **SP800-90B compliant** with proper configuration
- Works on **any system** with a high-resolution timer
- Is **independently certifiable** without kernel modifications
- Provides **defense in depth** when combined with other sources

## Build Modes

Jitterentropy is handled similarly to OpenSSL - it links differently depending on the build mode:

| Build Mode | Jitterentropy Source | Linking |
|------------|---------------------|---------|
| **Dynamic** | System package | Dynamic (`libjitterentropy.so`) |
| **FIPS** | Compiled from source | Static (`libjitterentropy.a`) |

### Dynamic Mode (Development)

```bash
# Requires jitterentropy-devel package
dnf install jitterentropy-devel   # Fedora/RHEL

cargo build --features "dynamic,jitterentropy"
```

Uses the system-installed jitterentropy library. Quick builds, but the system package version may differ from certified versions.

### FIPS Mode (Certification)

```bash
# Requires OpenSSL and jitterentropy source code
export KRYOPTIC_OPENSSL_SOURCES=/path/to/openssl
export KRYOPTIC_JITTERENTROPY_SOURCES=/path/to/jitterentropy-library

cargo build --no-default-features --features "standard,fips,jitterentropy"
```

Compiles jitterentropy from source with `-O0` optimization (critical for entropy quality). Required for FIPS certification to ensure reproducible, auditable builds.

**Note:** Both environment variables are required for FIPS builds with jitterentropy. This is consistent with how OpenSSL sources are handled.

## How Jitterentropy Works

### The Principle: CPU Timing Jitter

Modern CPUs exhibit non-deterministic execution timing due to:

1. **Cache Effects**: Cache hits vs. misses cause timing variations
2. **Branch Prediction**: Mispredicted branches add cycles
3. **Pipeline Stalls**: Memory access patterns affect pipeline efficiency
4. **Interrupt Handling**: Asynchronous interrupts cause jitter
5. **Power Management**: Frequency scaling affects timing
6. **Multi-core Interference**: Other cores competing for resources

These variations are:
- **Unpredictable**: Cannot be predicted even with full knowledge of the system
- **Physical**: Rooted in physical properties of silicon
- **Measurable**: Can be captured with high-resolution timers

### Entropy Collection Process

```
┌─────────────────────────────────────────────────────────────────┐
│                    Entropy Collection Loop                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Read high-resolution timer (T1)                             │
│                 ↓                                                │
│  2. Execute CPU-intensive operations:                           │
│     - Memory access patterns                                     │
│     - Arithmetic operations                                      │
│     - Loop iterations                                            │
│                 ↓                                                │
│  3. Read high-resolution timer (T2)                             │
│                 ↓                                                │
│  4. Calculate delta: Δ = T2 - T1                                │
│                 ↓                                                │
│  5. Extract entropy from timing variations                       │
│                 ↓                                                │
│  6. Accumulate in entropy pool                                   │
│                 ↓                                                │
│  7. Apply health tests (RCT, APT)                               │
│                 ↓                                                │
│  8. Condition with SHA-3 hash                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

#### 1. Noise Source

The noise source measures CPU execution time variations:

```c
// Simplified concept
uint64_t measure_jitter() {
    uint64_t t1 = read_timestamp();
    
    // Execute operations that cause timing jitter
    memory_access_pattern();
    cpu_intensive_loop();
    
    uint64_t t2 = read_timestamp();
    return t2 - t1;  // This delta contains entropy
}
```

#### 2. Health Tests

SP800-90B requires continuous health testing:

| Test | Purpose | Detection |
|------|---------|-----------|
| **RCT** (Repetition Count Test) | Detects stuck values | Fails if same value repeats too many times |
| **APT** (Adaptive Proportion Test) | Detects bias | Fails if one value appears too frequently |
| **Lag Predictor** | Detects patterns | Fails if output is predictable |

#### 3. Conditioning

Raw timing values are conditioned using SHA-3 to:
- Distribute entropy evenly across output bits
- Remove any statistical bias
- Produce uniform random output

### Oversampling Rate (OSR)

The oversampling rate controls how many timing measurements are combined for each output bit:

| OSR | Entropy Quality | Speed | Use Case |
|-----|-----------------|-------|----------|
| 1 | Standard | Fastest | General use with FIPS |
| 3 | Higher | Slower | High-security applications |
| 0 | Library default | Varies | Let library decide |

Higher OSR = More timing measurements = More entropy per bit = Slower generation

## FIPS Configuration

### SP800-90B Compliance

To achieve SP800-90B compliance, jitterentropy must be configured with:

```rust
use ossl::entropy::jitterentropy::{JitterentropyConfig, JitterentropySource};

// FIPS-compliant configuration
let config = JitterentropyConfig {
    osr: 1,              // Minimum oversampling
    fips_mode: true,     // Enable SP800-90B compliance
    use_safe_api: false, // Don't auto-recover from health failures
};

let source = JitterentropySource::new(config)?;
```

The `JENT_FORCE_FIPS` flag enables:
- Full SP800-90B health testing
- Stricter entropy estimation
- Failure on health test violations (no auto-recovery)

### Health Test Behavior

In FIPS mode, health test failures are **fatal**:

| Failure Type | Behavior | Recovery |
|--------------|----------|----------|
| RCT Temporary | Operation fails | Retry may succeed |
| APT Temporary | Operation fails | Retry may succeed |
| RCT Permanent | Collector invalid | Must recreate collector |
| APT Permanent | Collector invalid | Must recreate collector |

This is intentional - FIPS requires that compromised entropy sources stop producing output rather than potentially providing low-quality randomness.

## Integration with Kryoptic

### Entropy Source Abstraction

Kryoptic provides a pluggable entropy architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                      PKCS#11 API                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FIPS Provider                                 │
│              set_entropy_source(source)                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   EntropySource Trait                            │
│  - get_entropy(&mut [u8]) -> Result<usize>                      │
│  - get_nonce(&mut [u8], salt) -> Result<usize>                  │
│  - health_check() -> Result<()>                                  │
└─────────────────────────────────────────────────────────────────┘
          │                                       │
          ▼                                       ▼
┌─────────────────┐                   ┌──────────────────┐
│ GetrandomSource │                   │JitterentropySource│
│  (OS entropy)   │                   │  (CPU jitter)     │
└─────────────────┘                   └──────────────────┘
```

### Configuration Options

#### Option 1: Auto (Recommended)

Automatically selects the appropriate FIPS-compliant entropy source:
- **Kernel FIPS mode enabled**: Uses `getrandom` (kernel provides FIPS entropy)
- **Kernel FIPS mode disabled**: Uses `jitterentropy` (SP800-90B compliant)

```rust
use ossl::fips::use_fips_compliant_entropy;

let source_name = use_fips_compliant_entropy()?;
println!("Using entropy source: {}", source_name);
```

#### Option 2: Jitterentropy Only

For explicit FIPS compliance on any system:

```rust
use ossl::entropy::create_fips_entropy;
use ossl::fips::set_entropy_source;

let source = create_fips_entropy()?;
set_entropy_source(source);
```

#### Option 3: Getrandom Only

Use the kernel's entropy source (only FIPS-compliant on FIPS kernels):

```rust
use ossl::fips::use_getrandom_entropy;

use_getrandom_entropy();
```

### Configuration File

Kryoptic can be configured to use a specific entropy source via the TOML configuration file:

```toml
# Entropy source configuration (FIPS builds only)
# Options: "auto", "getrandom", "jitterentropy"
entropy_source = "auto"

[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "/var/lib/kryoptic/token.sql"
```

**Entropy Source Options:**

| Value | Description |
|-------|-------------|
| `auto` | (Default) Detects kernel FIPS mode: uses `getrandom` if FIPS enabled, otherwise `jitterentropy` |
| `getrandom` | Use only the kernel's `getrandom()` syscall |
| `jitterentropy` | Use only jitterentropy (requires `jitterentropy` feature) |

### Checking System Capabilities

```rust
use ossl::entropy::query_capabilities;

let caps = query_capabilities();
println!("Jitterentropy available: {}", caps.jitterentropy_available);
if let Some(ver) = caps.jitterentropy_version {
    println!("Version: {}", ver);
}
```

## Performance Considerations

### Timing Characteristics

| Operation | Typical Time | Notes |
|-----------|--------------|-------|
| Initialization | 10-100ms | Health tests run at startup |
| 32-byte generation | 1-10ms | Depends on CPU and OSR |
| Health check | <1ms | Small entropy generation |

### Optimization Tips

1. **Reuse collectors**: Thread-local collectors avoid repeated initialization
2. **Batch requests**: Request larger buffers rather than many small ones
3. **Pre-seed at startup**: Generate initial entropy during application startup
4. **Use appropriate OSR**: OSR=1 is sufficient for most FIPS use cases

### Thread Safety

The `JitterentropySource` uses thread-local storage for collectors:

- Each thread gets its own entropy collector
- No lock contention between threads
- Safe to use from multiple threads concurrently

## Troubleshooting

### Common Issues

#### "Timer service not available"

The system lacks a high-resolution timer. Solutions:
- Ensure `clock_gettime(CLOCK_MONOTONIC)` is available
- Check that the system supports high-resolution timers
- On VMs, ensure timer virtualization is enabled

#### "Timer too coarse for RNG"

The timer resolution is insufficient. This can happen on:
- Older systems
- Some virtualized environments
- Systems with aggressive power management

#### "Health test failed"

The entropy source failed SP800-90B health tests:
- May indicate a hardware/timing issue
- Retry the operation
- If persistent, the system may not be suitable for jitterentropy

### Verifying Jitterentropy Works

```rust
use ossl::entropy::jitterentropy::{JitterentropySource, version};

// Check version
println!("Jitterentropy version: {}", version());

// Try to create a source
match JitterentropySource::try_new_fips() {
    Ok(source) => {
        println!("Jitterentropy available");
        
        // Test entropy generation
        let mut buf = [0u8; 32];
        match source.get_entropy(&mut buf) {
            Ok(_) => println!("Entropy generation works"),
            Err(e) => println!("Entropy generation failed: {:?}", e),
        }
    }
    Err(e) => {
        println!("Jitterentropy not available: {}", e.description());
    }
}
```

## Security Considerations

### Entropy Quality

Jitterentropy's entropy quality depends on:

1. **Timer Resolution**: Higher resolution = better entropy
2. **CPU Complexity**: Modern CPUs with caches/pipelines = more jitter
3. **System Load**: Some load can increase jitter (but too much can cause issues)
4. **Virtualization**: VMs may have reduced jitter quality

### Attack Resistance

Jitterentropy is designed to resist:

- **Timing attacks**: Measurements are internal, not exposed
- **Prediction attacks**: Physical randomness cannot be predicted
- **Replay attacks**: Each measurement is unique

### Recommendations

1. **Use FIPS mode** for cryptographic applications
2. **Monitor health tests** in production
3. **Use `auto` mode** for portable FIPS compliance
4. **Test on target hardware** before deployment

## References

- [Jitterentropy Library](https://github.com/smuellerDD/jitterentropy-library)
- [Jitterentropy Documentation](http://www.chronox.de/jent.html)
- [SP800-90B: Recommendation for Entropy Sources](https://csrc.nist.gov/publications/detail/sp/800-90b/final)
- [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [CPU Time Jitter Based Non-Physical True Random Number Generator](http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html)
