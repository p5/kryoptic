This is a pkcs11 soft token written in rust.

# Dependencies

 * rustc
 * openssl dependencies
 * sqlite

Note, the default feature links against the system installed OpenSSL
libraries, you need the OpenSSL development packages to build with
the default features selection.

# Crates

To make it easier to deal with some of the tools and bindings kryoptic has
been changed from a monolithic crate to a workspace that holds multiple
packages. Specifically the main output artifact, the cdylib named
libkryoptic_pkcs11.so has been moved to the kryoptic_pkcs11 package in the
cdylib directory.

# Setup

Kryoptic normally builds and dynamically links against a system version
of OpenSSL; alternatively the build system can be pointed to OpenSSL
sources to generate a build with the crypto library statically linked
into the binaries.

For builds that need to include a static build of OpenSSL, download and
unpack the desired version and set the env var KRYOPTIC_OPENSSL_SOURCES
to the path where the source were unpacked.

Example:

    export KRYOPTIC_OPENSSL_SOURCES=/path/to/src/openssl

When building, you'll need to disable the dynamic feature.  Since
features are additive in `Cargo`, you'll need to disable the default
features and then select the features that you need.  For instance, if
you want the standard features, you can do:

    cargo build --no-default-features --features standard

# Build

Build the rust project:

    $ CONFDIR=/etc cargo build

The default build specifies "standard" as the default feature for
ease of use. "Standard" pulls in all the standard algorithms and the
sqlitedb storage backend.

In order to make a different selection you need to use the cargo
switch to disable default features (`--no-default-features`) and then
specify the features you want to build with, eg:

    $ cargo build --no-default-features --features fips,sqlitedb,nssdb

Note that you can set `OSSL_BINDGEN_CLANG_ARGS` (whitespace delimited)
to pass additional arguments into bindgen, in case that is important
for your build.

# FIPS Builds

The `--feature fips` builds create a token linking just to OpenSSL libfips.a
and enable FIPS behavior, restricting how algorithms behave and reporting
FIPS indicators for (non)approved algorithms and operations. It forces the
presence of the PKCS#11 3.2 interfaces as well as the PQC algorithms.
The `fips` build uses the kernel entropy source.

The `fips-jitterentropy` feature implies `fips` and links to a prebuilt JENT
shared library. Cargo does not compile JENT. Set
`KRYOPTIC_JITTERENTROPY_LIB_DIR` to the directory with the JENT shared library.
Set `KRYOPTIC_JITTERENTROPY_INCLUDE_DIR` to the directory with
`jitterentropy.h`. It defaults to the library directory. The build generates
Rust bindings from that header and links `libjitterentropy.so`.
Use a JENT header and library pair with a compatible ABI. Before distribution,
confirm that the exact package and operating environment meet the applicable
ESV requirements.

The adapter uses the public API in JENT v3.7.0. Initialization runs JENT's
startup tests. Collector allocation repeats them when needed. Each entropy read
uses `jent_read_entropy_safe()`, which checks runtime health and can replace a
collector after a health failure. Kryoptic checks the reported FIPS mode,
secure-memory support, and timer settings. These API checks do not establish
entropy credit or ESV approval. JENT v3.7.0 uses XDRBG-256, so the lab must
classify that output path and assess the exact library build and operating
environment. Kryoptic does not pin the JENT package digest or source revision.
The tests use the released v3.7.0 API as a compatibility fixture.

The JENT build sets `JENT_FORCE_FIPS`, which requires secure memory. Set
`RLIMIT_MEMLOCK` high enough for the maximum number of threads that request
entropy. Kryoptic creates one JENT collector for each such thread. More threads
need more locked memory, and the exact amount depends on JENT's configuration.
If JENT cannot lock enough memory, the first random request fails and sets the
FIPS provider's error state. Check the process limit with `ulimit -l`. For a
systemd service, set `LimitMEMLOCK` and test the limit with the maximum thread
count.

Set `KRYOPTIC_OPENSSL_SOURCES` to the OpenSSL source tree selected for the
FIPS build. The source tree must support `no-fips-jitter`. Kryoptic disables
OpenSSL's separate JENT source. Install the selected JENT library in the runtime
loader path. Build Kryoptic with:

```sh
cargo build -p kryoptic --no-default-features --features fips-jitterentropy
```

The feature selects JENT at build time. It adds a required JENT SONAME
dependency from the package. A missing library prevents module loading.
The build has no runtime source selector. A JENT failure stops random output.
The build does not fall back to kernel entropy.

Other FIPS behavior, including PKCS#11 validation metadata, remains controlled
by `fips`. Do not claim FIPS validation before CMVP issues the certificate.

The FIPS build allows to specify the name, version, and additional build
information returned by the embedded OpenSSL FIPS provider by setting the
following environment variables (requires custom patches to the OpenSSL
code base to take effect):
- KRYOPTIC_FIPS_VENDOR
- KRYOPTIC_FIPS_VERSION
- KRYOPTIC_FIPS_BUILD

If these variables are not set build defaults respectively to:
- CARGO_PKG_NAME
- CARGO_PKG_VERSION
- "test"

For the FIPS build, you need to generate the hmac checksum:

    $ ./misc/hmacify.sh target/release/libkryoptic_pkcs11.so

Without this step the token will panic at initialization.

# Tests

To run the tests, run the test command:

    $ cargo test

This command accepts the same feature set as the build command

# License

The license is currently set as the Apache Software License 2.0 the same license
OpenSSL uses.

In versions prior than and including 1.5.2 the license for the token code was 
the GPLv3.0+ as released by the FSF, we changed it to make the project more
easily reusable across a wider set of Open Source communities.

# Contributions

Contributions to the project are made under the project's [License](LICENSE.txt)
unless otherwise explicitly indicated by the contributor at the time of the
contribution.

See also the [default agreement](https://developercertificate.org/), which we assume
for contribution, and which is currently enforced by the github DCO check.
