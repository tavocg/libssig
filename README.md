# libssig

C library for digital signing using PKCS#11 through `p11-kit`.

## Public interface

- `libssig_context_open`
- `libssig_context_close`
- `libssig_version`
- `libssig_tokens`
- `libssig_tokens_free`
- `libssig_certificates`
- `libssig_certificates_free`
- `libssig_sign`
- `libssig_extend`
- `libssig_signature_free`
- `libssig_verify`
- `libssig_verify_free`
- `libssig_timestamp_request`
- `libssig_timestamp`
- `libssig_ocsp_request`
- `libssig_ocsp_request_free`
- `libssig_ocsp_verify`

Get the loaded library version (each output pointer may be `NULL`):

```c
int major, minor, patch;
libssig_version(&major, &minor, &patch);
```

Token hardware and firmware versions use `libssig_token_version`, which has
`major` and `minor` components.

Token queries default to hardware slots when options is `0`:

```c
libssig_tokens(&ctx, &tokens, 0);                  /* Hardware only. */
libssig_tokens(&ctx, &tokens, LIBSSIG_TOKENS_ALL); /* All present tokens. */
```

Certificate queries default to certificates declaring `contentCommitment`:

```c
libssig_certificates(&ctx, &token, &certs, 0);
/* Free certs before another query. */
libssig_certificates_free(&certs);
libssig_certificates(&ctx, &token, &certs, LIBSSIG_CERTIFICATES_ALL);
```

Results include Key Usage, numeric EKU OIDs and certificate policy OIDs. This is
metadata extraction, not trust validation or a check of the private key's
`CKA_SIGN` capability. All metadata is freed by `libssig_certificates_free()`.

`libssig_sign()` generates CAdES, PAdES, XAdES or JAdES at B-B, B-T, B-LT and B-LTA levels.
Its zero-initialized defaults are CAdES B-LTA, RSA PKCS#1 v1.5 and SHA-256;
LTA requires application-provided transport services. No silent downgrade is
performed. Use `LIBSSIG_LEVEL_B_B` for offline signing, and
`LIBSSIG_SIGN_DETACHED` for CAdES with external content.
See [baseline profiles](doc/profiles.md) and [standards and MICITT v4](doc/conformance.md).
See [the signing API example](doc/signing.md) for parameters and ownership.

`libssig_verify()` checks CMS/CAdES, PDF, XML XAdES and JSON JAdES signatures without a token. Optional
`LIBSSIG_VERIFY_SYSTEM_TRUST` or custom roots in `ca_data` also require trusted
certificate chains. Additional intermediates can be supplied separately.
See [the verification API](doc/verification.md).

RFC 3161 timestamping generates a request and incorporates a validated TSA
response into an existing CAdES signature. Verification also checks stored
signature timestamps, with independently configured TSA trust. The application
handles transport.
See [timestamping](doc/timestamping.md).

OCSP APIs extract responder URLs, generate requests and validate responses.
Verification accepts separate OCSP evidence for document and TSA certificates.
See [OCSP](doc/ocsp.md).

## Source layout

Features with multiple implementation files live in `libssig/<feature>/`,
with their interface in `<feature>.h` and private helpers beside it. Features
that only need a `.c`/`.h` pair, such as context and tokens, live directly in
`libssig/`, alongside shared implementation and versioning. `libssig/libssig.h`
includes every public interface. Only public headers are installed.

## Build

Requires CMake 3.16 or newer, a C99 compiler, `pkg-config`, and the development
packages for `p11-kit-1`, OpenSSL 3.0 or newer (`libcrypto`), `libmagic` (with its magic database), QPDF >= 11, Jansson, and libxml2.

```sh
cmake -S . -B build -DBUILD_TESTING=OFF
cmake --build build
```

Run tests (Python dependencies are included in `nix develop`; otherwise see
[tests/README.md](tests/README.md)):

```sh
git submodule update --init --recursive
ctest --test-dir build --output-on-failure
```

Conformance checks are enabled by default. `-DLIBSSIG_TEST_CONFORMANCE=OFF`
selects a minimal C-only test build; `-DBUILD_TESTING=OFF` builds only the library.

Build release and install:

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build-release
cmake --install build-release --prefix "$HOME/.local"
```

## License

Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>.

Licensed under the GNU General Public License, version 3 or any later version
(SPDX: `GPL-3.0-or-later`). See [LICENSE](LICENSE) for the full terms.
This software is provided without any warranty.
