# libssig (WIP)

A small C library for digital signing using PKCS#11 through `p11-kit`.

## Bindings (TBD)

- Python: [tavocg/pyssig](https://github.com/tavocg/pyssig)
- Go: [tavocg/go-ssig](https://github.com/tavocg/go-ssig)

## Public interface

- `libssig_context_open`
- `libssig_context_close`
- `libssig_version`
- `libssig_tokens`
- `libssig_tokens_free`
- `libssig_certificates`
- `libssig_certificates_free`

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

## Internal signing milestone

The internal API in `libssig/internal.h` now supports RSA PKCS#1 v1.5 with
SHA-256. `libssig_rsa_sha256_sign()` reuses an open context, opens a session,
authenticates, and selects a unique private key by the certificate's binary
`CKA_ID`. It requires an RSA key with `CKA_SIGN` and the provider mechanism
`CKM_SHA256_RSA_PKCS`. Keys requiring per-operation authentication are supported.
The input is the original data, not a precomputed digest.

The result is a raw RSA signature owned by `libssig_signature` and released with
`libssig_signature_free()`. Sessions are closed on success and failure, and
failed operations return an empty signature with the PKCS#11 error when present.
These functions are internal; a public `libssig_sign()` and CMS/CAdES packaging
remain to be implemented. Matching IDs alone do not prove that a certificate
contains the corresponding public key.

The signing test uses a simulated PKCS#11 module backed by an OpenSSL RSA key
and verifies the signature with the public key extracted from an X.509 test
certificate. Hardware integration has not been exercised by that test.

## Build

Requires CMake 3.16 or newer, a C99 compiler, `pkg-config`, and the development
packages for `p11-kit-1` and OpenSSL (`libcrypto`).

```sh
cmake -S . -B build
cmake --build build
```

Run tests:

```sh
ctest --test-dir build --output-on-failure
```

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
