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
- `libssig_sign`
- `libssig_signature_free`
- `libssig_verify`
- `libssig_verify_free`

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

`libssig_sign()` returns CMS or CAdES B-B signatures in memory, with embedded
content by default. Use `LIBSSIG_SIGN_DETACHED` for a separate signature.
Its zero-initialized defaults are CAdES, RSA PKCS#1 v1.5 and SHA-256.
See [the signing API example](doc/signing.md) for parameters and ownership.

`libssig_verify()` checks CMS/CAdES signatures without a token. Optional
`LIBSSIG_VERIFY_SYSTEM_TRUST` also requires trusted certificate chains.
See [the verification API](doc/verification.md).

## Build

Requires CMake 3.16 or newer, a C99 compiler, `pkg-config`, and the development
packages for `p11-kit-1`, OpenSSL 3.0 or newer (`libcrypto`), and `libmagic`
(with its magic database).

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
