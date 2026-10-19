# libssig (WIP)

A small C library for digital signing using PKCS#11 through `p11-kit`.

## Bindings (TBD)

- Python: [tavocg/pyssig](https://github.com/tavocg/pyssig)
- Go: [tavocg/go-ssig](https://github.com/tavocg/go-ssig)

## Public interface

- `libssig_version`
- `libssig_list_tokens`
- `libssig_tokens_free`
- `libssig_list_certificates`
- `libssig_certificates_free`

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
