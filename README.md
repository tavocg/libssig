# libssig

Simple digital signature library.

## Usage

- `libssig_version`
- `libssig_tokens`
- `libssig_sign`
- `libssig_verify`

## Build

Requires CMake 3.16 or newer, a C99 compiler, `pkg-config`, and the development
packages for `p11-kit-1` and OpenSSL (`libcrypto`).

```sh
cmake -S . -B build
cmake --build build
```

Run tests:

```sh
cd build && ctest
```

Build release and install:

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build-release
cmake --install build-release --prefix "$HOME/.local"
```
