# Manual token checks

Build with testing enabled (the default):

```sh
cmake -S . -B build
cmake --build build
```

List token URIs and signing certificates, including each certificate's `id_hex`:

```sh
./build/tests/list-tokens
./build/tests/list-tokens --all-certificates
```

By default only certificates with parsed Key Usage `contentCommitment` are
shown. `--all-certificates` also includes authentication certificates and
certificates with unknown, absent or invalid metadata. JSON includes Key Usage
and its names, EKU OIDs, policy OIDs, and `metadata_status`. `valid` means the
metadata was decoded, not that the certificate is trusted or currently valid.
Absent extensions are `null`; present OID lists are arrays. Listing does not
request a PIN or inspect private-key `CKA_SIGN` attributes. Signing still checks
the selected private key's capabilities.

Sign a fixed test message and verify the signature with the selected certificate:

```sh
./build/tests/sign-token 'pkcs11:token=...;serial=...' 01
./build/tests/sign-token 'pkcs11:token=...;serial=...' 01 rsa-pss sha384
./build/tests/sign-token 'pkcs11:token=...;serial=...' 02 ecdsa sha256
```

The second argument is the certificate's binary `CKA_ID` in hexadecimal, without
separators (`00ff01`, for example). Leading zeros are significant. A unique,
readable X.509 certificate must match that ID. Certificate listing currently
runs without login, so this tool requires the certificate to be visible before
authentication.

Defaults are `rsa-pkcs` and `sha256`. Algorithms are `rsa-pkcs`, `rsa-pss`, and
`ecdsa`; hashes are `sha256`, `sha384`, and `sha512`. Names are case insensitive.
The key type and token's supported mechanisms must match the requested algorithm.

The tool reads the PIN interactively without echo when login is required, or
uses the device's protected authentication path. It does not accept a PIN on the
command line. Exit status is zero only when signing and verification succeed.
Verification checks signature correspondence, not certificate trust or validity.
No signature file is written. This check is excluded from `ctest` because it
requires a real token and may require user interaction.

Check authentication alone:

```sh
./build/tests/login-token 'pkcs11:token=...;serial=...'
```

# Detached CMS file signing

Sign a file using the same token, ID, algorithm and hash choices:

```sh
./build/tests/sign-file 'pkcs11:token=...;serial=...' 01 input.pdf output.p7s
./build/tests/sign-file 'pkcs11:token=...;serial=...' 01 input.pdf output.p7s rsa-pss sha384
```

The output is binary DER CMS SignedData with the signing certificate embedded;
the original file stays separate. Existing output files are never overwritten.
The tool verifies the signature before creating the output. It reads files into
memory and accepts inputs up to `INT_MAX` bytes. Like `sign-token`, it uses the
internal API and requires an interactive token when authentication is needed.

Verify independently:

```sh
openssl cms -verify -binary -inform DER -in output.p7s \
  -content input.pdf -noverify -out verified.pdf
```

`-noverify` skips certificate trust validation; the content signature is still
checked. Changing the input must make verification fail. This is basic detached
CMS without signed attributes, timestamps, or a CAdES conformance claim. It does
not embed a signature inside the PDF.
