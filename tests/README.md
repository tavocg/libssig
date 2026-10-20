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

# Detached CAdES B-B file signing

Sign a file using the same token, ID, algorithm and hash choices:

```sh
./build/tests/sign-file 'pkcs11:token=...;serial=...' 01 input.pdf output.p7s
./build/tests/sign-file 'pkcs11:token=...;serial=...' 01 input.pdf output.p7s rsa-pss sha384
```

The output is binary DER CAdES B-B (CMS SignedData) with the signing certificate embedded;
the original file stays separate. Existing output files are never overwritten.
The tool verifies the signature before creating the output. It reads files into
memory and accepts inputs up to `INT_MAX` bytes. It uses the public
`libssig_sign()` API and requires an interactive token when authentication is needed.

Verify independently:

```sh
openssl cms -verify -binary -inform DER -in output.p7s \
  -content input.pdf -noverify -out verified.pdf
```

`-noverify` skips certificate trust validation; the content signature and signed
attributes are still checked. Changing the input must make verification fail.
For an independent ESS certificate-binding check, use OpenSSL's CAdES mode with
your trusted CA certificates and any intermediates:

```sh
openssl cms -verify -cades -binary -inform DER -in output.p7s \
  -content input.pdf -CAfile trusted-ca.pem -certfile intermediate-ca.pem \
  -out verified.pdf
```

CAdES output includes `contentType`, `messageDigest`, `signingTime`,
`signingCertificateV2`, and the MIME type. The internal caller can set
`params.mime_type`; when omitted, the library and manual tool detect it from
the content using libmagic. The magic database must be installed. An explicit
MIME value bypasses detection. The certificate hash omits issuer/serial in its ESS
identifier. The token signs canonical DER signed attributes; the document bytes
are bound through `messageDigest`.

`signingTime` is the local claimed time, not a trusted TSA timestamp. There is no
timestamping, chain download, revocation checking or long-term validation data.
It does not embed a signature inside a PDF. OpenSSL's `-cades` checks the ESS
binding; it is not a complete ETSI baseline-profile validator. The implementation
follows the mandatory B-B attributes and MIME recommendation in
[ETSI EN 319 122-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf),
clauses 5 and 6.3. The basic CMS function remains available internally.
