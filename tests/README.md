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

# CAdES B-B file signing

Sign a file using the same token, ID, algorithm and hash choices:

```sh
./build/tests/sign-file 'pkcs11:token=...;serial=...' 01 input.pdf output.p7m
./build/tests/sign-file 'pkcs11:token=...;serial=...' 01 input.pdf output.p7m rsa-pss sha384
```

The output is binary DER CAdES B-B (CMS SignedData) with the signing certificate embedded;
the original content is included by default. Existing output files are never overwritten.
The tool verifies the signature before creating the output. It reads files into
memory and accepts inputs up to `INT_MAX` bytes. It uses the public
`libssig_sign()` API and requires an interactive token when authentication is needed.

Verify independently:

```sh
openssl cms -verify -binary -inform DER -in output.p7m \
  -noverify -out verified.pdf
```

`-noverify` skips certificate trust validation; the content signature and signed
attributes are still checked. For detached signatures, changing the external input must make verification fail.
For an independent ESS certificate-binding check, use OpenSSL's CAdES mode with
your trusted CA certificates and any intermediates:

```sh
openssl cms -verify -cades -binary -inform DER -in output.p7m \
  -CAfile trusted-ca.pem -certfile intermediate-ca.pem \
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

## Attached signing and verification

`sign-file` includes the original content by default. Add `--detached` as the
last argument to generate a separate signature:

```sh
./build/tests/sign-file \
  'pkcs11:model=PKCS%2315%20emulated;manufacturer=NXP;serial=d3b89a00f4675e4e;token=Bit4id%20JCOP3' \
  4c6c61766544654669726d61 \
  prueba-mime.txt prueba-attached.p7m

./build/tests/sign-file \
  'pkcs11:model=PKCS%2315%20emulated;manufacturer=NXP;serial=d3b89a00f4675e4e;token=Bit4id%20JCOP3' \
  4c6c61766544654669726d61 \
  prueba-mime.txt prueba-mime.p7s --detached

./build/tests/verify-file prueba-attached.p7m
./build/tests/verify-file prueba-mime.p7s prueba-mime.txt
./build/tests/verify-file --system-trust prueba-mime.p7s prueba-mime.txt
```

Algorithm/hash arguments, if provided, precede `--detached`. The output path
must not exist. Verification requires no token or PIN. Without `--system-trust`,
a successful check establishes signature/content integrity only. With that flag,
all signers must also chain to OpenSSL's configured default trust store; a trust
failure preserves the cryptographic result and reports numeric X.509 errors.
No OCSP/CRL or network access is performed. See [verification](../doc/verification.md).

Automated coverage includes all nine algorithm/hash combinations in CMS/CAdES,
attached and detached, independent OpenSSL verification, altered content and
signatures, incorrect ESS certificate hashes, missing content/certificates,
truncated/trailing input, empty content, multiple signers, untrusted signers,
and a controlled default trust store containing a valid or expired signer.

## Custom certificate authorities

`--ca-file` activates trust checking with the supplied roots; `--intermediates`
provides untrusted certificates for chain construction. Files may contain one
or more PEM `CERTIFICATE` blocks (whitespace between blocks), or one DER
certificate. The signer certificate must be embedded in the CMS/CAdES container.

```sh
./build/tests/verify-file \
  --ca-file raices.pem \
  --intermediates intermediarios.pem \
  documento.p7m

# Add the system store to the custom authorities.
./build/tests/verify-file \
  --system-trust \
  --ca-file raices.pem \
  --intermediates intermediarios.pem \
  documento.p7m
```

Options precede file paths; append the original document for detached signatures.
`--intermediates` requires `--ca-file` or `--system-trust`. Missing files, empty
bundles, malformed certificates, and unknown or duplicated file options fail.
Without `--system-trust`, custom authorities are the only trusted certificates.
Neither external nor embedded intermediates become trusted authorities.

`verify_trust` generates a root/intermediate/signer chain and tests missing or
untrusted issuers, PEM and DER, duplicate/malformed bundles, and custom/system
store combinations. `verify_cli` checks command parsing, failure exit codes,
and compares the custom chain with independent OpenSSL verification.

## RFC 3161 signature timestamping

```sh
ctest --test-dir build -R '^timestamp$' --output-on-failure
```

The test creates a local TSA and timestamps all nine original algorithm/hash
combinations in attached and detached CAdES. It checks nonce, policy, imprint,
TSA signature/purpose/trust, future times, malformed/rejected responses and
existing timestamps. OpenSSL independently checks the response against its
request and verifies that the resulting container preserves the document.
No token, PIN, network, or external TSA is used. See
[timestamping](../doc/timestamping.md) for the application-side transport example.

## Verifying stored timestamps

No original `.tsq` request or `.tsr` response is needed:

```sh
./build/tests/verify-file \
  --require-timestamp \
  --tsa-ca-file tsa-raices.pem \
  --tsa-intermediates tsa-intermediarios.pem \
  documento.p7m

# Use the configured system store for TSA trust.
./build/tests/verify-file --tsa-system-trust --require-timestamp documento.p7m
```

Document trust (`--ca-file`, `--intermediates`, `--system-trust`) and TSA trust
are independent. Omit `--require-timestamp` to accept unsigned-by-TSA documents;
present stamps are still checked. The command shows the document signature,
timestamp validity, timestamp UTC time, and TSA chain result separately.

The `timestamp` test now also verifies persisted tokens, including all nine
original algorithm/hash combinations, attached/detached documents, transplanted
or tampered tokens, malformed/duplicate attributes, missing stamps, expired TSA
certificates, and multiple signers with mixed timestamp presence. CLI checks use
only saved containers and separate document/TSA authorities.

## OCSP without network access

```sh
./build/tests/ocsp-file request cert.pem issuer.pem request.der
./build/tests/ocsp-file verify \
  cert.pem issuer.pem request.der response.der roots.pem intermediates.pem
```

`request` prints HTTP(S) URLs from AIA and creates a new DER request without
replacing existing files. The application sends it and supplies the returned
DER response. `verify` distinguishes not revoked, revoked, unknown and failure;
only not revoked returns exit status zero. Replace `roots.pem` with
`--system-trust` to use the configured default OpenSSL store. A final
`--allow-missing-nonce` explicitly permits responders that omit the nonce,
without allowing mismatches or stale responses.

`ocsp` and `ocsp_cli` use local issuers and delegated responders. Tests include
wrong trust/authorization/signatures, nonce and freshness failures, duplicate
status records, all certificate states, saved requests, no-overwrite behavior,
and independent OpenSSL checks. `timestamp` also exercises TSA OCSP evidence.
See [OCSP](../doc/ocsp.md) for API semantics and evidence in `libssig_verify`.

### TSA real de Costa Rica (opcional)

`tsa_sinpe` envía una sola solicitud RFC 3161 a TSA-SINPE y comprueba
nonce, huella, firma, propósito TSA y cadena de confianza. Después incorpora
el sello en un CAdES y verifica el contenedor persistido. Usa una firma
sintética: no requiere tarjeta ni PIN. No consulta revocación.

Obtén las raíces de confianza oficiales de la jerarquía TSA del BCCR y,
si la respuesta no los incluye, sus certificados intermediarios. No uses
como raíz confiable un certificado obtenido únicamente de la respuesta TSA.

```sh
cmake -S . -B build \
  -DLIBSSIG_TEST_TSA_SINPE=ON \
  -DLIBSSIG_TSA_SINPE_CA_FILE=/ruta/raices-tsa.pem \
  -DLIBSSIG_TSA_SINPE_INTERMEDIATES_FILE=/ruta/intermediarios-tsa.pem
cmake --build build -j
ctest --test-dir build -R '^tsa_sinpe$' --output-on-failure -V
```

El intermediario es opcional: omite esa opción si no hace falta.
La URL predeterminada es `http://tsa.sinpe.fi.cr/tsaHttp/`, indicada en la
[guía del BCCR](https://www.bccr.fi.cr/firma-digital/DocFirmaDigital/guiaxolidos.pdf).
Puede cambiarse con `LIBSSIG_TSA_SINPE_URL` si el servicio publica otra URL.
La prueba depende de la red, disponibilidad y políticas del servicio real;
no se habilita de forma predeterminada. Al habilitarla, también participa en
`ctest` sin filtros. Para deshabilitarla: `-DLIBSSIG_TEST_TSA_SINPE=OFF`.
Cada ejecución conserva TSQ, TSR y CAdES en un subdirectorio nuevo de
`build/tests/tsa-sinpe-fixtures/`, incluso si la validación falla.

El auxiliar `timestamp-file` también permite generar solicitudes y aplicar
respuestas manualmente; ejecutarlo sin argumentos muestra su uso.

### Niveles CAdES/PAdES

`ctest -R '^ades$' --output-on-failure` genera B-B, B-T, B-LT y B-LTA con
servicios locales en memoria, sin red ni tarjeta. Prueba las nueve
combinaciones de algoritmo/hash, contenido CAdES incluido/separado, DSS PDF,
OCSP/CRL, errores de TSA, revocación y alteraciones de evidencia protegida.

Para la comprobación independiente con pyHanko y OpenSSL, ver
[doc/profiles.md](../doc/profiles.md). No es una dependencia de compilación.

Historical validation (offline, synthetic roots):

```sh
ctest --test-dir build -R '^(ades|history)$' --output-on-failure
./build/tests/verify-file --system-trust --tsa-system-trust firma.p7m
```

`history` includes certificates already expired today, trusted timestamps from
before expiry, earlier/later revocation, key compromise, missing/stale evidence
and refreshing only the current archive-TSA status. See `doc/profiles.md` for
the supported historical policy and its limits.

`verify` selects the validation policy from detected evidence by default.
`--historical` on `verify-file` additionally requires LTA even for an input
without archive evidence. Automatic selection and per-signer level reporting
are tested for all four CAdES and PAdES levels.

## JSON/XML AdES

`document_ades` uses a simulated PKCS#11 module, local keys, TSA and OCSP/CRL;
no physical card or personal certificates are needed. It covers 144 combinations
of formats, levels, algorithms, hashes and attached/detached content, plus
B-B-to-LTA extension, archive renewal, separate request/response timestamping,
nonce mismatch, invalid payloads, duplicate XML IDs, missing validation data,
DTD rejection, duplicate JSON members and 600 parser mutations/truncations.

Independent conformance checks run by default with the rest of CTest. The
ETSI schemas are pinned Git submodules under `tests/standards/`; the W3C import
is retained locally with its original license. These are structural schemas,
not a complete official ETSI conformance certification suite.

```sh
git submodule update --init --recursive
nix develop --command cmake -S . -B build
nix develop --command cmake --build build --parallel
nix develop --command ctest --test-dir build --output-on-failure
# Only independent checks; CTest also runs their fixture generators:
nix develop --command ctest --test-dir build -L conformance --output-on-failure
```

Without Nix, install `tests/requirements.txt` in a Python 3.10+ environment
before configuring, and set `-DPython3_EXECUTABLE=/path/to/venv/bin/python`.
CMake and CTest never install packages or fetch schemas. Missing dependencies
or submodules cause an actionable configure error. To deliberately build just
the C tests, use `-DLIBSSIG_TEST_CONFORMANCE=OFF`; `BUILD_TESTING=OFF` also removes
all test dependencies. Normal application/library builds need no submodules.

`ades_interop` checks CAdES ATSv3 and PAdES LTA/renewal using pyHanko/OpenSSL.
`document_interop` independently verifies 144 JSON/XML signatures and their
RFC 3161 timestamps. `document_schema` applies unmodified official schemas.
They use CTest fixtures, so selection by `-R`/`-L`, parallel execution, and
running from an empty build fixture directory remain supported.

The same `tests/CMakeLists.txt` can be added by a consumer against an imported
`libssig::ssig` target. CRSign reuses it through a pinned libssig submodule.
See [standards/README.md](standards/README.md) for upstream versions and licenses.
