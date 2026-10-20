# Verification API

Include `<libssig/libssig.h>`. Verification takes bytes, not file paths, and
requires no PKCS#11 context, token, or PIN. The container must be CMS/CAdES DER;
the signed container cannot be a PDF, XML, PEM, or S/MIME message. Custom
certificate inputs separately support PEM and DER.

```c
libssig_verify_params params = {
    .data = signature_bytes,
    .data_len = signature_len,
    .content = original_bytes,
    .content_len = original_len,
    .options = 0,
};
libssig_verify_result result = {0};
libssig_status status = libssig_verify(&params, &result);

if (status == LIBSSIG_OK) {
    /* Every signer and the original content passed verification.
     * With no ca_data and options = 0, certificate trust has not been checked. */
}
libssig_verify_free(&result);
```

For a container with embedded content, leave `content = NULL` and
`content_len = 0`. The library detects attached versus detached automatically.
External content supplied to an attached container is rejected to avoid
ambiguity. For an empty external file, supply a non-NULL pointer and zero len;
NULL means the external content is absent.

All signers must pass cryptographic verification. Any present ESS
`signingCertificate`/`signingCertificateV2` attributes must correctly identify
the signer and referenced certificates. Duplicate or malformed ESS/MIME
attributes are rejected. This is not a complete CAdES baseline policy validator;
missing ESS attributes allow ordinary CMS verification. No MIME value is inferred
from untrusted external metadata.

The result owns an array of signers with copied X.509 DER certificates and the
signed MIME attribute, when present. It contains no extracted document. Inputs
are borrowed during the call. Free a previous result before reuse; do not copy
structures with owned memory. `libssig_verify_free()` accepts NULL and clears
results, including already empty results.

## Custom authorities and intermediates

Provide certificate bytes in `ca_data`/`ca_data_len` to require trust using your
own authorities. The library reads no certificate files itself. Each certificate
input accepts a PEM bundle of one or more `CERTIFICATE` blocks separated only
by whitespace, or one complete DER X.509 certificate. Empty inputs, malformed
blocks, non-certificate blocks, and extra non-whitespace text are rejected.
Certificate buffers are borrowed only during the call and limited to `INT_MAX`
bytes. Omit a buffer with NULL and zero len.

```c
libssig_verify_params params = {
    .data = signed_file_bytes, /* Attached container. */
    .data_len = signed_file_len,
    .ca_data = roots_pem,
    .ca_data_len = roots_pem_len,
    .intermediates_data = intermediates_pem,
    .intermediates_data_len = intermediates_pem_len,
    .options = 0, /* Trust only the supplied authorities. */
};
```

Custom roots alone activate trust checking. Setting
`options = LIBSSIG_VERIFY_SYSTEM_TRUST` combines these authorities with the
system store; without that mask, system roots are not loaded. A chain can end
at a trusted authority from either source; it need not validate against both.
Only explicit `ca_data` and enabled system roots enter the trusted store.
Partial-chain trust is not enabled: a lone non-self-signed intermediate does
not become an accepted chain endpoint.

`intermediates_data`/`intermediates_data_len` supplies additional untrusted
certificates for chain construction and ESS certificate references, alongside
certificates embedded in the signed container. These certificates never become
trust anchors. Supplying intermediates requires `ca_data` or `SYSTEM_TRUST`;
otherwise the call returns `LIBSSIG_ERROR_ARGUMENT`. The signer certificate must
still be embedded in the signed container.

## System trust

Set `params.options = LIBSSIG_VERIFY_SYSTEM_TRUST` to require certificate chains
valid at the current time and anchored in OpenSSL's configured default trust
store. OpenSSL honors `SSL_CERT_FILE` and `SSL_CERT_DIR`; this is not a portable
bridge to every operating system's native certificate store. Certificates
embedded in the container can supply intermediates, but never become trusted
anchors merely by being embedded.

The result separates `signature_valid`, `trust_checked`, and `trusted`.
`LIBSSIG_ERROR_TRUST` preserves valid signature information and each signer's
numeric X.509 `trust_error`. If the store could not be loaded, `trust_checked`
remains false and there is no per-signer chain error. With no custom roots or
trust option,
`trusted = false` means trust was not evaluated, not that the certificate was
rejected. Unknown option bits return `LIBSSIG_ERROR_ARGUMENT`.

Verification does not download missing intermediates, contact OCSP, fetch CRLs,
or apply document-signing EKU or national policy requirements. It can validate
OCSP responses supplied by the application; see [OCSP](ocsp.md). Trust checks use
the current time, not the signer's claimed `signingTime`. A valid result does
not establish revocation status or a trusted signing time.

## Persisted signature timestamps

Every present `signature-time-stamp` attribute is checked automatically, with
no original RFC 3161 request or response required. An invalid or malformed stamp
returns `LIBSSIG_ERROR_TIMESTAMP`, while preserving `signature_valid` and the
original document signers. This means a valid document signature can coexist
with an invalid timestamp. Duplicate timestamp attributes or multiple values
are rejected; one timestamp per signer is supported.

Each `result.signers[i].timestamp` exposes:

| Field | Meaning |
| --- | --- |
| `present` | A timestamp attribute exists |
| `valid` | Imprint matches this document signature; timestamp signature, ESS binding, TSA certificate purpose, TSA name if present, version and generation time pass |
| `status` | Per-timestamp status; `ERROR_NOT_FOUND` when absent |
| `time` | UTC ISO 8601 string at second precision, only if valid; fractional seconds are not returned |
| `cert_der`, `cert_der_len` | Copied TSA signer certificate, owned by the result |
| `trust_checked`, `trusted`, `trust_error` | Independent TSA chain result and numeric X.509 error |

`valid` alone does not authenticate the claimed time to a trusted authority.
Configure TSA trust independently using `tsa_ca_data`/`tsa_ca_data_len`,
`tsa_intermediates_data`/`tsa_intermediates_data_len`, and optionally
`LIBSSIG_VERIFY_TSA_SYSTEM_TRUST`. The document's `ca_data` and `SYSTEM_TRUST`
are never inherited by TSA verification. TSA intermediates require a TSA trust
source. Certificate input formats, ownership and limits match the document
certificate inputs.

```c
libssig_verify_params params = {
    .data = timestamped_bytes,
    .data_len = timestamped_len,
    .tsa_ca_data = tsa_roots_pem,
    .tsa_ca_data_len = tsa_roots_pem_len,
    .tsa_intermediates_data = tsa_intermediates_pem,
    .tsa_intermediates_data_len = tsa_intermediates_pem_len,
    .options = LIBSSIG_VERIFY_REQUIRE_TIMESTAMP,
};
```

`LIBSSIG_VERIFY_REQUIRE_TIMESTAMP` requires a valid timestamp on every signer;
otherwise missing stamps are reported without failing the call. It does not
implicitly enable TSA trust. With a TSA trust source, an untrusted chain returns
`LIBSSIG_ERROR_TRUST` while retaining `timestamp.valid = true` when cryptographic
checks passed. Top-level `trust_checked` and `trusted` refer only to document
signers; consult the nested timestamp fields for TSA trust. All timestamp checks
still run when the document signer's trust check fails. A bad timestamp takes
precedence over a trust failure in the returned status; individual results
retain the separate outcomes.

Timestamp cryptographic verification supports SHA-256/384/512 message imprints.
Future generation times beyond 300 seconds are rejected. Certificate trust is
checked at the current time, including for the TSA. Without supplied OCSP evidence no revocation checking is performed, and there
is no historical validation; an expired TSA can have `valid = true` and a failed
current trust check. These checks do not establish CAdES LT/LTA compliance.

## Errors

| Status | Meaning |
| --- | --- |
| `LIBSSIG_ERROR_ARGUMENT` | Invalid arguments, unknown option bits, external content for an attached container, or intermediates without a trust source |
| `LIBSSIG_ERROR_FORMAT` | Malformed/truncated CMS or certificate input, or trailing garbage |
| `LIBSSIG_ERROR_CONTENT_REQUIRED` | Detached signature without the original content |
| `LIBSSIG_ERROR_VERIFY` | Signature/content mismatch, missing signer certificate, or invalid ESS/MIME attribute |
| `LIBSSIG_ERROR_UNSUPPORTED` | Unsupported container type or an algorithm reported unsupported by OpenSSL |
| `LIBSSIG_ERROR_TRUST` | Valid document signature, but document/TSA certificate trust could not be established |
| `LIBSSIG_ERROR_OCSP` | Supplied OCSP is invalid, unknown, unavailable or required evidence is missing |
| `LIBSSIG_ERROR_REVOKED` | Authenticated OCSP says a document/TSA certificate is revoked |
| `LIBSSIG_ERROR_TIMESTAMP` | Valid document signature, but an invalid/malformed timestamp or a required timestamp is absent |

Memory and other local cryptographic failures use `LIBSSIG_ERROR_MEMORY` and
`LIBSSIG_ERROR_CRYPTO`. Except for `ERROR_TRUST`, `ERROR_TIMESTAMP`, `ERROR_OCSP` and `ERROR_REVOKED`,
failures leave the result empty.
External content is limited to `INT_MAX` bytes, containers to `LONG_MAX` bytes;
verification and parsing take place in memory.

## Manual commands

```sh
# Existing detached signature and its exact original content.
./build/tests/verify-file prueba-mime.p7s prueba-mime.txt

# A container generated with the default signing options.
./build/tests/verify-file documento.p7m

# Also require system trust (may fail if the issuer is not trusted locally).
./build/tests/verify-file --system-trust prueba-mime.p7s prueba-mime.txt

# Require your own authorities, without loading system roots.
./build/tests/verify-file --ca-file raices.pem \
  --intermediates intermediarios.pem documento.p7m

# Verify a stored timestamp and require trusted TSA certificates.
./build/tests/verify-file --require-timestamp --tsa-ca-file tsa-raices.pem \
  --tsa-intermediates tsa-intermediarios.pem documento.p7m

# Combine custom and system authorities.
./build/tests/verify-file --system-trust --ca-file raices.pem \
  --intermediates intermediarios.pem documento.p7m
```

The commands return zero only when all requested checks pass. They do not write
or extract documents. Extensions are illustrative; container contents determine
whether an original file is required.
