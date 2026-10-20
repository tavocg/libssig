# Verification API

Include `<libssig/libssig.h>`. Verification takes bytes, not file paths, and
requires no PKCS#11 context, token, or PIN. The container must be CMS/CAdES DER;
this API does not parse signed PDF, XML, PEM, or S/MIME messages.

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
     * With options = 0, certificate trust has not been checked. */
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
remains false and there is no per-signer chain error. With no trust option,
`trusted = false` means trust was not evaluated, not that the certificate was
rejected. Unknown option bits return `LIBSSIG_ERROR_ARGUMENT`.

Verification does not download missing intermediates, contact OCSP, fetch CRLs,
or apply document-signing EKU or national policy requirements. Trust checks use
the current time, not the signer's claimed `signingTime`. A valid result does
not establish revocation status or a trusted signing time.

## Errors

| Status | Meaning |
| --- | --- |
| `LIBSSIG_ERROR_ARGUMENT` | Invalid arguments, unknown option bits, or external content for an attached container |
| `LIBSSIG_ERROR_FORMAT` | Malformed/truncated CMS input or trailing bytes |
| `LIBSSIG_ERROR_CONTENT_REQUIRED` | Detached signature without the original content |
| `LIBSSIG_ERROR_VERIFY` | Signature/content mismatch, missing signer certificate, or invalid ESS/MIME attribute |
| `LIBSSIG_ERROR_UNSUPPORTED` | Unsupported container type or an algorithm reported unsupported by OpenSSL |
| `LIBSSIG_ERROR_TRUST` | Valid signature, but certificate trust could not be established |

Memory and other local cryptographic failures use `LIBSSIG_ERROR_MEMORY` and
`LIBSSIG_ERROR_CRYPTO`. Except for `ERROR_TRUST`, failures leave the result empty.
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
```

The commands return zero only when all requested checks pass. They do not write
or extract documents. Extensions are illustrative; container contents determine
whether an original file is required.
