# Signing API

Include `<libssig/libssig.h>` and link `libssig::ssig`. Public declarations do
not require PKCS#11 or OpenSSL headers.

Open a context, select a token with `libssig_tokens()`, then select its
certificate with `libssig_certificates()`. Keep the context and selected objects
alive during the signing call. The certificate must have accessible DER and a
nonempty binary ID; the private key is selected using that ID.

```c
/* ctx is open; token and cert point to selected results.
 * data/data_len hold the original bytes. pin/pin_len come from the application. */
libssig_sign_params params = {
    .token = token,
    .cert = cert,
    .data = data,
    .data_len = data_len,
    .pin = pin,
    .pin_len = pin_len,
    .algo = LIBSSIG_ALGO_RSA_PSS,
    .hash = LIBSSIG_HASH_SHA384,
    .format = LIBSSIG_FORMAT_CADES,
    .level = LIBSSIG_LEVEL_B_B,
    .mime_type = "application/pdf",
};

libssig_signature signature = {0};
libssig_status status = libssig_sign(&ctx, &params, &signature);
if (status == LIBSSIG_OK) {
    /* signature.data contains signature.len bytes of DER with embedded content.
     * The application may write these bytes to a .p7s file. */
} else {
    /* Inspect status first; signature.ck_rv holds a PKCS#11 error when present. */
}
libssig_signature_free(&signature);
```

A zero-initialized parameter structure defaults to `LIBSSIG_ALGO_RSA_PKCS`,
`LIBSSIG_HASH_SHA256`, `LIBSSIG_FORMAT_CADES` and `LIBSSIG_LEVEL_B_LTA`; the token, certificate and
content still need to be supplied. LTA also requires `services`; the example
above explicitly selects B-B for offline signing. See [profiles](profiles.md). Empty content is represented by `NULL, 0`.

| Parameter | Choices |
| --- | --- |
| `algo` | `LIBSSIG_ALGO_RSA_PKCS`, `LIBSSIG_ALGO_RSA_PSS`, `LIBSSIG_ALGO_ECDSA` |
| `hash` | `LIBSSIG_HASH_SHA256`, `LIBSSIG_HASH_SHA384`, `LIBSSIG_HASH_SHA512` |
| `format` | `LIBSSIG_FORMAT_CADES`, `LIBSSIG_FORMAT_PADES`, `LIBSSIG_FORMAT_CMS` (B-B only) |
| `level` | `LIBSSIG_LEVEL_B_B`, `LIBSSIG_LEVEL_B_T`, `LIBSSIG_LEVEL_B_LT`, `LIBSSIG_LEVEL_B_LTA` (default) |
| `services` | Transport callback, TSA URL and trust configuration for T/LT/LTA |
| `options` | `0` embeds the original content; `LIBSSIG_SIGN_DETACHED` keeps it separate |
| `mime_type` | Optional CAdES MIME type; NULL detects it from content with libmagic; ignored for CMS |

RSA-PSS uses MGF1 with the selected hash and a salt as long as the digest.
Every algorithm supports the three hashes when the token implements the required
combined mechanism. There is no fallback. Unsupported algorithm/hash/format
values return `LIBSSIG_ERROR_UNSUPPORTED`; provider failures return
`LIBSSIG_ERROR_PKCS11` with `ck_rv`. Malformed arguments return
`LIBSSIG_ERROR_ARGUMENT`, and container/verification failures return
`LIBSSIG_ERROR_CRYPTO`. MIME detection/database failures return
`LIBSSIG_ERROR_MAGIC`. Check `status` even when `ck_rv` is zero.

When `mime_type` is NULL, CAdES uses libmagic's `MAGIC_MIME_TYPE` detection on
`data`/`data_len`, without a filename. An explicit MIME value bypasses detection.
Unrecognized binary content may be classified as `application/octet-stream` by
libmagic; detection errors fail the operation instead of substituting that type.
The installed magic database must be available; libmagic honors `MAGIC` when
selecting the database. CMS does not perform MIME detection.

Inputs are borrowed and are not retained. The library neither prompts for a PIN
nor reads/writes documents; libmagic may read its local database. `pin = NULL, pin_len = 0` requests the protected device
path when authentication is needed; an explicitly empty software PIN uses a
non-NULL pointer with length zero. The application owns and clears its PIN
buffer after the call. The library does not keep a copy.

The output owns its memory and includes the signing certificate. Initialize it
with `{0}` and free it before reusing it as output. On failure it contains no
signature bytes, while `ck_rv` may describe the failure. The free function accepts
NULL or an already empty result, clears all fields, and does not close the
context. Copying the structure does not duplicate its owned memory.

This API accepts content up to `INT_MAX` bytes. It checks correspondence between
the generated signature and the selected certificate, but does not validate
certificate trust, validity periods, revocation, or application-specific usage
policies. CAdES includes a locally claimed signing time, not a TSA timestamp.
The signature includes the original content by default. Set
`params.options = LIBSSIG_SIGN_DETACHED` for a separate signature; retain the
exact original file for verification. Unknown option bits are rejected.
See [verification](verification.md) to check either form.
