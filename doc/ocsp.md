# OCSP requests and verification

The application owns HTTP, endpoint selection, credentials, timeouts and cache.
Libssig extracts OCSP URLs, creates a request and validates the response without
network access. The same API works for a document signer or a TSA certificate.
It checks current revocation evidence, not historical signing validity or CRLs.

## Create a request

```c
libssig_ocsp_request_params params = {
    .cert_data = cert_bytes,
    .cert_data_len = cert_len,
    .issuer_data = issuer_bytes,
    .issuer_data_len = issuer_len,
};
libssig_ocsp_query query = {0};
libssig_status status = libssig_ocsp_request(&params, &query);
```

Supply one PEM or DER X.509 certificate per input buffer. The issuer must be a
CA that actually signed the target certificate. This relationship is checked,
but the issuer is not automatically trusted. Inputs are borrowed during calls;
all certificate and DER inputs are limited to `INT_MAX` bytes.

The result contains DER in `query.data`/`query.len` and an owned list of HTTP(S)
OCSP URLs in `query.urls`. URLs come from the target certificate's AIA;
unsupported schemes are omitted. No URL is required to generate the request:
the application can configure an endpoint separately. Malformed OCSP URI values
or malformed/duplicate AIA extensions are rejected. An advertised URL does not
itself establish responder trust.

The unsigned request has one CertID using SHA-1 for issuer-name/key
identification, as commonly supported by OCSP services. This is not a SHA-1
signature or a hash of the document. The request includes a random 32-byte nonce.
Keep the exact request to bind the reply to the query. Free the output using
`libssig_ocsp_request_free(&query)`; the function accepts NULL, clears fields,
and frees URLs as well as request data. Free previous results before reuse.

## Transport

After saving the DER request, the application performs the equivalent of:

```sh
curl --fail --show-error \
  -H 'Content-Type: application/ocsp-request' \
  -H 'Accept: application/ocsp-response' \
  --data-binary @request.der \
  --output response.der \
  'http://ocsp.example/status'
```

The URL is illustrative. No request is sent by the library. The application
handles HTTP failures separately and must not interpret an unavailable service
as proof that the certificate is not revoked.

## Validate the response

```c
libssig_ocsp_verify_params params = {
    .cert_data = cert_bytes,
    .cert_data_len = cert_len,
    .issuer_data = issuer_bytes,
    .issuer_data_len = issuer_len,
    .request = query.data,
    .request_len = query.len,
    .response = response_bytes,
    .response_len = response_len,
    .ca_data = roots_pem,
    .ca_data_len = roots_pem_len,
    .intermediates_data = intermediates_pem,
    .intermediates_data_len = intermediates_pem_len,
    .options = 0,
    .max_age = 0,
    .clock_skew = 0,
};
libssig_ocsp_result result = {0};
libssig_status status = libssig_ocsp_verify(&params, &result);

if (status == LIBSSIG_OK && result.status == LIBSSIG_OCSP_GOOD) {
    /* Authenticated, fresh response reporting this certificate not revoked. */
}
libssig_ocsp_request_free(&query);
```

Require explicit roots, `LIBSSIG_OCSP_SYSTEM_TRUST`, or both. Roots and additional
intermediates accept PEM bundles or a single DER certificate, as in
[verification](verification.md). The issuer and embedded response certificates
are untrusted chain-building inputs, not automatically trust anchors.

Validation checks:

- The target certificate was signed by the supplied CA issuer.
- The unsigned single-certificate request names that target and issuer.
- A successful response has exactly one status for that CertID.
- A matching nonce; duplicate nonce extensions are rejected.
- The response signature and current certificate chain.
- The responder is the actual issuer, or is directly issued by it with explicit
  `id-kp-OCSPSigning` EKU and suitable Key Usage. A different trusted CA or
  arbitrary trusted responder is not accepted for this issuer.
- `producedAt`, `thisUpdate`, `nextUpdate` when present, and revocation time.
  Unsupported critical extensions are rejected.

`max_age = 0` defaults to 86400 seconds; `clock_skew = 0` defaults to 300 seconds.
Use positive values to override them, up to `LONG_MAX`. Maximum age applies to
both producedAt and thisUpdate, even when nextUpdate exists. Missing nextUpdate
is accepted only within this age bound. Future times beyond the skew, expired
nextUpdate and inconsistent time ordering fail. Returned times are UTC ISO 8601
at second precision; absent nextUpdate/revocation time is an empty string.

Some services omit nonces for cached responses. Set
`LIBSSIG_OCSP_ALLOW_MISSING_NONCE` explicitly to accept a missing response nonce;
a mismatched nonce still fails, as do stale responses. The request must contain
a nonce. Current request verification supports the library's SHA-1 CertIDs.

## Result semantics

`libssig_ocsp_verify()` returns `LIBSSIG_OK` for an authenticated and fresh OCSP
response, including **revoked** and **unknown** responses. Always inspect
`result.status`:

| Status | Meaning |
| --- | --- |
| `LIBSSIG_OCSP_GOOD` | Responder reports the certificate not revoked |
| `LIBSSIG_OCSP_REVOKED` | Responder reports revocation; reason and time are provided |
| `LIBSSIG_OCSP_UNKNOWN` | Authorized responder cannot determine the certificate status |
| `LIBSSIG_OCSP_FAILED` | No usable authenticated response |

`valid` is true for the first three states. `error` holds the function's return
status. `response_status` is the outer RFC 6960 response code, or -1 if not parsed.
`reason` is the CRL reason code, or -1 when inapplicable. Results own no memory.
Failures clear certificate-state metadata and retain only the parsed outer
response code and error. Format, argument, signature/matching, trust, missing or
ambiguous status and responder-service errors remain distinguishable through
`error`. A non-successful outer response returns `LIBSSIG_ERROR_OCSP`.

GOOD does not itself establish that the target certificate is currently valid
or suitable for a document/TSA role. Its validity period and other application
policies are separate. Responder-chain certificates are checked at the current
time, but their revocation is not checked recursively. No CRL fallback, network,
or historical validation is performed.

## Evidence in libssig_verify

Attach each request/response to a signer index and target role. Trust is selected
from the document or TSA parameter group independently:

```c
libssig_ocsp_evidence evidence[] = {
    {
        .signer_index = 0,
        .tsa = false,
        .issuer_data = issuer_pem,
        .issuer_data_len = issuer_pem_len,
        .request = request_der,
        .request_len = request_der_len,
        .response = response_der,
        .response_len = response_der_len,
    },
};
libssig_verify_params params = {
    .data = signed_bytes,
    .data_len = signed_len,
    .ca_data = roots_pem,
    .ca_data_len = roots_pem_len,
    .ocsp = evidence,
    .ocsp_count = sizeof(evidence) / sizeof(evidence[0]),
    .options = LIBSSIG_VERIFY_REQUIRE_OCSP,
};
```

Use `tsa = true` for the timestamp signer's certificate, with its actual issuer.
That evidence uses `tsa_ca_data`, `tsa_intermediates_data` and
`LIBSSIG_VERIFY_TSA_SYSTEM_TRUST`; document evidence uses the corresponding
ordinary trust fields. Evidence requires the appropriate trust source. In each
evidence entry, `options` accepts only `LIBSSIG_OCSP_ALLOW_MISSING_NONCE`; system
trust is controlled by the parent verify options. Per-entry max_age/clock_skew
have the same defaults as the standalone API.

`LIBSSIG_VERIFY_REQUIRE_OCSP` requires GOOD for every document signer.
`LIBSSIG_VERIFY_REQUIRE_TSA_OCSP` requires a valid timestamp and GOOD OCSP for
its TSA on every signer. Without these flags, missing evidence is allowed, but
all supplied evidence is checked. Duplicate entries for the same signer/role
or out-of-range indices return `LIBSSIG_ERROR_ARGUMENT`.

Results are `result.signers[i].ocsp` and
`result.signers[i].timestamp.ocsp`. No supplied evidence yields FAILED with
`error = LIBSSIG_ERROR_NOT_FOUND`; an evidence entry with `response = NULL` and
`response_len = 0` represents a query without a usable response and yields
FAILED with `error = LIBSSIG_ERROR_OCSP`. The application retains the transport
error details and decides whether a required policy allows retry or offline use.

Authenticated revocation returns `LIBSSIG_ERROR_REVOKED` from `libssig_verify`.
Unknown, failed or missing required evidence returns `LIBSSIG_ERROR_OCSP`.
The document signature, timestamp and chain results are preserved: `trusted`
continues to mean chain trust, not successful revocation validation. A revoked
certificate can have a valid cryptographic signature and a trusted chain.
Revocation takes precedence over other evidence failures; per-target fields
retain the detailed outcome. Fatal local or argument errors still clear output.

## Manual tools

```sh
./build/tests/ocsp-file request cert.pem issuer.pem request.der

# The application sends request.der to a configured or advertised OCSP URL.
./build/tests/ocsp-file verify \
  cert.pem issuer.pem request.der response.der roots.pem intermediates.pem

# Use OpenSSL's configured system store instead of an explicit root file.
./build/tests/ocsp-file verify \
  cert.pem issuer.pem request.der response.der --system-trust

# Explicitly allow responders that omit the response nonce.
./build/tests/ocsp-file verify \
  cert.pem issuer.pem request.der response.der roots.pem --allow-missing-nonce
```

Request output paths must not exist. The CLI exits zero only for GOOD; revoked,
unknown and failed responses all return nonzero, while printing distinct states.
It never performs HTTP. `verify-file` does not yet accept OCSP evidence files on
the command line; applications can supply them through `libssig_verify_params`.

```sh
ctest --test-dir build -R 'ocsp|timestamp' --output-on-failure
```

Tests use local certificates/responders and no network. They cover issuer and
delegated signatures, unauthorized responders, wrong trust, nonce policies,
freshness, duplicates, malformed input, all certificate states, CLI behavior,
independent OpenSSL verification, and separate document/TSA evidence integration.
