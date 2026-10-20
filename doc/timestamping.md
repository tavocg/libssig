# CAdES signature timestamps

`libssig_timestamp_request()` creates an RFC 3161 TimeStampReq from the selected
CAdES signer's signature value. The application sends it to its chosen TSA.
`libssig_timestamp()` validates the TimeStampResp and inserts its timestamp
token as an unsigned `signature-time-stamp` attribute. No token or PIN is needed
for either call. The original signature and attached/detached mode are preserved.
This supplies the signature timestamp used by CAdES B-T; the API is not a complete
ETSI baseline policy validator.

## Request

```c
libssig_timestamp_request_params params = {
    .data = cades_bytes,
    .data_len = cades_len,
    .signer_index = 0,
    .hash = LIBSSIG_HASH_SHA256,
    .policy_oid = NULL,
};
libssig_signature request = {0};
libssig_status status = libssig_timestamp_request(&params, &request);
```

With `{0}`, the request hash is SHA-256 and the first signer is selected.
SHA-384 and SHA-512 are also supported, independently of the original signature
algorithm. `policy_oid` optionally requires a numeric TSA policy OID. Requests
include a random positive 128-bit nonce and ask the TSA to include its certificate.
Keep the exact DER request for response validation.

The input must be CAdES with signed contentType, messageDigest, signingTime and
signingCertificateV2 attributes, plus the signer's embedded certificate. The
selected signer's signed attributes and ESS certificate binding are checked.
Timestamping does not check the document digest, original signer's trust, or
baseline policy compliance: use `libssig_verify()` with the original content
when needed. Detached signatures need no original document just to request or
incorporate a timestamp. Ordinary CMS without these CAdES attributes is rejected.

## Transport

The application chooses the URL, authentication, HTTPS policy, timeouts and
response size limit. It sends the DER request as `application/timestamp-query`
and receives a DER response as `application/timestamp-reply`. The original
file and private key are not sent; the request contains the hash of the
signature value, a nonce, and optional policy.

For example, after writing `request.data`/`request.len` to `request.tsq`, an
application could perform the equivalent of:

```sh
curl --fail --show-error \
  -H 'Content-Type: application/timestamp-query' \
  -H 'Accept: application/timestamp-reply' \
  --data-binary @request.tsq \
  --output response.tsr \
  'https://tsa.example/timestamp'
```

That URL is illustrative. No network request is made by libssig. The proposed
Sign CLI uses `-A TSA_URL`, or a TSA configured inside `-p PROFILE`; these future
CLI forms are documented in [TODO.md](TODO.md).

## Validate and incorporate

```c
libssig_timestamp_params params = {
    .data = cades_bytes,
    .data_len = cades_len,
    .signer_index = 0,
    .request = request.data,
    .request_len = request.len,
    .response = response_bytes,
    .response_len = response_len,
    .ca_data = tsa_roots_pem,
    .ca_data_len = tsa_roots_pem_len,
    .intermediates_data = tsa_intermediates_pem,
    .intermediates_data_len = tsa_intermediates_pem_len,
    .options = 0,
};
libssig_signature timestamped = {0};
libssig_status status = libssig_timestamp(&params, &timestamped);

/* On success, save timestamped.data/timestamped.len as the new container. */
libssig_signature_free(&timestamped);
libssig_signature_free(&request);
```

Supply explicit TSA roots, `LIBSSIG_TIMESTAMP_SYSTEM_TRUST`, or both. The TSA
trust configuration is independent of the document signer's authorities. Root
and intermediate inputs follow [the verification API](verification.md): PEM
certificate bundles or one DER certificate; intermediates are never trust anchors.
The system option uses OpenSSL's configured default store, not a guaranteed
native operating-system trust implementation.

Before attaching, the library requires a granted response and checks:

- The original signature value matches the request imprint.
- Response version, message imprint, nonce, requested policy, and any TSA name.
- TSA signature, ESS certificate binding, timestamp-signing certificate purpose,
  and certificate chain to the configured trust anchors.
- The generation time is valid and no more than 300 seconds in the future.

Only requests following the library's nonce/certReq/extension conventions are
accepted. Invalid or truncated DER, trailing data, unknown options, inconsistent
pointer/len pairs, and empty certificate inputs fail. Inputs are limited to
`INT_MAX` bytes. The selected signer must not already have a timestamp attribute;
existing timestamps are never replaced. A signer index refers to the current
input container; do not assume indices survive modifications to a multi-signer
container's DER ordering.

Both outputs use `libssig_signature` as an owned DER buffer. Free them with
`libssig_signature_free()`; `ck_rv` is always zero. Free previous outputs before
reuse, keep input buffers alive during each synchronous call, and do not alias
an output with a structure holding its input bytes. Errors leave outputs empty.
`LIBSSIG_ERROR_TIMESTAMP` indicates a non-granted TSA response;
`LIBSSIG_ERROR_TRUST` indicates failure to establish TSA certificate trust;
`LIBSSIG_ERROR_VERIFY` covers mismatches or invalid signatures;
`LIBSSIG_ERROR_AMBIGUOUS` indicates an existing timestamp for that signer.

No OCSP, CRL, certificate fetching, LT/LTA evidence, or historical trust validation
is performed. TSA chains are validated at the current time. `libssig_verify()` also validates persisted signature timestamp tokens, without
the original TSQ/TSR. Configure its independent `tsa_ca_data` and optional
`LIBSSIG_VERIFY_TSA_SYSTEM_TRUST` to validate TSA trust, and use
`LIBSSIG_VERIFY_REQUIRE_TIMESTAMP` to reject missing timestamps. See
[verification](verification.md#persisted-signature-timestamps).

## Automated example

```sh
cmake --build build
ctest --test-dir build -R '^timestamp$' --output-on-failure

openssl ts -verify \
  -queryfile build/tests/timestamp-fixtures/timestamp.tsq \
  -in build/tests/timestamp-fixtures/timestamp.tsr \
  -CAfile build/tests/timestamp-fixtures/tsa-root.pem
```

The test uses a locally generated TSA and no HTTP service. Its certificates and
responses are fixtures, not production trust authorities. It covers nine
original algorithm/hash combinations, attached and detached containers, altered
responses, nonce/policy/imprint mismatches, rejected requests, future timestamps,
wrong TSA trust, incorrect EKU, duplicate timestamps, and system trust selection.
