# CAdES and PAdES baseline generation

`libssig_sign_params.level` selects B-B, B-T, B-LT or B-LTA. Zero means B-LTA.
`format` selects CAdES (default), PAdES, or basic CMS (B-B only).
An unavailable service, untrusted chain, revoked certificate, invalid response
or missing validation material fails the operation with empty output; the
library never silently saves a lower level.

| Level | CAdES | PAdES |
| --- | --- | --- |
| B-B | CMS signed attributes and ESSv2 | Detached CMS in a PDF signature dictionary |
| B-T | Signature timestamp | Signature timestamp inside CMS |
| B-LT | Certificate chains and OCSP/CRL in SignedData | Chains and OCSP/CRL in the PDF DSS |
| B-LTA | ATSv3 with ATSHashIndexV3 | Document timestamp covering the DSS and preceding revisions |

The implementation follows [ETSI EN 319 122-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.02.01_60/en_31912201v010201p.pdf)
and [ETSI EN 319 142-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf).
National trust policies, qualified-signature status and legal acceptance are
not inferred from the requested level.

## Services and ownership

libssig uses no sockets and reads no files. The application supplies an
exchange callback, used synchronously for timestamp/OCSP POSTs and certificate/
CRL GETs. Requests are borrowed; responses must use malloc-compatible owned
memory, released by `libssig_signature_free`. Return a nonzero status on HTTP
failure. Only HTTP(S) URLs are accepted. Each response is limited to 16 MiB,
issuer paths to 16 steps, and OCSP/CRL URLs to 16 alternatives per certificate.

```c
libssig_verify_params trust = {
    .options = LIBSSIG_VERIFY_SYSTEM_TRUST | LIBSSIG_VERIFY_TSA_SYSTEM_TRUST,
    /* Optional document/TSA roots and intermediates, with independent trust. */
};
libssig_sign_services services = {
    .exchange = http_exchange, /* implemented by the application */
    .tsa_url = "https://tsa.example/timestamp",
    .trust = &trust,
};
libssig_sign_params params = {
    .token = token, .cert = cert,
    .data = data, .data_len = data_len,
    .pin = pin, .pin_len = pin_len,
    .format = LIBSSIG_FORMAT_PADES,
    .level = LIBSSIG_LEVEL_B_LTA,
    .services = &services,
};
libssig_signature output = {0};
libssig_status status = libssig_sign(&ctx, &params, &output);
/* Save only when status == LIBSSIG_OK. */
libssig_signature_free(&output);
```

A NULL `services.trust` uses system trust for document and TSA. Supplied
intermediates and downloaded issuer certificates remain untrusted. AIA may
supply missing issuers. Non-root certificates in both paths require good,
authenticated OCSP or a valid complete direct CRL. OCSP is nonce-bound;
responders that omit it require explicit `LIBSSIG_OCSP_ALLOW_MISSING_NONCE`
in `services.ocsp_options`. Missing-nonce permission does not accept a mismatch.
`max_age`/`clock_skew` configure freshness (OCSP defaults: 24 h / 300 s).
CRLs must be currently valid; `max_age != 0` also bounds their age.

## Existing signatures and verification

`libssig_extend()` upgrades a CAdES container without accessing the card. For
detached CAdES, supply the original `content` (a non-NULL pointer for empty
content). It can also upgrade a PDF containing one signature whose ByteRange
covers the complete input and whose Contents reserve is large enough.

PDF changes use incremental revisions; the original byte ranges remain
unchanged. Encrypted PDFs, certification permissions (/Perms), XFA, advanced
CRL scopes/delta CRLs, and OCSP delegation requiring additional responder
revocation proofs are rejected rather than treated as complete LT evidence.
Adding a second signature to an already signed PDF, CMS countersignature augmentation and renewal of existing archive timestamps
are not implemented. A PDF signature reserves 256 KiB for its CMS/token;
exceeding that capacity fails explicitly.

`libssig_verify()` recognizes PDF input and checks CMS signatures, signature
timestamps and archive/document timestamps, including archive hash indexes.
Trust is checked at the current time. It does not yet implement a complete
ETSI historical/past-validation policy, automatically consume embedded status
information as a revocation policy, classify arbitrary external signatures by
baseline level, or schedule preservation/renewal. An archive seal protects
embedded evidence; checking that seal alone does not replace historical
validation of that evidence. Existing explicit OCSP verification remains
available. Installation of a root is independent of the embedded certificates.

## Tests

The `ades` test generates all four levels with a local TSA/OCSP responder and
checks failure on revoked certificates, archive-service errors and modified
archive-protected evidence. PAdES B-B signing also exercises all nine existing
algorithm/hash combinations through the PKCS#11 mock.

Optional independent interoperability checks require Python with `pyhanko`
(and its `asn1crypto` dependency), plus the `openssl` CLI:

```sh
ctest --test-dir build -R '^ades$' --output-on-failure
python tests/ades_interop.py build/tests/ades-fixtures
```

The independent check recalculates CAdES ATSv3/index hashes with asn1crypto,
verifies the archive token with OpenSSL and validates the PAdES evidence record
with pyHanko, offline against synthetic test roots. These fixtures have short
certificate validity periods and should be regenerated before checking them.
