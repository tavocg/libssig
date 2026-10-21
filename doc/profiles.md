# AdES baseline profiles

`libssig_sign_params.level` selects B-B, B-T, B-LT or B-LTA. Zero means B-LTA.
`format` selects CAdES (default), PAdES, XAdES, JAdES, or basic CMS (B-B only).
An unavailable service, untrusted chain, revoked certificate, invalid response
or missing validation material fails the operation with empty output; the
library never silently saves a lower level.

| Level | CAdES | PAdES |
| --- | --- | --- |
| B-B | CMS signed attributes and ESSv2 | Detached CMS in a PDF signature dictionary |
| B-T | Signature timestamp | Signature timestamp inside CMS |
| B-LT | Certificate chains and OCSP/CRL in SignedData | Chains and OCSP/CRL in the PDF DSS |
| B-LTA | ATSv3 with ATSHashIndexV3 | Document timestamp covering the DSS and preceding revisions |

The implementation follows [ETSI EN 319 122-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf)
and [ETSI EN 319 142-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf).
National trust policies, qualified-signature status and legal acceptance are
not inferred from the requested level.

JAdES follows ETSI TS 119 182-1 v1.2.1; XAdES follows EN 319 132-1 v1.3.1.
Both expose B-B/T/LT/LTA through the same sign, extend, timestamp and verify APIs.
JAdES uses flattened JWS with base64url-encoded payload and `etsiU` entries;
`iat` is signed, and `sigTst` covers the base64url signature value. Its archive
input follows clause 5.3.6.2.3, including payload, protected header, signature
and preceding encoded unsigned entries. XAdES uses an enveloping XMLDSig
Signature, C14N 1.1, SignedProperties, SigningCertificateV2 and DataObjectFormat.
Original bytes are stored in a base64 ds:Object. `SIGN_DETACHED` keeps them
external, resolved only from the caller's content bytes. ArchiveTimeStamp uses
the v1.4.1 namespace and the non-distributed computation in clause 5.5.2.3.
AnyValidationData/anyValData carry document and TSA chains plus OCSP/CRL.
No parser opens an external URI, file, schema or entity. Unsupported transforms,
JWS serializations and qualifying properties fail explicitly.

Documents are bounded to 32 MiB in these new formats, XML depth to 64 and nodes
to 100000; unsigned JSON entries, certificates and revocation items to 1024.
ECDSA JAdES uses the JOSE curve/hash pair (P-256/SHA-256, P-384/SHA-384,
P-521/SHA-512). RSA-PSS uses matching MGF1 and a digest-length salt.

All four formats support additional archive timestamps with freshly collected
validation material for preceding TSAs. Renewal must run while those TSA chains
can still be validated at the current time; no automated preservation scheduler
or arbitrary historical time sliding is provided.

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
Adding a second document signature to an already signed PDF and CMS
countersignature augmentation are not implemented. Archive timestamps can be
renewed in all four formats; the previous evidence and the latest TSA chain
must still be verifiable when renewal runs. A PDF signature reserves 256 KiB for its CMS/token;
exceeding that capacity fails explicitly.

`libssig_verify()` recognizes PDF input and checks CMS signatures, signature
timestamps and archive/document timestamps, including archive hash indexes.
Verification automatically detects CMS/CAdES/PAdES and the available evidence.
Each signer reports `level_detected`, `level` and `level_validated` separately:

| Detected evidence | Default validation |
| --- | --- |
| B-B signed attributes | Document chain at the current time |
| B-T signature timestamp | Current document and timestamp trust |
| B-LT timestamp and revocation data | Current chains plus included OCSP/CRL for every non-anchor |
| B-LTA archive/document timestamp | Bounded offline historical policy, with current trust for the last archive |

Detection reports the supported evidence combination, not an authoritative
level embedded in the signature. Containers do not have a single signed
baseline-level field. Removing all unsigned evidence can make a formerly
stronger signature indistinguishable from a lower level; use
`LIBSSIG_VERIFY_HISTORICAL` to require LTA when that is the application's policy.
Invalid detected higher-level evidence is never retried as a lower-level
success. Missing embedded revocation status produces an incomplete result,
not a validated LT/LTA label. Unclassified CMS returns no detected baseline.
`result.format` is meaningful when signers are present.

`LIBSSIG_VERIFY_CURRENT_TIME` explicitly disables automatic profile policies
for diagnostics and checks signatures, current trust, timestamps and explicit
OCSP. It does not validate LT/LTA levels. It is incompatible with HISTORICAL.

This is not a complete implementation of the ETSI EN 319 102-1 validation-time-sliding algorithm or a
classification of arbitrary external signatures by baseline level.

## Historical validation

```c
libssig_verify_params params = {
    .data = signed_data,
    .data_len = signed_len,
    .options = LIBSSIG_VERIFY_SYSTEM_TRUST |
               LIBSSIG_VERIFY_TSA_SYSTEM_TRUST,
};
libssig_verify_result result = {0};
libssig_status status = libssig_verify(&params, &result);
/* Inspect signature_valid, trusted and each signer's history separately. */
libssig_verify_free(&result);
```

Both document and TSA trust must be explicitly configured (custom roots or the
system store). No embedded certificate becomes a trust anchor. The policy:

- Validates the signature timestamp's chain at its authenticated generation
  time and uses that time for the document chain. A signed `signingTime`
  attribute is never a substitute for a trusted TSA.
- Requires a valid archive timestamp, with an exact archive hash index for
  CAdES, or a final PDF document timestamp covering the DSS and document
  signature. Evidence added after that proof is not used historically.
- Requires authenticated OCSP or a complete direct CRL for every non-anchor
  certificate in the document and signature-TSA chains. Embedded certificates
  in the timestamp are protected with the entire timestamp attribute. External
  intermediates alone are not proof of historical existence.
- Checks OCSP CertID, response signatures, responder authorization and validity
  at issuance, and CRL issuer/signature/key usage. Status evidence must cover
  the archive time (`thisUpdate <= archive <= nextUpdate`); OCSP `producedAt`
  must precede the archive. A missing `nextUpdate` is insufficient under this
  policy. Status issued after the signing time can establish historical status.
- Rejects revocation at/before the signing proof. A later administrative
  revocation can still establish validity at that proof. Key/CA compromise is
  conservatively rejected even when the reported revocation time is later;
  CRL invalidity dates can move the effective revocation earlier.
- Bootstraps the last archive with TSA trust and revocation at the current
  time, also checking its chain at generation. Expired or revoked archive-TSA
  certificates are not rescued by their own claimed timestamp.

`libssig_verify_signer.history` distinguishes valid, incomplete, revoked and
untrusted outcomes. `validation_time` reports the authenticated signing proof;
`revocation_checked` indicates a completed non-revocation decision or an
authenticated revocation finding. `LIBSSIG_ERROR_EVIDENCE` preserves the
cryptographic signature result and indicates missing or unusable evidence.
`trusted` still describes document chain trust, not a successful historical
revocation decision.

When archived status for the latest archive TSA is no longer current, supply
fresh DER OCSP responses or CRLs using `current_revocations` and
`current_revocation_count` (an array of `libssig_revocation_evidence`). These
are authenticated and used only for the current archive-TSA chain. They never
repair missing historical proofs. Automatic LTA verification accepts them without
requiring a HISTORICAL flag. The library performs no HTTP requests.
Current evidence is limited to 1024 objects, 16 MiB each. Historical certificate
and revocation collections are also limited to 1024 objects.

Selected historical verification does not mix with explicit request-bound `ocsp` inputs or
`REQUIRE_OCSP`/`REQUIRE_TSA_OCSP`; those retain their existing current-time
semantics. CAdES mixing archived and non-archived signers currently requires archive
evidence for every signer; otherwise it reports incomplete validation.
Historical PDF support currently requires one document signature
followed by one final document timestamp with no later unsigned revision.
The historical result authenticates the original signed PDF revision; it does
not perform a semantic document-diff analysis or determine whether subsequent
visual/content changes were authorized by that signer.
Archive renewal, multiple preservation generations, algorithm sunset policies,
advanced CRLs and recursive OCSP responder revocation remain unsupported;
insufficient supported evidence fails rather than implying full ETSI validity.
Installation of a root is independent of embedded certificates.

## Tests

The `history` test verifies an expired document signer and expired signature
TSA, revocation before/after the signing proof, compromise, missing/stale
evidence, and fresh current evidence for an older archive. The `ades` test generates all four levels with a local TSA/OCSP responder and
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
