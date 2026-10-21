# Implemented standards and MICITT v4

Reference editions (published editions, excluding drafts):

| Format | Edition | Implemented baseline levels |
| --- | --- | --- |
| CAdES | [EN 319 122-1 v1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf) | B-B, B-T, B-LT, B-LTA |
| PAdES | [EN 319 142-1 v1.2.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf) | B-B, B-T, B-LT, B-LTA |
| XAdES | [EN 319 132-1 v1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf) | B-B, B-T, B-LT, B-LTA |
| JAdES | [TS 119 182-1 v1.2.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf) | B-B, B-T, B-LT, B-LTA |

These are supported generation profiles, not a claim to accept every legal
serialization, transform, optional property or preservation scenario in these
standards. Unknown/unsupported forms fail explicitly. Structural and independent
cryptographic tests provide implementation evidence; they are not third-party
certification of complete ETSI or legal conformity.

## MICITT minimum

[Política de Formatos Oficiales v4.0, 2025-09-09](https://mifirmadigital.micitt.go.cr/docs/normativa/DCFD-Politica-de-Formato-Oficiales.-v4-firmado.pdf),
OID `2.16.188.1.1.1.2.1`, is reviewed separately from the format specifications.
The document distinguishes LT from archive-based LTA. LTA remains libssig's
default at the application's request; B-B or B-T alone are not represented as
meeting the national long-term format policy.

| Policy requirement | Implementation and application responsibility |
| --- | --- |
| Article 5.1: recognized format and long-term evidence | Four native AdES containers, LT evidence and archive timestamps at LTA |
| 5.2.1: signature and signer's certificate | Actual PKCS#11 signature; embedded X.509 certificate bound to the signed information |
| 5.2.1/5.2.2: trusted time evidence | Nonce-bound RFC 3161 requests; TSA signature, ESS binding, EKU, imprint, time and chain checks |
| 5.2.1/5.2.2: certification paths | Chain building and evidence collection for signer and TSAs; roots are explicit application trust, never trusted because embedded |
| 5.2.1/5.2.2: certificate status | Authenticated OCSP or complete direct CRL evidence for non-root chain members; unavailable/revoked evidence fails LT/LTA |
| 5.2.2: historically usable evidence | Archive integrity and bounded historical validation; current chain and revocation required for the latest archive TSA |
| 5.2.4: later addition of evidence | `libssig_extend` needs no private key; upgrades only if evidence and service validation succeeds |

**National hierarchy is a trust policy, not a property of the container.**
For national acceptance, callers must configure document and TSA roots belonging
to Costa Rica's SNCD, use registered signer/TSA certificates, and satisfy the
applicable certificate/signing policy. Generic system trust can include unrelated
foreign roots and does not establish SNCD membership. Do not infer national
compliance from `LIBSSIG_OK`, `level_detected`, or an OID alone. The library
ships neither personal certificates nor a hardcoded national trust bundle.

## Verification evidence

- CAdES: independent ASN.1 hash-index and archive-imprint recomputation, followed
  by OpenSSL verification of the RFC 3161 token.
- PAdES: pyHanko AdES LTA validation with a verified evidence record, in addition
  to OpenSSL CMS verification and internal PDF byte-range/DSS checks.
- XAdES/JAdES: 144 generated combinations, independent signature/imprint checks,
  OpenSSL timestamp validation, and validation against unmodified official
  ETSI XML/JSON schemas (plus W3C XMLDSig). XMLSec also verifies XMLDSig output.
- Negative and sanitizer checks cover content/evidence alteration and parser
  rejection paths. No private certificates or physical card are used in CI.

## Current scope

XAdES accepts the supported enveloping or detached two-reference profile;
XML enveloped signatures, arbitrary XPath/XSLT, manifests, countersignatures and
distributed properties are not implemented. JAdES uses flattened serialization,
base64 payload and base64url unsigned-entry incorporation; general multi-signer,
compact, unencoded payload, sigD and clear-entry/JCS forms are not implemented.
CAdES/PAdES retain the restrictions listed in [profiles](profiles.md), including
one document signature in generated PDFs. All four formats support timely
archive renewal; generation requires the preceding TSA chains to remain
currently valid. Unsupported evidence such as delta/indirect CRLs is rejected.

The historical policy is bounded, not a complete EN 319 102-1 validation engine:
it does not implement arbitrary time sliding after every TSA expires. Long-term
preservation requires timely archive renewal, appropriate algorithms, trusted
services, retained evidence and an application preservation process. National
policy enforcement and version selection are proposed separately for review;
no unchecked selector can turn unsupported behavior into a conformant result.

## Private workflow names

Edition-dependent entry points are private and named explicitly:
`libssig_cades_v131_sign/extend/verify`, `libssig_pades_v121_sign/extend/verify`,
`libssig_xades_v131_sign/extend/verify` and
`libssig_jades_v121_sign/extend/verify`. Archive and qualifying-property helpers
carry the corresponding edition prefix as well. Shared CMS/RFC 3161, cryptography,
trust, revocation, byte and transport services remain independent of this naming.
Public functions remain `libssig_sign`, `libssig_extend`, `libssig_verify` and
the timestamp APIs. Public version-selection masks are not implemented yet.

The unimplemented selector design is available in [the workflow proposal](workflows.md) for review.
