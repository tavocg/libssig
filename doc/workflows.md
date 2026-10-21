# Proposal: selectable standard editions and institutional policies

**Draft for review. No public selector, mask, registry or institutional policy
below is implemented by this document.** The format implementations and private
edition-specific names have already been committed separately.

## Keep the three choices independent

- `format` chooses the container: CAdES, PAdES, XAdES or JAdES.
- A workflow selector chooses a standard and one of its implemented editions.
  That descriptor dispatches to different insertion/extension/verification
  functions; it is not a set of conditionals scattered through one workflow.
- Institutional policy selectors add constraints without changing wire-format
  rules: accepted levels, algorithms, key usage, certification hierarchy, TSA
  accreditation, evidence and preservation requirements.

MICITT v4 is an institutional policy applied to an ETSI format, not an
alternative name for an ETSI format. Other institutions can later supply policies
or register their own format-specific standards/workflows.

## Proposed public representation

A small reusable selector avoids consuming a global bit for every edition ever
published by every institution:

```c
/* Proposed API, not available yet. */
typedef struct {
    const char* standard; /* Registered identifier; borrowed during the call. */
    uint64_t versions;   /* Edition mask scoped to this standard. */
} libssig_workflow_selection;
```

Proposed identifiers include `etsi.en319122-1`, `etsi.en319142-1`,
`etsi.en319132-1`, `etsi.ts119182-1` and `cr.micitt.formatos`. A standard's
version bits have meaning only inside that standard; different standards can
reuse bit positions. This allows additional institutions without exhausting a
single library-wide mask or changing a global institution enum.

Add `workflow` to sign/extend/verify and timestamp parameter structures. For
institutional policies, use a borrowed selector array and a count so that more
than one institution's constraints can apply. Policy constraints intersect;
incompatible constraints are an error, never a silent override.

```c
/* Illustrative usage after approval and implementation. */
const libssig_workflow_selection policies[] = {
    {"cr.micitt.formatos", LIBSSIG_MICITT_V4},
};
libssig_sign_params params = {
    .format = LIBSSIG_FORMAT_XADES,
    .level = LIBSSIG_LEVEL_B_LTA,
    .workflow = {
        .standard = "etsi.en319132-1",
        .versions = LIBSSIG_XADES_V131,
    },
    .policies = policies,
    .policy_count = sizeof(policies) / sizeof(policies[0]),
    /* Existing token, certificate, content, PIN, services and trust fields. */
};
```

## Resolution and defaults

1. `workflow.standard == NULL` chooses the ETSI standard for `format`.
2. `versions == 0` chooses the newest **published, implemented, tested** edition
   in the installed library. No network lookup and no selection of drafts.
3. Sign, extend and timestamp insertion require exactly one explicit edition bit,
   or zero for the default. Multiple bits or bits belonging to another registered
   standard fail with `ERROR_ARGUMENT`. Unknown standards fail with
   `ERROR_UNSUPPORTED`.
4. Verification may accept an explicit mask of allowed editions. It first matches
   structure/declared features and then runs the appropriate validators. Once
   cryptographic/evidence validation fails, it must not try a weaker edition as
   a way to turn failure into success. With zero/default, use the latest compatible
   implemented edition; ambiguous format metadata is not proof of an originating
   edition. Report the edition checked, not an invented edition of origin.
5. Extending a known signature preserves its signed bytes and existing archive
   evidence. If a selected edition requires an incompatible change to already
   signed properties, fail explicitly; a new private-key signature is required.
6. Expose the resolved standard identifier and edition in verification results
   and Sign JSON, separately from level and institutional policy results.

Defaults are pinned in reviewed descriptor tables and may advance with a library
release. Applications needing reproducible output pin an explicit edition mask.
The baseline level remains independently selectable, with B-LTA as today's
library default.

## Private organization

Keep existing public feature directories. Add a shared `workflow.c`/`workflow.h`
resolver directly in `libssig/`; split it only when it gains distinct substantial
responsibilities. Register immutable descriptors with:

- Standard identifier, supported format, edition, mask bit, publication status
  and default priority.
- Dedicated sign, extend, verify and timestamp request/insertion callbacks.
- Supported algorithms, levels, input forms and evidence capabilities.

Current handlers already use `cades_v131`, `pades_v121`, `xades_v131` and
`jades_v121` private names. A later edition gets new functions such as
`libssig_xades_v141_sign` and its own tests. Shared PKCS#11, CMS, XML, JSON,
cryptography, RFC 3161, trust and revocation primitives can remain shared when
semantics are unchanged. Do not clone those primitives just to change a version.

A separate policy descriptor provides pre-sign and post-verification checks.
MICITT v4 must check SNCD document and TSA trust using independently authenticated
national anchors/accreditation configuration; matching names or certificate OIDs
alone is insufficient. Generic system trust is not a substitute for this check.
If national accreditation data is absent, report policy validation as incomplete
or failed, never nationally compliant by default. Keep system trust as the
existing generic default for applications that request no institutional policy.

Initially register built-in descriptors at compile time. A future application
registration API can accept a copied descriptor for another institution; no
implicit plugin loading or downloaded executable workflows are needed.

## Migration and acceptance checks

1. Add selection types, descriptor tables and resolver with the current editions
   as defaults; preserve existing zero-initialized call behavior.
2. Wire the four public operations through the resolver and return resolved
   metadata. Existing generic APIs retain their names.
3. Add MICITT v4 enforcement using configured national trust/accreditation data,
   independently of the wire-format version.
4. Expose optional named selectors in Sign. Translate names to library selectors;
   keep standard decisions in libssig.
5. Test defaults, explicit versions, unknown/conflicting masks and the same input
   across workflows. Demonstrate that two edition descriptors invoke different
   handlers, that rejected evidence never triggers a weaker fallback, and that
   national-policy success cannot come from an unrelated trusted certificate.

This proposal deliberately leaves public structure/flag naming and selector
semantics reviewable before implementation.
