# Pinned external conformance inputs

- `xades/`: ETSI EN 319 132-1 v1.3.1, official Git submodule at
  `01ab58e88086f1b4ec1549cf9905cc63a4b791f7` (tag `v1.3.1`).
- `jades/`: ETSI TS 119 182-1 v1.2.1, official Git submodule at
  `e996a56aeaff4eca5f2c4e35be0ddef81822f889` (tag `v1.2.1`).
- `xmldsig-core-schema.xsd`: unmodified W3C XMLDSig schema imported by ETSI;
  source: https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/xmldsig-core-schema.xsd
  SHA-256: `35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c`.
  The original W3C copyright and software-license notice is retained in the file.

The ETSI repositories provide schemas, not a standalone official conformance
checker. Our CTest runners apply them to generated signatures and run independent
cryptographic checks. Each upstream retains its own license (see its LICENSE).
No network access is performed during CMake configure or CTest execution.

Use `git submodule update --init --recursive` or `git clone --recurse-submodules`.
Keep gitlinks pinned to the tested edition when updating a workflow. The W3C
schema is vendored because ETSI references it by URL rather than including it;
this keeps tests self-contained and preserves the exact normative import.
