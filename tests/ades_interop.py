# SPDX-License-Identifier: GPL-3.0-or-later
"""Optional independent checks: pyHanko/asn1crypto plus the OpenSSL CLI.
Usage: python ades_interop.py BUILD/tests/ades-fixtures
No network access or personal certificates are required.
"""
import asyncio
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from asn1crypto import algos, cms, core, pem, x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec, SignatureValidationSpec, CertValidationPolicySpec,
    RevocationInfoGatheringSpec, RevinfoOnlineFetchingRule,
)
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, RevocationCheckingPolicy

class Hashes(core.SequenceOf):
    _child_spec = core.OctetString

class HashIndex(core.Sequence):
    _fields = [('algorithm', algos.DigestAlgorithm), ('certs', Hashes),
               ('revocations', Hashes), ('attributes', Hashes)]

root = Path(sys.argv[1]).resolve()
trust = [x509.Certificate.load(pem.unarmor((root / name).read_bytes())[2])
         for name in ['cades-0-0.pem', 'ades-tsa-root.pem']]
policy = CertValidationPolicySpec(
    trust_manager=SimpleTrustManager.build(trust_roots=trust),
    revinfo_policy=CertRevTrustPolicy(RevocationCheckingPolicy.from_legacy('hard-fail')),
)
spec = PdfSignatureValidationSpec(SignatureValidationSpec(
    cert_validation_policy=policy, ts_cert_validation_policy=policy,
    key_usage_settings=KeyUsageConstraints(key_usage=None),
    revinfo_gathering_policy=RevocationInfoGatheringSpec(
        online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY),
))
with (root / 'pades-level-3.pdf').open('rb') as file:
    reader = PdfFileReader(file)
    result = asyncio.run(ades_lta_validation(reader.embedded_signatures[0], spec))
    assert result.ades_subindic.name == 'OK', result
    assert result.oldest_evidence_record_timestamp is not None, result
    assert result.api_status.intact and result.api_status.valid and result.api_status.docmdp_ok
    print('PAdES: pyHanko AdESPassed.OK with a verified evidence-record timestamp')

signed = cms.ContentInfo.load((root / 'ades-level-3.p7m').read_bytes())['content']
signer = signed['signer_infos'][0]
archive_attr = next(a for a in signer['unsigned_attrs'] if a['type'].dotted == '0.4.0.1733.2.4')
token = cms.ContentInfo.load(archive_attr['values'][0].dump())
index_attr = next(a for a in token['content']['signer_infos'][0]['unsigned_attrs']
                  if a['type'].dotted == '0.4.0.19122.1.5')
index_der = index_attr['values'][0].dump()
index = HashIndex.load(index_der)
algorithm = index['algorithm']['algorithm'].native

def digest(data):
    return hashlib.new(algorithm, data).digest()

assert sorted(index['certs'].native) == sorted(digest(c.dump()) for c in signed['certificates'])
assert sorted(index['revocations'].native) == sorted(digest(c.dump()) for c in signed['crls'])
assert sorted(index['attributes'].native) == sorted(
    digest(a['type'].dump() + value.dump())
    for a in signer['unsigned_attrs'] if a is not archive_attr
    for value in a['values']
)
content = signed['encap_content_info']['content'].native
imprint_input = signed['encap_content_info']['content_type'].dump() + digest(content)
for field in ['version', 'sid', 'digest_algorithm', 'signed_attrs', 'signature_algorithm', 'signature']:
    imprint_input += signer[field].dump()
imprint_input += index_der
with tempfile.TemporaryDirectory(prefix='libssig-ats-interop-') as directory:
    path = Path(directory) / 'archive.der'
    path.write_bytes(token.dump())
    subprocess.run(['openssl', 'ts', '-verify', '-token_in', '-in', str(path),
                    '-digest', digest(imprint_input).hex(),
                    '-CAfile', str(root / 'ades-tsa-root.pem')], check=True)
print('CAdES ATSv3: independent hash-index/imprint calculation and OpenSSL verification passed')
