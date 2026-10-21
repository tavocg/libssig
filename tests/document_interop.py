#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent JWS/XMLDSig and RFC 3161 verification (cryptography + lxml)."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from lxml import etree

NS = {"ds": "http://www.w3.org/2000/09/xmldsig#", "x": "http://uri.etsi.org/01903/v1.3.2#", "v": "http://uri.etsi.org/01903/v1.4.1#"}

def b64(text):
    return base64.b64decode(text, validate=True)

def url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def canonical(node):
    # Fixtures use no xml:base, xml:id or inherited xml:* attributes: C14N 1.0
    # and C14N 1.1 have the same output for these generated documents.
    return etree.tostring(node, method="c14n", exclusive=False, with_comments=False)

def crypto(cert, algorithm, hash_name, signature, data):
    digest = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}[hash_name]()
    key = cert.public_key()
    if algorithm == "ES":
        half = len(signature) // 2
        der = encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))
        key.verify(der, data, ec.ECDSA(digest))
    else:
        scheme = padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size) if algorithm == "PS" else padding.PKCS1v15()
        key.verify(signature, data, scheme, digest)

def timestamp(token, data, root, work):
    (work / "token.der").write_bytes(token)
    (work / "imprint.bin").write_bytes(data)
    subprocess.run(["openssl", "ts", "-verify", "-token_in", "-in", str(work / "token.der"), "-data", str(work / "imprint.bin"), "-CAfile", str(root)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def json_verify(path, content, root, work):
    doc = json.loads(path.read_bytes())
    header = json.loads(url(doc["protected"]))
    payload = doc.get("payload", base64.urlsafe_b64encode(content).decode().rstrip("="))
    assert url(payload) == content
    cert = x509.load_der_x509_certificate(b64(header["x5c"][0]))
    assert isinstance(header["iat"], int)
    alg = header["alg"]
    crypto(cert, alg[:2], alg[2:], url(doc["signature"]), (doc["protected"] + "." + payload).encode())
    unsigned = doc.get("header", {}).get("etsiU", [])
    for i, raw in enumerate(unsigned):
        item = json.loads(url(raw))
        for kind in ["sigTst", "arcTst"]:
            if kind not in item:
                continue
            data = doc["signature"].encode() if kind == "sigTst" else (payload + "." + doc["protected"] + "." + doc["signature"] + "." + "".join(unsigned[:i])).encode()
            timestamp(b64(item[kind]["tstTokens"][0]["val"]), data, root, work)

def xml_verify(path, content, root, work):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    doc = etree.fromstring(path.read_bytes(), parser)
    info = doc.find("ds:SignedInfo", NS)
    signature = doc.find("ds:SignatureValue", NS)
    keyinfo = doc.find("ds:KeyInfo", NS)
    properties = doc.find("ds:Object/x:QualifyingProperties/x:SignedProperties", NS)
    cert = x509.load_der_x509_certificate(b64(keyinfo.find("ds:X509Data/ds:X509Certificate", NS).text))
    algorithm = info.find("ds:SignatureMethod", NS).get("Algorithm")
    alg = "ES" if "ecdsa" in algorithm else "PS" if "MGF1" in algorithm else "RS"
    bits = next(bits for bits in ["256", "384", "512"] if bits in algorithm)
    crypto(cert, alg, bits, b64(signature.text), canonical(info))
    object_node = doc.find("ds:Object[@Id='Content']", NS)
    if object_node is not None:
        assert b64(object_node.text or "") == content
    refs = info.findall("ds:Reference", NS)
    assert len(refs) == 2
    for ref in refs:
        data = canonical(properties) if ref.get("Type") else content
        digest_uri = ref.find("ds:DigestMethod", NS).get("Algorithm")
        bits = next(bits for bits in ["256", "384", "512"] if bits in digest_uri)
        assert hashlib.new("sha" + bits, data).digest() == b64(ref.find("ds:DigestValue", NS).text)
    unsigned = doc.find("ds:Object/x:QualifyingProperties/x:UnsignedProperties/x:UnsignedSignatureProperties", NS)
    if unsigned is not None:
        for i, node in enumerate(unsigned):
            kind = etree.QName(node).localname
            if kind not in ["SignatureTimeStamp", "ArchiveTimeStamp"]:
                continue
            data = canonical(signature)
            if kind == "ArchiveTimeStamp":
                data = content + canonical(properties) + canonical(info) + canonical(signature) + canonical(keyinfo)
                data += b"".join(canonical(n) for n in list(unsigned)[:i])
                if object_node is not None:
                    data += canonical(object_node)
            timestamp(b64(node.find("x:EncapsulatedTimeStamp", NS).text), data, root, work)

def main():
    fixtures = Path(sys.argv[1])
    content = (fixtures / "document-content.bin").read_bytes()
    root = fixtures / "document-tsa-root.pem"
    paths = sorted(fixtures.glob("document-*.json")) + sorted(fixtures.glob("document-*.xml"))
    assert len(paths) == 144, len(paths)
    with tempfile.TemporaryDirectory(prefix="libssig-document-interop-") as temp:
        for path in paths:
            (json_verify if path.suffix == ".json" else xml_verify)(path, content, root, Path(temp))
    print(f"Independent verification passed: {len(paths)} documents, signatures and RFC 3161 timestamps")

if __name__ == "__main__":
    main()
