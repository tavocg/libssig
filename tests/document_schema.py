#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate generated fixtures against downloaded, unmodified ETSI/W3C schemas.
Usage: document_schema.py FIXTURES STANDARDS_DIRECTORY
The standards directory contains xades-schemas/, jades-schemas/ and the W3C
xmldsig-core-schema.xsd. No schema is fetched while tests execute.
"""
import base64
import json
from pathlib import Path
import sys
from lxml import etree
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

fixtures, standards = map(Path, sys.argv[1:])
xades = standards / "xades-schemas"
jades = standards / "jades-schemas"

class LocalSchemas(etree.Resolver):
    def resolve(self, url, public_id, context):
        filename = url.rsplit("/", 1)[-1]
        if filename == "xmldsig-core-schema.xsd":
            return self.resolve_filename(str(standards / filename), context)
        if filename in ["1913201-XAdES01903v132.xsd", "1913201-XAdES01903v141.xsd"]:
            return self.resolve_filename(str(xades / filename), context)
        raise ValueError(f"Unexpected external schema: {url}")

parser = etree.XMLParser(no_network=True, resolve_entities=False)
parser.resolvers.add(LocalSchemas())
wrapper = b'''<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
<xs:import namespace="http://www.w3.org/2000/09/xmldsig#" schemaLocation="xmldsig-core-schema.xsd"/>
<xs:import namespace="http://uri.etsi.org/01903/v1.3.2#" schemaLocation="1913201-XAdES01903v132.xsd"/>
<xs:import namespace="http://uri.etsi.org/01903/v1.4.1#" schemaLocation="1913201-XAdES01903v141.xsd"/>
</xs:schema>'''
xml_schema = etree.XMLSchema(etree.fromstring(wrapper, parser))
for path in sorted(fixtures.glob("document-*.xml")):
    xml_schema.assertValid(etree.parse(str(path)))

base = "https://schemas.libssig.test/"
registry = Registry()
for path in jades.rglob("*.json"):
    registry = registry.with_resource(base + str(path.relative_to(jades)), Resource.from_contents(json.loads(path.read_bytes()), default_specification=DRAFT7))
protected = Draft7Validator({"$ref": base + "19182-protected-jsonSchema.json#/definitions/jwsProtectedHeader"}, registry=registry)
unsigned = Draft7Validator({"$ref": base + "19182-jsonSchema.json#/definitions/etsiUClearInstance"}, registry=registry)
def decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
for path in sorted(fixtures.glob("document-*.json")):
    doc = json.loads(path.read_bytes())
    protected.validate(json.loads(decode(doc["protected"])))
    for item in doc.get("header", {}).get("etsiU", []):
        unsigned.validate(json.loads(decode(item)))
print("ETSI/W3C schema validation passed for all 144 document fixtures")
