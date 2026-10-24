/* SPDX-License-Identifier: GPL-3.0-or-later */
#define LIBSSIG_ADES_FIXTURE_MAIN document_ades_fixture_original_main
#include "ades_test.c"
#undef LIBSSIG_ADES_FIXTURE_MAIN
#include <libssig/jades.h>
#include <libssig/time.h>
#include <libssig/xades.h>
#include <libxml/parser.h>

libssig_status document_fixture_sign(
    EVP_PKEY*           key,
    X509*               cert,
    libssig_sign_params params,
    libssig_signature*  output
);

static X509* document_cert_create(EVP_PKEY* key) {
	X509* cert = X509_new();
	bool  ok = cert && X509_set_version(cert, 2) &&
	          ASN1_INTEGER_set(X509_get_serialNumber(cert), 42) &&
	          X509_gmtime_adj(X509_getm_notBefore(cert), -3600) &&
	          X509_gmtime_adj(X509_getm_notAfter(cert), 86400) &&
	          X509_set_pubkey(cert, key) &&
	          X509_NAME_add_entry_by_txt(
	              X509_get_subject_name(cert),
	              "CN",
	              MBSTRING_ASC,
	              (const unsigned char*)"Document signer",
	              -1,
	              -1,
	              0
	          ) &&
	          X509_set_issuer_name(cert, X509_get_subject_name(root)) &&
	          extension_add(cert, NID_basic_constraints, "critical,CA:FALSE") &&
	          extension_add(
	              cert,
	              NID_key_usage,
	              "critical,digitalSignature,nonRepudiation"
	          ) &&
	          extension_add(
	              cert,
	              NID_info_access,
	              "OCSP;URI:http://test/ocsp"
	          ) &&
	          X509_sign(cert, root_key, EVP_sha256());
	if (!ok) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}
static int verify_check(
    const libssig_signature* bytes,
    libssig_verify_params    trust,
    libssig_format           format,
    libssig_level            level,
    bool                     detached,
    const unsigned char*     content,
    size_t                   content_len
) {
	trust.data = bytes->data;
	trust.data_len = bytes->len;
	trust.content = detached ? content : NULL;
	trust.content_len = detached ? content_len : 0;
	libssig_verify_result result = {0};
	libssig_status        status = libssig_verify(&trust, &result);
	if (status != LIBSSIG_OK) {
		fprintf(
		    stderr,
		    "document verify format=%d level=%d status=%d\n",
		    format,
		    level,
		    status
		);
	}
	CHECK(
	    status == LIBSSIG_OK && result.count == 1 && result.signature_valid &&
	    result.trusted && result.format == format && result.detached == detached
	);
	CHECK(
	    result.signers[0].level == level && result.signers[0].level_detected &&
	    result.signers[0].level_validated
	);
	time_t signed_at;
	CHECK(
	    libssig_verify_time_parse(result.signers[0].signing_time, &signed_at)
	);
	CHECK(signed_at > time(NULL) - 86400 && signed_at <= time(NULL) + 5);
	CHECK(result.signers[0].anchor.source == LIBSSIG_TRUST_FALLBACK);
	CHECK(result.signers[0].timestamp.present == (level != LIBSSIG_LEVEL_B_B));
	if (level != LIBSSIG_LEVEL_B_B) {
		CHECK(
		    result.signers[0].timestamp.anchor.source == LIBSSIG_TRUST_FALLBACK
		);
	}
	CHECK(result.signers[0].archive.present == (level == LIBSSIG_LEVEL_B_LTA));
	libssig_verify_free(&result);
	if (detached) {
		static const unsigned char different[] = "tampered";
		trust.content = different;
		trust.content_len = sizeof(different) - 1;
		CHECK(libssig_verify(&trust, &result) != LIBSSIG_OK);
		libssig_verify_free(&result);
	}
	return 0;
}
static int timestamp_api_check(
    const libssig_signature* baseline,
    libssig_verify_params    trust,
    bool                     detached,
    const unsigned char*     content,
    size_t                   content_len,
    libssig_format           format
) {
	libssig_timestamp_request_params request_params = {
	    .data = baseline->data,
	    .data_len = baseline->len,
	    .hash = LIBSSIG_HASH_SHA384,
	    .policy_oid = "1.2.3.4.1"
	};
	libssig_signature request = {0};
	CHECK(libssig_timestamp_request(&request_params, &request) == LIBSSIG_OK);
	TS_RESP* reply = response_create(&request, false);
	buffer   response = response_encode(reply);
	CHECK(reply && response.data);
	libssig_timestamp_params params = {
	    .data = baseline->data,
	    .data_len = baseline->len,
	    .request = request.data,
	    .request_len = request.len,
	    .response = response.data,
	    .response_len = response.len,
	    .fallback_ca_data = trust.tsa_fallback_ca_data,
	    .fallback_ca_data_len = trust.tsa_fallback_ca_data_len,
	    .options = trust.options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
	                   ? LIBSSIG_TIMESTAMP_SYSTEM_TRUST
	                   : 0,
	    .ca_data = trust.tsa_ca_data,
	    .ca_data_len = trust.tsa_ca_data_len
	};
	libssig_signature stamped = {0};
	libssig_status    status = libssig_timestamp(&params, &stamped);
	if (status != LIBSSIG_OK) {
		fprintf(
		    stderr,
		    "timestamp API format=%d detached=%d status=%d\n",
		    format,
		    detached,
		    status
		);
	}
	CHECK(status == LIBSSIG_OK);
	CHECK(
	    verify_check(
	        &stamped,
	        trust,
	        format,
	        LIBSSIG_LEVEL_B_T,
	        detached,
	        content,
	        content_len
	    ) == 0
	);
	libssig_signature_free(&stamped);
	const unsigned char* cursor = request.data;
	TS_REQ*              changed = d2i_TS_REQ(NULL, &cursor, (long)request.len);
	CHECK(changed);
	BIGNUM* number = ASN1_INTEGER_to_BN(TS_REQ_get_nonce(changed), NULL);
	CHECK(number && BN_add_word(number, 1));
	ASN1_INTEGER* nonce = BN_to_ASN1_INTEGER(number, NULL);
	CHECK(nonce && TS_REQ_set_nonce(changed, nonce));
	unsigned char* different = NULL;
	int            different_len = i2d_TS_REQ(changed, &different);
	CHECK(different_len > 0);
	params.request = different;
	params.request_len = (size_t)different_len;
	CHECK(libssig_timestamp(&params, &stamped) != LIBSSIG_OK && !stamped.data);
	OPENSSL_free(different);
	ASN1_INTEGER_free(nonce);
	BN_free(number);
	TS_REQ_free(changed);
	libssig_signature_free(&request);
	free(response.data);
	TS_RESP_free(reply);
	return 0;
}
static int negative_check_document(
    const libssig_signature* source,
    libssig_verify_params    trust,
    libssig_format           format
) {
	trust.data = source->data;
	trust.data_len = source->len;
	libssig_verify_result result = {0};
	libssig_signature     altered = {0};
	if (format == LIBSSIG_FORMAT_JADES) {
		json_t* root = json_loadb(
		    (char*)source->data,
		    source->len,
		    JSON_REJECT_DUPLICATES,
		    NULL
		);
		CHECK(root);
		json_object_set_new(root, "payload", json_string("dGFtcGVyZWQ"));
		CHECK(libssig_jades_v121_write(root, &altered));
		json_decref(root);
	} else {
		xmlDoc* xml = xmlReadMemory(
		    (char*)source->data,
		    (int)source->len,
		    NULL,
		    NULL,
		    XML_PARSE_NONET
		);
		CHECK(xml);
		xmlNode* root = xmlDocGetRootElement(xml);
		xmlNode* object = libssig_xml_child(
		    root,
		    "SignedInfo",
		    LIBSSIG_XMLDSIG
		);
		xmlNode*
		    duplicate = xmlNewChild(object, root->ns, BAD_CAST "Object", NULL);
		CHECK(
		    duplicate &&
		    xmlNewProp(duplicate, BAD_CAST "Id", BAD_CAST "SignedProperties")
		);
		CHECK(libssig_xml_write(xml, &altered));
		xmlFreeDoc(xml);
	}
	trust.data = altered.data;
	trust.data_len = altered.len;
	CHECK(libssig_verify(&trust, &result) != LIBSSIG_OK);
	libssig_verify_free(&result);
	libssig_signature_free(&altered);
	if (format == LIBSSIG_FORMAT_JADES) {
		json_t* root = json_loadb(
		    (char*)source->data,
		    source->len,
		    JSON_REJECT_DUPLICATES,
		    NULL
		);
		json_t* items = json_object_get(
		    json_object_get(root, "header"),
		    "etsiU"
		);
		CHECK(items && json_array_size(items) >= 3);
		CHECK(json_array_remove(items, 1) == 0);
		CHECK(libssig_jades_v121_write(root, &altered));
		json_decref(root);
	} else {
		xmlDoc* xml = xmlReadMemory(
		    (char*)source->data,
		    (int)source->len,
		    NULL,
		    NULL,
		    XML_PARSE_NONET
		);
		CHECK(xml);
		xmlNode* node = libssig_xml_child(
		    libssig_xml_child(
		        libssig_xml_child(
		            libssig_xml_child(
		                xmlDocGetRootElement(xml),
		                "Object",
		                LIBSSIG_XMLDSIG
		            ),
		            "QualifyingProperties",
		            LIBSSIG_XADES132
		        ),
		        "UnsignedProperties",
		        LIBSSIG_XADES132
		    ),
		    "UnsignedSignatureProperties",
		    LIBSSIG_XADES132
		);
		/* There are two ds:Object elements. Resolve the qualifying one
		 * explicitly. */
		if (!node) {
			for (xmlNode* n = xmlDocGetRootElement(xml)->children; n;
			     n = n->next) {
				xmlNode* q = libssig_xml_child(
				    n,
				    "QualifyingProperties",
				    LIBSSIG_XADES132
				);
				if (q) {
					node = libssig_xml_child(
					    libssig_xml_child(
					        q,
					        "UnsignedProperties",
					        LIBSSIG_XADES132
					    ),
					    "UnsignedSignatureProperties",
					    LIBSSIG_XADES132
					);
				}
			}
		}
		xmlNode* evidence = libssig_xml_child(
		    node,
		    "AnyValidationData",
		    LIBSSIG_XADES141
		);
		CHECK(evidence);
		xmlUnlinkNode(evidence);
		xmlFreeNode(evidence);
		CHECK(libssig_xml_write(xml, &altered));
		xmlFreeDoc(xml);
	}
	trust.data = altered.data;
	trust.data_len = altered.len;
	CHECK(libssig_verify(&trust, &result) != LIBSSIG_OK);
	libssig_verify_free(&result);
	libssig_signature_free(&altered);
	static const unsigned char bad_xml
	    [] = "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>";
	trust.data = bad_xml;
	trust.data_len = sizeof(bad_xml) - 1;
	CHECK(libssig_verify(&trust, &result) != LIBSSIG_OK);
	libssig_verify_free(&result);
	static const unsigned char bad_json
	    [] = "{\"protected\":\"a\",\"protected\":\"b\",\"signature\":\"\"}";
	trust.data = bad_json;
	trust.data_len = sizeof(bad_json) - 1;
	CHECK(libssig_verify(&trust, &result) == LIBSSIG_ERROR_FORMAT);
	libssig_verify_free(&result);
	return 0;
}

static int parser_mutations_check(
    const libssig_signature* source,
    libssig_verify_params    trust
) {
	unsigned char* bytes = malloc(source->len);
	CHECK(bytes);
	unsigned int seed = 0x712344u;
	for (size_t i = 0; i < 300; ++i) {
		memcpy(bytes, source->data, source->len);
		seed = 1664525u * seed + 1013904223u;
		size_t pos = seed % source->len;
		bytes[pos] ^= (unsigned char)(1u << (i % 8));
		trust.data = bytes;
		trust.data_len = i % 3 ? source->len : pos;
		libssig_verify_result result = {0};
		libssig_status        status = libssig_verify(&trust, &result);
		CHECK(status >= LIBSSIG_OK && status <= LIBSSIG_ERROR_EVIDENCE);
		libssig_verify_free(&result);
	}
	free(bytes);
	return 0;
}

int main(int argc, char** argv) {
	CHECK(unsetenv("NIX_SSL_CERT_FILE") == 0);
	CHECK(
	    setenv("SSL_CERT_FILE", "/nonexistent-libssig-document-root", 1) == 0
	);
	CHECK(setenv("SSL_CERT_DIR", "/nonexistent-libssig-document-dir", 1) == 0);
	CHECK(argc == 2);
	directory = argv[1];
	root_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	tsa_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	CHECK(root_key && tsa_key);
	root = certificate_create(root_key, true);
	tsa = certificate_create(tsa_key, false);
	CHECK(
	    root && tsa &&
	    extension_add(tsa, NID_info_access, "OCSP;URI:http://test/ocsp") &&
	    X509_sign(tsa, root_key, EVP_sha256())
	);
	BIO* pem = BIO_new(BIO_s_mem());
	CHECK(pem && PEM_write_bio_X509(pem, root));
	char* root_bytes = NULL;
	long  root_len = BIO_get_mem_data(pem, &root_bytes);
	CHECK(root_len > 0);
	CHECK(
	    file_write(
	        "document-tsa-root.pem",
	        (unsigned char*)root_bytes,
	        (size_t)root_len
	    ) == 0
	);
	libssig_verify_params trust = {
	    .fallback_ca_data = (unsigned char*)root_bytes,
	    .fallback_ca_data_len = (size_t)root_len,
	    .tsa_fallback_ca_data = (unsigned char*)root_bytes,
	    .tsa_fallback_ca_data_len = (size_t)root_len,
	    .options = LIBSSIG_VERIFY_SYSTEM_TRUST | LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
	};
	libssig_sign_services services =
	    {.exchange = exchange, .tsa_url = "http://test/tsa", .trust = &trust};
	const unsigned char content[] = {0, 1, 0xff, '<', '&', '"', 0};
	libssig_level       levels[] = {
        LIBSSIG_LEVEL_B_B,
        LIBSSIG_LEVEL_B_T,
        LIBSSIG_LEVEL_B_LT,
        LIBSSIG_LEVEL_B_LTA
    };
	for (int algo = 0; algo < 3; ++algo) {
		for (int hash = 0; hash < 3; ++hash) {
			const char* curves[] = {"prime256v1", "secp384r1", "secp521r1"};
			EVP_PKEY*
			    key = algo == 2
			              ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", curves[hash])
			              : EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
			CHECK(key);
			X509* cert = document_cert_create(key);
			CHECK(cert);
			char cert_name[80];
			snprintf(
			    cert_name,
			    sizeof(cert_name),
			    "document-cert-%d-%d.pem",
			    algo,
			    hash
			);
			BIO* cert_pem = BIO_new(BIO_s_mem());
			CHECK(cert_pem && PEM_write_bio_X509(cert_pem, cert));
			char* cert_bytes = NULL;
			long  cert_len = BIO_get_mem_data(cert_pem, &cert_bytes);
			CHECK(
			    cert_len > 0 && file_write(
			                        cert_name,
			                        (unsigned char*)cert_bytes,
			                        (size_t)cert_len
			                    ) == 0
			);
			BIO_free(cert_pem);
			for (int f = 0; f < 2; ++f) {
				for (int detached = 0; detached < 2; ++detached) {
					for (size_t l = 0; l < 4; ++l) {
						libssig_format      format = f ? LIBSSIG_FORMAT_XADES
						                               : LIBSSIG_FORMAT_JADES;
						libssig_sign_params params = {
						    .data = content,
						    .data_len = sizeof(content),
						    .algo = (libssig_algo)algo,
						    .hash = (libssig_hash)hash,
						    .format = format,
						    .level = levels[l],
						    .services = &services,
						    .mime_type = "application/octet-stream",
						    .options = detached ? LIBSSIG_SIGN_DETACHED : 0
						};
						libssig_signature output = {0};
						timestamp_calls = ocsp_calls = 0;
						libssig_status status = document_fixture_sign(
						    key,
						    cert,
						    params,
						    &output
						);
						if (status != LIBSSIG_OK) {
							fprintf(
							    stderr,
							    "document sign algo=%d hash=%d f=%d d=%d l=%zu "
							    "status=%d\n",
							    algo,
							    hash,
							    f,
							    detached,
							    l,
							    status
							);
						}
						CHECK(status == LIBSSIG_OK && output.data);
						CHECK(timestamp_calls == (l == 0 ? 0 : l == 3 ? 2 : 1));
						CHECK(
						    verify_check(
						        &output,
						        trust,
						        format,
						        levels[l],
						        detached,
						        content,
						        sizeof(content)
						    ) == 0
						);
						char name[120];
						snprintf(
						    name,
						    sizeof(name),
						    "document-%d-%d-%d-%d-%zu.%s",
						    algo,
						    hash,
						    f,
						    detached,
						    l,
						    f ? "xml" : "json"
						);
						CHECK(file_write(name, output.data, output.len) == 0);
						if (algo == 0 && hash == 0 && l == 0) {
							CHECK(
							    timestamp_api_check(
							        &output,
							        trust,
							        detached,
							        content,
							        sizeof(content),
							        format
							    ) == 0
							);
						}
						if (algo == 0 && hash == 0 && l == 3 && !detached) {
							CHECK(parser_mutations_check(&output, trust) == 0);
							CHECK(
							    negative_check_document(
							        &output,
							        trust,
							        format
							    ) == 0
							);
						}
						if (algo == 0 && hash == 0 && l == 3) {
							libssig_extend_params renew = {
							    .data = output.data,
							    .data_len = output.len,
							    .content = detached ? content : NULL,
							    .content_len = detached ? sizeof(content) : 0,
							    .services = &services
							};
							libssig_signature renewed = {0};
							CHECK(
							    libssig_extend(&renew, &renewed) == LIBSSIG_OK
							);
							CHECK(
							    verify_check(
							        &renewed,
							        trust,
							        format,
							        LIBSSIG_LEVEL_B_LTA,
							        detached,
							        content,
							        sizeof(content)
							    ) == 0
							);
							libssig_signature_free(&renewed);
						}
						if (algo == 0 && hash == 0 && l == 0) {
							libssig_sign_params empty = params;
							empty.data = NULL;
							empty.data_len = 0;
							libssig_signature empty_output = {0};
							CHECK(
							    document_fixture_sign(
							        key,
							        cert,
							        empty,
							        &empty_output
							    ) == LIBSSIG_OK
							);
							static const unsigned char present_empty = 0;
							CHECK(
							    verify_check(
							        &empty_output,
							        trust,
							        format,
							        LIBSSIG_LEVEL_B_B,
							        detached,
							        &present_empty,
							        0
							    ) == 0
							);
							libssig_signature_free(&empty_output);
						}
						if (l == 0) {
							libssig_extend_params extend = {
							    .data = output.data,
							    .data_len = output.len,
							    .content = detached ? content : NULL,
							    .content_len = detached ? sizeof(content) : 0,
							    .services = &services
							};
							libssig_signature extended = {0};
							CHECK(
							    libssig_extend(&extend, &extended) == LIBSSIG_OK
							);
							CHECK(
							    verify_check(
							        &extended,
							        trust,
							        format,
							        LIBSSIG_LEVEL_B_LTA,
							        detached,
							        content,
							        sizeof(content)
							    ) == 0
							);
							libssig_signature_free(&extended);
						}
						libssig_signature_free(&output);
					}
				}
			}
			X509_free(cert);
			EVP_PKEY_free(key);
		}
	}
	CHECK(file_write("document-content.bin", content, sizeof(content)) == 0);
	BIO_free(pem);
	X509_free(tsa);
	X509_free(root);
	EVP_PKEY_free(tsa_key);
	EVP_PKEY_free(root_key);
	return 0;
}
