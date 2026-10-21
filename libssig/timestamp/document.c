/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/jades.h>
#include <libssig/services.h>
#include <libssig/xades.h>
#include <openssl/bn.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	libssig_jades     json;
	libssig_xades     xml;
	libssig_signature input;
	bool              jades;
} timestamp_document;
static void document_free(timestamp_document* doc) {
	libssig_jades_free(&doc->json);
	libssig_xades_free(&doc->xml);
	libssig_signature_free(&doc->input);
}
static libssig_status document_read(
    const unsigned char* data,
    size_t               len,
    size_t               index,
    timestamp_document*  doc
) {
	if (index) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	libssig_verify_params params = {.data = data, .data_len = len};
	doc->jades = libssig_document_format(data, len) == LIBSSIG_FORMAT_JADES;
	if (doc->jades) {
		libssig_status status = libssig_jades_read(&params, &doc->json);
		if (status == LIBSSIG_ERROR_CONTENT_REQUIRED) {
			static const unsigned char empty = 0;
			libssig_jades_free(&doc->json);
			params.content = &empty;
			status = libssig_jades_read(&params, &doc->json);
		}
		if (status != LIBSSIG_OK) {
			return status;
		}
		if (doc->json.unsigned_items) {
			return LIBSSIG_ERROR_UNSUPPORTED;
		}
		const char* signature = json_string_value(
		    json_object_get(doc->json.root, "signature")
		);
		return libssig_bytes_append(&doc->input, signature, strlen(signature))
		           ? LIBSSIG_OK
		           : LIBSSIG_ERROR_MEMORY;
	}
	doc->xml.signature_only = true;
	libssig_status status = libssig_xades_read(&params, &doc->xml);
	if (status != LIBSSIG_OK) {
		return status;
	}
	if (doc->xml.unsigned_properties) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_signature signed_info = {0};
	bool ok = libssig_xml_c14n(doc->xml.signed_info, &signed_info) &&
	          libssig_document_signature_check(
	              doc->xml.cert,
	              doc->xml.algo,
	              doc->xml.hash,
	              signed_info.data,
	              signed_info.len,
	              &doc->xml.signature
	          ) &&
	          libssig_xml_c14n(doc->xml.signature_value, &doc->input);
	libssig_signature_free(&signed_info);
	return ok ? LIBSSIG_OK : LIBSSIG_ERROR_VERIFY;
}
libssig_status libssig_document_timestamp_request(
    const libssig_timestamp_request_params* params,
    libssig_signature*                      output
) {
	timestamp_document doc = {0};
	libssig_status     status = document_read(
        params->data,
        params->data_len,
        params->signer_index,
        &doc
    );
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  len = 0;
	if (status == LIBSSIG_OK) {
		status = libssig_document_digest(
		             doc.input.data,
		             doc.input.len,
		             params->hash,
		             digest,
		             &len
		         )
		             ? libssig_ades_query(digest, len, params->hash, output)
		             : LIBSSIG_ERROR_UNSUPPORTED;
	}
	if (status == LIBSSIG_OK && params->policy_oid) {
		ASN1_OBJECT*         policy = OBJ_txt2obj(params->policy_oid, 1);
		const unsigned char* cursor = output->data;
		TS_REQ* query = d2i_TS_REQ(NULL, &cursor, (long)output->len);
		bool    ok = policy && query && TS_REQ_set_policy_id(query, policy);
		unsigned char* der = NULL;
		int            count = ok ? i2d_TS_REQ(query, &der) : 0;
		libssig_signature_free(output);
		status = count > 0 && libssig_bytes_append(output, der, (size_t)count)
		             ? LIBSSIG_OK
		             : LIBSSIG_ERROR_ARGUMENT;
		OPENSSL_free(der);
		TS_REQ_free(query);
		ASN1_OBJECT_free(policy);
	}
	document_free(&doc);
	return status;
}
static bool request_valid(TS_REQ* query, const libssig_signature* input) {
	TS_MSG_IMPRINT*    imprint = TS_REQ_get_msg_imprint(query);
	const ASN1_OBJECT* oid = NULL;
	if (imprint) {
		X509_ALGOR_get0(&oid, NULL, NULL, TS_MSG_IMPRINT_get_algo(imprint));
	}
	const EVP_MD*      md = oid ? EVP_get_digestbyobj(oid) : NULL;
	unsigned char      digest[EVP_MAX_MD_SIZE];
	unsigned int       len = 0;
	ASN1_OCTET_STRING* value = imprint ? TS_MSG_IMPRINT_get_msg(imprint) : NULL;
	const ASN1_INTEGER* nonce = TS_REQ_get_nonce(query);
	BIGNUM*             number = nonce ? ASN1_INTEGER_to_BN(nonce, NULL) : NULL;
	bool valid = md && value && number && !BN_is_negative(number) &&
	             BN_num_bits(number) == 128 && TS_REQ_get_version(query) == 1 &&
	             TS_REQ_get_cert_req(query) &&
	             TS_REQ_get_ext_count(query) == 0 &&
	             EVP_Digest(input->data, input->len, digest, &len, md, NULL) ==
	                 1 &&
	             ASN1_STRING_length(value) == (int)len &&
	             !CRYPTO_memcmp(ASN1_STRING_get0_data(value), digest, len);
	BN_free(number);
	return valid;
}
libssig_status libssig_document_timestamp(
    const libssig_timestamp_params* params,
    libssig_signature*              output
) {
	timestamp_document doc = {0};
	libssig_status     status = document_read(
        params->data,
        params->data_len,
        params->signer_index,
        &doc
    );
	const unsigned char* cursor = params->request;
	TS_REQ* query = d2i_TS_REQ(NULL, &cursor, (long)params->request_len);
	bool    valid = query && cursor == params->request + params->request_len;
	cursor = params->response;
	TS_RESP* reply = d2i_TS_RESP(NULL, &cursor, (long)params->response_len);
	valid = valid && reply && cursor == params->response + params->response_len;
	if (status == LIBSSIG_OK) {
		status = valid && request_valid(query, &doc.input)
		             ? libssig_timestamp_response(params, query, reply)
		             : LIBSSIG_ERROR_VERIFY;
	}
	unsigned char* der = NULL;
	int len = status == LIBSSIG_OK ? i2d_PKCS7(TS_RESP_get_token(reply), &der)
	                               : 0;
	libssig_signature token = {.data = der, .len = len > 0 ? (size_t)len : 0};
	if (status == LIBSSIG_OK && len <= 0) {
		status = LIBSSIG_ERROR_CRYPTO;
	}
	if (status == LIBSSIG_OK && doc.jades) {
		json_t* header = json_pack("{s:[]}", "etsiU");
		if (!header || json_object_set_new(doc.json.root, "header", header)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		doc.json.unsigned_items = json_object_get(
		    json_object_get(doc.json.root, "header"),
		    "etsiU"
		);
		if (status == LIBSSIG_OK &&
		    (!libssig_jades_timestamp_add(&doc.json, "sigTst", &token) ||
		     !libssig_jades_write(doc.json.root, output))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	} else if (status == LIBSSIG_OK) {
		xmlNode* parent = libssig_xml_add(
		    doc.xml.properties->parent,
		    LIBSSIG_XADES132,
		    "UnsignedProperties",
		    NULL
		);
		doc.xml.unsigned_properties = libssig_xml_add(
		    parent,
		    LIBSSIG_XADES132,
		    "UnsignedSignatureProperties",
		    NULL
		);
		if (!doc.xml.unsigned_properties ||
		    !libssig_xades_timestamp_add(&doc.xml, false, &token) ||
		    !libssig_xml_write(doc.xml.xml, output)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	OPENSSL_free(der);
	TS_RESP_free(reply);
	TS_REQ_free(query);
	document_free(&doc);
	return status;
}
