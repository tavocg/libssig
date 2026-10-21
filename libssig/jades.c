/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/jades.h>
#include <stdlib.h>
#include <string.h>

void libssig_jades_free(libssig_jades* doc) {
	json_decref(doc->root);
	json_decref(doc->protected);
	free(doc->payload);
	X509_free(doc->cert);
	libssig_signature_free(&doc->signature);
	libssig_validation_free(&doc->evidence);
	*doc = (libssig_jades){0};
}
bool libssig_jades_write(json_t* value, libssig_signature* bytes) {
	char* text = value ? json_dumps(value, JSON_COMPACT | JSON_ENSURE_ASCII)
	                   : NULL;
	bool  ok = text && libssig_bytes_append(bytes, text, strlen(text));
	free(text);
	return ok;
}
static const char* algs[3][3] = {
    {"RS256", "RS384", "RS512"},
    {"PS256", "PS384", "PS512"},
    {"ES256", "ES384", "ES512"}
};
const char* libssig_jades_alg_name(libssig_algo algo, libssig_hash hash) {
	return algo >= 0 && algo <= LIBSSIG_ALGO_ECDSA && hash >= 0 &&
	               hash <= LIBSSIG_HASH_SHA512
	           ? algs[algo][hash]
	           : NULL;
}
libssig_status libssig_jades_alg(
    const char*   name,
    X509*         cert,
    libssig_algo* algo,
    libssig_hash* hash
) {
	if (!name) {
		return LIBSSIG_ERROR_FORMAT;
	}
	for (int i = 0; i < 3; ++i) {
		for (int j = 0; j < 3; ++j) {
			if (!strcmp(name, algs[i][j])) {
				*algo = (libssig_algo)i;
				*hash = (libssig_hash)j;
				EVP_PKEY* key = X509_get_pubkey(cert);
				bool valid = key && EVP_PKEY_is_a(key, i == 2 ? "EC" : "RSA");
				if (valid && i == 2) {
					char        group[80];
					size_t      len = 0;
					const char* groups[] =
					    {"prime256v1", "secp384r1", "secp521r1"};
					valid = EVP_PKEY_get_utf8_string_param(
					            key,
					            "group",
					            group,
					            sizeof(group),
					            &len
					        ) > 0 &&
					        !strcmp(group, groups[j]);
				}
				EVP_PKEY_free(key);
				return valid ? LIBSSIG_OK : LIBSSIG_ERROR_UNSUPPORTED;
			}
		}
	}
	return LIBSSIG_ERROR_UNSUPPORTED;
}
json_t* libssig_jades_item(json_t* value) {
	const char*       text = json_string_value(value);
	libssig_signature bytes = {0};
	if (!text ||
	    !libssig_base64_read(text, json_string_length(value), true, &bytes)) {
		return NULL;
	}
	json_t* item = json_loadb(
	    (char*)bytes.data,
	    bytes.len,
	    JSON_REJECT_DUPLICATES,
	    NULL
	);
	libssig_signature_free(&bytes);
	return item;
}
bool libssig_jades_add(libssig_jades* doc, json_t* value) {
	libssig_signature bytes = {0};
	bool              ok = libssig_jades_write(value, &bytes);
	char*   text = ok ? libssig_base64(bytes.data, bytes.len, true) : NULL;
	json_t* encoded = text ? json_string(text) : NULL;
	ok = encoded && json_array_append(doc->unsigned_items, encoded) == 0;
	json_decref(encoded);
	json_decref(value);
	free(text);
	libssig_signature_free(&bytes);
	return ok;
}
json_t* libssig_jades_pki(const libssig_signature* bytes) {
	char*   text = libssig_base64(bytes->data, bytes->len, false);
	json_t* value = text ? json_pack("{s:s}", "val", text) : NULL;
	free(text);
	return value;
}
bool libssig_jades_pki_read(json_t* value, libssig_signature* bytes) {
	const char* text = json_string_value(json_object_get(value, "val"));
	return text && json_object_size(value) == 1 &&
	       libssig_base64_read(text, strlen(text), false, bytes);
}
bool libssig_jades_timestamp_read(json_t* value, libssig_signature* token) {
	json_t* tokens = json_object_get(value, "tstTokens");
	return json_object_size(value) == 1 && json_array_size(tokens) == 1 &&
	       libssig_jades_pki_read(json_array_get(tokens, 0), token);
}
bool libssig_jades_input(const libssig_jades* doc, libssig_signature* bytes) {
	const char* header = json_string_value(
	    json_object_get(doc->root, "protected")
	);
	return header && libssig_bytes_append(bytes, header, strlen(header)) &&
	       libssig_bytes_append(bytes, ".", 1) &&
	       libssig_bytes_append(bytes, doc->payload, strlen(doc->payload));
}
bool libssig_jades_archive_input(
    const libssig_jades* doc,
    size_t               count,
    libssig_signature*   bytes
) {
	const char* header = json_string_value(
	    json_object_get(doc->root, "protected")
	);
	const char* sig = json_string_value(
	    json_object_get(doc->root, "signature")
	);
	bool ok = header && sig &&
	          libssig_bytes_append(bytes, doc->payload, strlen(doc->payload)) &&
	          libssig_bytes_append(bytes, ".", 1) &&
	          libssig_bytes_append(bytes, header, strlen(header)) &&
	          libssig_bytes_append(bytes, ".", 1) &&
	          libssig_bytes_append(bytes, sig, strlen(sig)) &&
	          libssig_bytes_append(bytes, ".", 1);
	for (size_t i = 0; ok && i < count; ++i) {
		const char* value = json_string_value(
		    json_array_get(doc->unsigned_items, i)
		);
		ok = value && libssig_bytes_append(bytes, value, strlen(value));
	}
	return ok;
}
static bool cert_read(
    const char* text,
    STACK_OF(X509) * certs,
    X509** out_cert
) {
	libssig_signature bytes = {0};
	if (!text || sk_X509_num(certs) >= 1024 ||
	    !libssig_base64_read(text, strlen(text), false, &bytes)) {
		return false;
	}
	const unsigned char* cursor = bytes.data;
	X509*                cert = d2i_X509(NULL, &cursor, (long)bytes.len);
	bool                 ok = cert && cursor == bytes.data + bytes.len &&
	          sk_X509_push(certs, cert);
	if (ok && out_cert) {
		if (X509_up_ref(cert) != 1) {
			libssig_signature_free(&bytes);
			return false;
		}
		*out_cert = cert;
	}
	if (!ok) {
		X509_free(cert);
	}
	libssig_signature_free(&bytes);
	return ok;
}
static libssig_status headers_read(libssig_jades* doc) {
	json_t*     header = doc->protected;
	const char* name;
	json_t*     value;
	json_object_foreach(header, name, value) {
		if (strcmp(name, "alg") && strcmp(name, "x5c") &&
		    strcmp(name, "x5t#S256") && strcmp(name, "iat") &&
		    strcmp(name, "cty")) {
			return LIBSSIG_ERROR_UNSUPPORTED;
		}
	}
	if (!json_is_integer(json_object_get(header, "iat")) ||
	    json_integer_value(json_object_get(header, "iat")) < 0) {
		return LIBSSIG_ERROR_FORMAT;
	}
	json_t* certs = json_object_get(header, "x5c");
	if (!json_is_array(certs) || !json_array_size(certs) ||
	    json_array_size(certs) > 1024) {
		return LIBSSIG_ERROR_FORMAT;
	}
	for (size_t i = 0; i < json_array_size(certs); ++i) {
		if (!cert_read(
		        json_string_value(json_array_get(certs, i)),
		        doc->evidence.certs,
		        i == 0 ? &doc->cert : NULL
		    )) {
			return LIBSSIG_ERROR_FORMAT;
		}
	}
	json_t* thumb = json_object_get(header, "x5t#S256");
	if (thumb) {
		unsigned char     digest[EVP_MAX_MD_SIZE];
		unsigned int      len = 0;
		libssig_signature bytes = {0};
		bool              ok = libssig_base64_read(
                      json_string_value(thumb),
                      json_string_length(thumb),
                      true,
                      &bytes
                  ) &&
		          X509_digest(doc->cert, EVP_sha256(), digest, &len) &&
		          bytes.len == len && !memcmp(bytes.data, digest, len);
		libssig_signature_free(&bytes);
		if (!ok) {
			return LIBSSIG_ERROR_VERIFY;
		}
	}
	return LIBSSIG_OK;
}
libssig_status libssig_jades_read(
    const libssig_verify_params* params,
    libssig_jades*               doc
) {
	if (params->data_len > LIBSSIG_DOCUMENT_LIMIT) {
		return LIBSSIG_ERROR_FORMAT;
	}
	doc->root = json_loadb(
	    (char*)params->data,
	    params->data_len,
	    JSON_REJECT_DUPLICATES,
	    NULL
	);
	doc->evidence.certs = sk_X509_new_null();
	doc->evidence.revocations = sk_ASN1_TYPE_new_null();
	if (!doc->evidence.certs || !doc->evidence.revocations) {
		return LIBSSIG_ERROR_MEMORY;
	}
	if (!json_is_object(doc->root)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	const char* key;
	json_t*     value;
	json_object_foreach(
	    doc->root,
	    key,
	    value
	) if (strcmp(key, "protected") && strcmp(key, "payload") &&
	      strcmp(key, "signature") &&
	      strcmp(key, "header")) return LIBSSIG_ERROR_UNSUPPORTED;
	const char* text = json_string_value(
	    json_object_get(doc->root, "protected")
	);
	libssig_signature bytes = {0};
	if (!text || !libssig_base64_read(text, strlen(text), true, &bytes)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	doc->protected = json_loadb(
	    (char*)bytes.data,
	    bytes.len,
	    JSON_REJECT_DUPLICATES,
	    NULL
	);
	libssig_signature_free(&bytes);
	if (!json_is_object(doc->protected)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	libssig_status status = headers_read(doc);
	if (status != LIBSSIG_OK) {
		return status;
	}
	text = json_string_value(json_object_get(doc->root, "signature"));
	if (!text ||
	    !libssig_base64_read(text, strlen(text), true, &doc->signature)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	value = json_object_get(doc->root, "payload");
	if (value && params->content) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	if (!value && !params->content) {
		return LIBSSIG_ERROR_CONTENT_REQUIRED;
	}
	if (value) {
		text = json_string_value(value);
		if (!text || !libssig_base64_read(
		                 text,
		                 json_string_length(value),
		                 true,
		                 &bytes
		             )) {
			return LIBSSIG_ERROR_FORMAT;
		}
		doc->payload = malloc(strlen(text) + 1);
		if (doc->payload) {
			memcpy(doc->payload, text, strlen(text) + 1);
		}
		libssig_signature_free(&bytes);
	} else {
		doc->payload = libssig_base64(
		    params->content,
		    params->content_len,
		    true
		);
	}
	if (!doc->payload) {
		return LIBSSIG_ERROR_MEMORY;
	}
	value = json_object_get(doc->root, "header");
	doc->unsigned_items = json_object_get(value, "etsiU");
	if (value && (!json_is_object(value) || json_object_size(value) != 1 ||
	              !json_is_array(doc->unsigned_items) ||
	              !json_array_size(doc->unsigned_items) ||
	              json_array_size(doc->unsigned_items) > 1024)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	for (size_t i = 0; i < json_array_size(doc->unsigned_items); ++i) {
		if (!json_is_string(json_array_get(doc->unsigned_items, i))) {
			return LIBSSIG_ERROR_UNSUPPORTED;
		}
	}
	return LIBSSIG_OK;
}

bool libssig_jades_timestamp_add(
    libssig_jades*           doc,
    const char*              kind,
    const libssig_signature* token
) {
	json_t* value = libssig_jades_pki(token);
	json_t* item = value ? json_pack("{s:{s:[o]}}", kind, "tstTokens", value)
	                     : NULL;
	return item && libssig_jades_add(doc, item);
}
