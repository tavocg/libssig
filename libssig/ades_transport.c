/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ades_internal.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

bool libssig_level_valid(libssig_level level) {
	return level == LIBSSIG_LEVEL_B_B || level == LIBSSIG_LEVEL_B_T ||
	       level == LIBSSIG_LEVEL_B_LT || level == LIBSSIG_LEVEL_B_LTA;
}
libssig_status libssig_ades_encode(
    CMS_ContentInfo*   cms,
    libssig_signature* output
) {
	int len = i2d_CMS_ContentInfo(cms, NULL);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	output->data = malloc((size_t)len);
	if (!output->data) {
		return LIBSSIG_ERROR_MEMORY;
	}
	unsigned char* cursor = output->data;
	if (i2d_CMS_ContentInfo(cms, &cursor) != len) {
		libssig_signature_free(output);
		return LIBSSIG_ERROR_CRYPTO;
	}
	output->len = (size_t)len;
	return LIBSSIG_OK;
}
libssig_status libssig_ades_fetch(
    const libssig_sign_services* services,
    libssig_fetch_kind           kind,
    const char*                  url,
    const unsigned char*         data,
    size_t                       len,
    libssig_signature*           response
) {
	if (!services || !services->exchange || !url ||
	    (strncmp(url, "http://", 7) && strncmp(url, "https://", 8))) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	libssig_status status = services->exchange(
	    services->user_data,
	    kind,
	    url,
	    data,
	    len,
	    response
	);
	if (status == LIBSSIG_OK && (!response->data || !response->len ||
	                             response->len > 16 * 1024 * 1024)) {
		status = LIBSSIG_ERROR_FORMAT;
	}
	if (status != LIBSSIG_OK) {
		libssig_signature_free(response);
	}
	return status;
}
libssig_status libssig_ades_query(
    const unsigned char* imprint,
    size_t               len,
    libssig_hash         hash,
    libssig_signature*   output
) {
	const EVP_MD* digest = libssig_timestamp_digest(hash);
	if (!digest || len != (size_t)EVP_MD_get_size(digest)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	TS_REQ*         request = TS_REQ_new();
	TS_MSG_IMPRINT* message = TS_MSG_IMPRINT_new();
	X509_ALGOR*     algorithm = X509_ALGOR_new();
	unsigned char   random[16];
	bool            ok = request && message && algorithm &&
	          RAND_bytes(random, sizeof(random)) == 1;
	random[0] |= 0x80;
	BIGNUM*       number = ok ? BN_bin2bn(random, sizeof(random), NULL) : NULL;
	ASN1_INTEGER* nonce = number ? BN_to_ASN1_INTEGER(number, NULL) : NULL;
	if (ok) {
		X509_ALGOR_set_md(algorithm, digest);
		ok = nonce && TS_REQ_set_version(request, 1) &&
		     TS_REQ_set_nonce(request, nonce) &&
		     TS_REQ_set_cert_req(request, 1) &&
		     TS_MSG_IMPRINT_set_algo(message, algorithm) &&
		     TS_MSG_IMPRINT_set_msg(
		         message,
		         (unsigned char*)imprint,
		         (int)len
		     ) &&
		     TS_REQ_set_msg_imprint(request, message);
	}
	int encoded_len = ok ? i2d_TS_REQ(request, NULL) : 0;
	if (encoded_len > 0) {
		output->data = malloc((size_t)encoded_len);
		unsigned char* cursor = output->data;
		ok = output->data && i2d_TS_REQ(request, &cursor) == encoded_len;
		if (ok) {
			output->len = (size_t)encoded_len;
		}
	} else {
		ok = false;
	}
	ASN1_INTEGER_free(nonce);
	BN_free(number);
	X509_ALGOR_free(algorithm);
	TS_MSG_IMPRINT_free(message);
	TS_REQ_free(request);
	if (!ok) {
		libssig_signature_free(output);
	}
	return ok ? LIBSSIG_OK : LIBSSIG_ERROR_CRYPTO;
}
libssig_status libssig_ades_response(
    const libssig_sign_services* services,
    const libssig_signature*     request,
    libssig_signature*           response
) {
	libssig_status status = libssig_ades_fetch(
	    services,
	    LIBSSIG_FETCH_TIMESTAMP,
	    services->tsa_url,
	    request->data,
	    request->len,
	    response
	);
	if (status != LIBSSIG_OK) {
		return status;
	}
	const unsigned char* cursor = request->data;
	TS_REQ*              query = d2i_TS_REQ(NULL, &cursor, (long)request->len);
	bool valid = query && cursor == request->data + request->len;
	cursor = response->data;
	TS_RESP* reply = d2i_TS_RESP(NULL, &cursor, (long)response->len);
	valid = valid && reply && cursor == response->data + response->len;
	const libssig_verify_params empty = {
	    .options = LIBSSIG_VERIFY_SYSTEM_TRUST |
	               LIBSSIG_VERIFY_TSA_SYSTEM_TRUST,
	};
	const libssig_verify_params* trust = services->trust ? services->trust
	                                                     : &empty;
	libssig_timestamp_params     params = {
	        .ca_data = trust->tsa_ca_data,
	        .ca_data_len = trust->tsa_ca_data_len,
	        .intermediates_data = trust->tsa_intermediates_data,
	        .intermediates_data_len = trust->tsa_intermediates_data_len,
	        .options = trust->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
	                       ? LIBSSIG_TIMESTAMP_SYSTEM_TRUST
	                       : 0,
    };
	STACK_OF(X509)* chain = NULL;
	BIO* pem = BIO_new(BIO_s_mem());
	status = valid ? libssig_validation_tsa_certs(
	                     TS_RESP_get_token(reply),
	                     services,
	                     &chain
	                 )
	               : LIBSSIG_ERROR_FORMAT;
	if (status == LIBSSIG_OK && !pem) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(chain); ++i) {
		X509* cert = sk_X509_value(chain, i);
		if (PEM_write_bio_X509(pem, cert) != 1) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
	}
	char* cert_bytes = NULL;
	long  cert_len = pem ? BIO_get_mem_data(pem, &cert_bytes) : 0;
	if (status == LIBSSIG_OK && cert_len > 0) {
		params.intermediates_data = (unsigned char*)cert_bytes;
		params.intermediates_data_len = (size_t)cert_len;
		status = libssig_timestamp_response(&params, query, reply);
	}
	if (status == LIBSSIG_OK) {
		PKCS7* token = TS_RESP_get_token(reply);
		for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(chain); ++i) {
			X509* cert = sk_X509_value(chain, i);
			bool  found = false;
			for (int j = 0; j < sk_X509_num(token->d.sign->cert); ++j) {
				if (X509_cmp(cert, sk_X509_value(token->d.sign->cert, j)) ==
				    0) {
					found = true;
					break;
				}
			}
			if (!found && !PKCS7_add_certificate(token, cert)) {
				status = LIBSSIG_ERROR_CRYPTO;
			}
		}
		unsigned char* bytes = NULL;
		int len = status == LIBSSIG_OK ? i2d_TS_RESP(reply, &bytes) : 0;
		unsigned char* owned = len > 0 ? malloc((size_t)len) : NULL;
		if (owned) {
			memcpy(owned, bytes, (size_t)len);
			libssig_signature_free(response);
			response->data = owned;
			response->len = (size_t)len;
		} else {
			status = LIBSSIG_ERROR_CRYPTO;
		}
		OPENSSL_free(bytes);
	}
	sk_X509_pop_free(chain, X509_free);
	BIO_free(pem);
	TS_REQ_free(query);
	TS_RESP_free(reply);
	return status;
}
