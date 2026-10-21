/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/document.h>
#include <libssig/services.h>
#include <libssig/trust.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>

bool libssig_document_signature_check(
    X509*                    cert,
    libssig_algo             algo,
    libssig_hash             hash,
    const void*              data,
    size_t                   len,
    const libssig_signature* signature
) {
	EVP_PKEY*     key = X509_get_pubkey(cert);
	EVP_MD_CTX*   ctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX* key_ctx = NULL;
	const EVP_MD* md = libssig_timestamp_digest(hash);
	bool          valid = key && ctx && md &&
	             EVP_PKEY_is_a(
	                 key,
	                 algo == LIBSSIG_ALGO_ECDSA ? "EC" : "RSA"
	             ) &&
	             EVP_DigestVerifyInit(ctx, &key_ctx, md, NULL, key) == 1;
	if (valid && algo == LIBSSIG_ALGO_RSA_PSS) {
		valid = EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_PSS_PADDING) >
		            0 &&
		        EVP_PKEY_CTX_set_rsa_pss_saltlen(key_ctx, EVP_MD_get_size(md)) >
		            0 &&
		        EVP_PKEY_CTX_set_rsa_mgf1_md(key_ctx, md) > 0;
	}
	const unsigned char* bytes = signature->data;
	size_t               size = signature->len;
	unsigned char*       der = NULL;
	if (valid && algo == LIBSSIG_ALGO_ECDSA) {
		size_t     half = (size_t)(EVP_PKEY_get_bits(key) + 7) / 8;
		ECDSA_SIG* sig = ECDSA_SIG_new();
		BIGNUM* r = size == 2 * half ? BN_bin2bn(bytes, (int)half, NULL) : NULL;
		BIGNUM* s = r ? BN_bin2bn(bytes + half, (int)half, NULL) : NULL;
		valid = sig && r && s && ECDSA_SIG_set0(sig, r, s);
		if (valid) {
			int n = i2d_ECDSA_SIG(sig, &der);
			valid = n > 0;
			bytes = der;
			size = n > 0 ? (size_t)n : 0;
		} else {
			BN_free(r);
			BN_free(s);
		}
		ECDSA_SIG_free(sig);
	}
	if (valid) {
		valid = EVP_DigestVerify(ctx, bytes, size, data, len) == 1;
	}
	OPENSSL_free(der);
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return valid;
}
libssig_status libssig_document_stamp(
    const libssig_signature*     input,
    libssig_hash                 hash,
    const libssig_sign_services* services,
    libssig_signature*           token
) {
	unsigned char     imprint[EVP_MAX_MD_SIZE];
	unsigned int      len = 0;
	libssig_signature query = {0}, response = {0};
	libssig_status    status = libssig_document_digest(
                                input->data,
                                input->len,
                                hash,
                                imprint,
                                &len
                            )
	                               ? libssig_ades_query(imprint, len, hash, &query)
	                               : LIBSSIG_ERROR_CRYPTO;
	if (status == LIBSSIG_OK) {
		status = libssig_ades_response(services, &query, &response);
	}
	const unsigned char* cursor = response.data;
	TS_RESP*             reply = status == LIBSSIG_OK
	                                 ? d2i_TS_RESP(NULL, &cursor, (long)response.len)
	                                 : NULL;
	unsigned char*       der = NULL;
	int size = reply ? i2d_PKCS7(TS_RESP_get_token(reply), &der) : 0;
	if (status == LIBSSIG_OK) {
		status = size > 0 && libssig_bytes_append(token, der, (size_t)size)
		             ? LIBSSIG_OK
		             : LIBSSIG_ERROR_TIMESTAMP;
	}
	OPENSSL_free(der);
	TS_RESP_free(reply);
	libssig_signature_free(&query);
	libssig_signature_free(&response);
	return status;
}
libssig_status libssig_document_stamp_verify(
    const libssig_signature*     input,
    const libssig_signature*     token,
    const libssig_verify_params* params,
    libssig_verify_timestamp*    result
) {
	const unsigned char* cursor = token->data;
	CMS_ContentInfo*     cms = token->len <= LIBSSIG_DOCUMENT_LIMIT
	                               ? d2i_CMS_ContentInfo(
                                     NULL,
                                     &cursor,
                                     (long)token->len
                                 )
	                               : NULL;
	ASN1_OCTET_STRING**  content = cms ? CMS_get0_content(cms) : NULL;
	const unsigned char* tst = content && *content
	                               ? ASN1_STRING_get0_data(*content)
	                               : NULL;
	TS_TST_INFO*         info = tst ? d2i_TS_TST_INFO(
                                  NULL,
                                  &tst,
                                  ASN1_STRING_length(*content)
                              )
	                                : NULL;
	TS_MSG_IMPRINT* imprint = info ? TS_TST_INFO_get_msg_imprint(info) : NULL;
	const ASN1_OBJECT* oid = NULL;
	if (imprint) {
		X509_ALGOR_get0(&oid, NULL, NULL, TS_MSG_IMPRINT_get_algo(imprint));
	}
	const EVP_MD* md = oid ? EVP_get_digestbyobj(oid) : NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  len = 0;
	result->present = true;
	bool valid = cms && cursor == token->data + token->len && md &&
	             EVP_Digest(input->data, input->len, digest, &len, md, NULL) ==
	                 1;
	libssig_status status = valid ? libssig_verify_timestamp_token(
	                                    cms,
	                                    params,
	                                    md,
	                                    digest,
	                                    len,
	                                    result
	                                )
	                              : LIBSSIG_ERROR_TIMESTAMP;
	TS_TST_INFO_free(info);
	CMS_ContentInfo_free(cms);
	if (status != LIBSSIG_OK && status != LIBSSIG_ERROR_TRUST &&
	    status != LIBSSIG_ERROR_MEMORY && status != LIBSSIG_ERROR_CRYPTO) {
		status = LIBSSIG_ERROR_TIMESTAMP;
	}
	return status;
}
