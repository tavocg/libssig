/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <limits.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

static bool signer_check(CMS_SignerInfo* signer, STACK_OF(X509) * certs) {
	const int required[] = {
	    NID_pkcs9_contentType,
	    NID_pkcs9_messageDigest,
	    NID_pkcs9_signingTime,
	    NID_id_smime_aa_signingCertificateV2
	};
	for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); ++i) {
		if (CMS_signed_get_attr_by_NID(signer, required[i], -1) < 0) {
			return false;
		}
	}

	X509* cert = NULL;
	CMS_SignerInfo_get0_algs(signer, NULL, &cert, NULL, NULL);
	return cert && CMS_SignerInfo_verify(signer) == 1 &&
	       libssig_verify_ess_check(signer, cert, certs);
}

libssig_status libssig_timestamp_container(
    const unsigned char* data,
    size_t               len,
    size_t               index,
    CMS_ContentInfo**    out_cms,
    CMS_SignerInfo**     out_signer
) {
	const unsigned char* cursor = data;
	*out_cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)len);
	if (!*out_cms || cursor != data + len) {
		return LIBSSIG_ERROR_FORMAT;
	}

	if (OBJ_obj2nid(CMS_get0_type(*out_cms)) != NID_pkcs7_signed) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}

	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(*out_cms);
	int count = sk_CMS_SignerInfo_num(signers);
	if (count <= 0 || index >= (size_t)count) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*out_signer = sk_CMS_SignerInfo_value(signers, (int)index);
	if (CMS_unsigned_get_attr_by_NID(
	        *out_signer,
	        NID_id_smime_aa_timeStampToken,
	        -1
	    ) >= 0) {
		return LIBSSIG_ERROR_AMBIGUOUS;
	}

	STACK_OF(X509)* certs = CMS_get1_certs(*out_cms);
	CMS_set1_signers_certs(*out_cms, certs, 0);
	bool ok = signer_check(*out_signer, certs);
	sk_X509_pop_free(certs, X509_free);
	return ok ? LIBSSIG_OK : LIBSSIG_ERROR_VERIFY;
}

bool libssig_timestamp_imprint(TS_REQ* request, CMS_SignerInfo* signer) {
	return libssig_timestamp_imprint_matches(
	    TS_REQ_get_msg_imprint(request),
	    signer
	);
}

static bool nonce_set(TS_REQ* request) {
	unsigned char bytes[16];
	if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
		return false;
	}
	bytes[0] |= 0x80;
	BIGNUM*       number = BN_bin2bn(bytes, sizeof(bytes), NULL);
	ASN1_INTEGER* nonce = number ? BN_to_ASN1_INTEGER(number, NULL) : NULL;
	bool          ok = nonce && TS_REQ_set_nonce(request, nonce);
	BN_free(number);
	ASN1_INTEGER_free(nonce);
	return ok;
}

static libssig_status request_create(
    const libssig_timestamp_request_params* params,
    CMS_SignerInfo*                         signer,
    TS_REQ**                                out_request
) {
	const EVP_MD* digest = libssig_timestamp_digest(params->hash);
	if (!digest) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}

	ASN1_OBJECT* policy = params->policy_oid
	                          ? OBJ_txt2obj(params->policy_oid, 1)
	                          : NULL;
	if (params->policy_oid && !policy) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*out_request = TS_REQ_new();
	TS_MSG_IMPRINT* imprint = libssig_timestamp_imprint_create(signer, digest);
	bool ok = *out_request && imprint && TS_REQ_set_version(*out_request, 1) &&
	          TS_REQ_set_msg_imprint(*out_request, imprint) &&
	          nonce_set(*out_request) && TS_REQ_set_cert_req(*out_request, 1) &&
	          (!policy || TS_REQ_set_policy_id(*out_request, policy));
	TS_MSG_IMPRINT_free(imprint);
	ASN1_OBJECT_free(policy);
	return ok ? LIBSSIG_OK : LIBSSIG_ERROR_CRYPTO;
}

static libssig_status request_encode(
    TS_REQ*            request,
    libssig_signature* output
) {
	int len = i2d_TS_REQ(request, NULL);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}

	output->data = malloc((size_t)len);
	if (!output->data) {
		return LIBSSIG_ERROR_MEMORY;
	}

	unsigned char* cursor = output->data;
	if (i2d_TS_REQ(request, &cursor) != len) {
		libssig_signature_free(output);
		return LIBSSIG_ERROR_CRYPTO;
	}
	output->len = (size_t)len;
	return LIBSSIG_OK;
}

libssig_status libssig_timestamp_request(
    const libssig_timestamp_request_params* params,
    libssig_signature*                      request
) {
	if (!request) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*request = (libssig_signature){0};
	if (!params || !params->data || !params->data_len ||
	    params->data_len > INT_MAX) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	CMS_ContentInfo* cms = NULL;
	CMS_SignerInfo*  signer = NULL;
	TS_REQ*          query = NULL;
	libssig_status   status = libssig_timestamp_container(
        params->data,
        params->data_len,
        params->signer_index,
        &cms,
        &signer
    );
	if (status == LIBSSIG_OK) {
		status = request_create(params, signer, &query);
	}

	if (status == LIBSSIG_OK) {
		status = request_encode(query, request);
	}
	TS_REQ_free(query);
	CMS_ContentInfo_free(cms);
	return status;
}
