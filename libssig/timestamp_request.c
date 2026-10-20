/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/timestamp_internal.h>
#include <limits.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

const EVP_MD* libssig_timestamp_digest(libssig_hash hash) {
	switch (hash) {
	case LIBSSIG_HASH_SHA256:
		return EVP_sha256();
	case LIBSSIG_HASH_SHA384:
		return EVP_sha384();
	case LIBSSIG_HASH_SHA512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

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

static TS_MSG_IMPRINT* imprint_create(
    CMS_SignerInfo* signer,
    const EVP_MD*   digest
) {
	ASN1_OCTET_STRING* signature = CMS_SignerInfo_get0_signature(signer);
	unsigned char      hash[EVP_MAX_MD_SIZE];
	unsigned int       len = 0;
	TS_MSG_IMPRINT*    imprint = TS_MSG_IMPRINT_new();
	X509_ALGOR*        algorithm = X509_ALGOR_new();
	bool               ok = imprint && algorithm &&
	          EVP_Digest(
	              ASN1_STRING_get0_data(signature),
	              (size_t)ASN1_STRING_length(signature),
	              hash,
	              &len,
	              digest,
	              NULL
	          );
	if (ok) {
		X509_ALGOR_set_md(algorithm, digest);
		ok = TS_MSG_IMPRINT_set_algo(imprint, algorithm) &&
		     TS_MSG_IMPRINT_set_msg(imprint, hash, (int)len);
	}
	X509_ALGOR_free(algorithm);
	if (!ok) {
		TS_MSG_IMPRINT_free(imprint);
		return NULL;
	}
	return imprint;
}

bool libssig_timestamp_imprint(TS_REQ* request, CMS_SignerInfo* signer) {
	TS_MSG_IMPRINT*    imprint = TS_REQ_get_msg_imprint(request);
	X509_ALGOR*        algorithm = TS_MSG_IMPRINT_get_algo(imprint);
	const ASN1_OBJECT* oid = NULL;
	int                type;
	X509_ALGOR_get0(&oid, &type, NULL, algorithm);
	int           nid = OBJ_obj2nid(oid);
	const EVP_MD* digest = nid == NID_sha256   ? EVP_sha256()
	                       : nid == NID_sha384 ? EVP_sha384()
	                       : nid == NID_sha512 ? EVP_sha512()
	                                           : NULL;
	if (!digest || (type != V_ASN1_NULL && type != V_ASN1_UNDEF)) {
		return false;
	}

	TS_MSG_IMPRINT*    expected = imprint_create(signer, digest);
	ASN1_OCTET_STRING* actual = TS_MSG_IMPRINT_get_msg(imprint);
	ASN1_OCTET_STRING* hash = expected ? TS_MSG_IMPRINT_get_msg(expected)
	                                   : NULL;
	bool ok = hash && ASN1_STRING_length(actual) == ASN1_STRING_length(hash) &&
	          CRYPTO_memcmp(
	              ASN1_STRING_get0_data(actual),
	              ASN1_STRING_get0_data(hash),
	              (size_t)ASN1_STRING_length(hash)
	          ) == 0;
	TS_MSG_IMPRINT_free(expected);
	return ok;
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
	TS_MSG_IMPRINT* imprint = imprint_create(signer, digest);
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
