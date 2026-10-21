/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ades.h>
#include <libssig/time.h>
#include <libssig/trust.h>
#include <libssig/tsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
	STACK_OF(X509) * certs;
	X509_STORE*    store;
	bool           requested;
	bool           historical;
	libssig_status store_status;
} timestamp_trust;

static void trust_free(timestamp_trust* trust) {
	sk_X509_pop_free(trust->certs, X509_free);
	X509_STORE_free(trust->store);
}

static libssig_status trust_load(
    const libssig_verify_params* params,
    timestamp_trust*             trust
) {
	STACK_OF(X509)* roots = NULL;
	libssig_status status = libssig_verify_certs_parse(
	    params->tsa_ca_data,
	    params->tsa_ca_data_len,
	    &roots
	);
	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_parse(
		    params->tsa_intermediates_data,
		    params->tsa_intermediates_data_len,
		    &trust->certs
		);
	}

	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_append(trust->certs, roots);
	}

	trust->historical = params->options & LIBSSIG_VERIFY_HISTORICAL;
	trust->requested = params->tsa_ca_data ||
	                   (params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST);
	if (status == LIBSSIG_OK && trust->requested) {
		libssig_verify_params options = {
		    .fallback_ca_data = params->tsa_fallback_ca_data,
		    .fallback_ca_data_len = params->tsa_fallback_ca_data_len,
		    .options = (params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST)
		                   ? LIBSSIG_VERIFY_SYSTEM_TRUST
		                   : 0,
		};
		trust->store_status = libssig_verify_store_create(
		    &options,
		    roots,
		    &trust->store
		);
		if (trust->store_status != LIBSSIG_OK &&
		    trust->store_status != LIBSSIG_ERROR_TRUST) {
			status = trust->store_status;
		}
	}
	sk_X509_pop_free(roots, X509_free);
	return status;
}

static libssig_status attribute_decode(
    CMS_SignerInfo*   signer,
    CMS_ContentInfo** out_token,
    bool*             present
) {
	int i = CMS_unsigned_get_attr_by_NID(
	    signer,
	    NID_id_smime_aa_timeStampToken,
	    -1
	);
	*present = i >= 0;
	if (i < 0) {
		return LIBSSIG_ERROR_NOT_FOUND;
	}

	X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(signer, i);
	if (CMS_unsigned_get_attr_by_NID(
	        signer,
	        NID_id_smime_aa_timeStampToken,
	        i
	    ) >= 0 ||
	    X509_ATTRIBUTE_count(attr) != 1) {
		return LIBSSIG_ERROR_FORMAT;
	}

	ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attr, 0);
	if (!value || value->type != V_ASN1_SEQUENCE) {
		return LIBSSIG_ERROR_FORMAT;
	}

	const unsigned char* data = ASN1_STRING_get0_data(value->value.sequence);
	const unsigned char* cursor = data;
	int                  len = ASN1_STRING_length(value->value.sequence);
	*out_token = d2i_CMS_ContentInfo(NULL, &cursor, len);
	return *out_token && cursor == data + len ? LIBSSIG_OK
	                                          : LIBSSIG_ERROR_FORMAT;
}

static TS_TST_INFO* info_decode(CMS_ContentInfo* token) {
	if (OBJ_obj2nid(CMS_get0_type(token)) != NID_pkcs7_signed ||
	    CMS_is_detached(token) != 0 ||
	    OBJ_obj2nid(CMS_get0_eContentType(token)) != NID_id_smime_ct_TSTInfo ||
	    sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(token)) != 1) {
		return NULL;
	}

	ASN1_OCTET_STRING*   content = *CMS_get0_content(token);
	const unsigned char* data = ASN1_STRING_get0_data(content);
	const unsigned char* cursor = data;
	int                  len = ASN1_STRING_length(content);
	TS_TST_INFO*         info = d2i_TS_TST_INFO(NULL, &cursor, len);
	if (!info || cursor != data + len) {
		TS_TST_INFO_free(info);
		return NULL;
	}
	return info;
}

static bool tsa_name_valid(TS_TST_INFO* info, X509* cert) {
	GENERAL_NAME* name = TS_TST_INFO_get_tsa(info);
	if (!name) {
		return true;
	}

	if (name->type == GEN_DIRNAME &&
	    X509_NAME_cmp(name->d.directoryName, X509_get_subject_name(cert)) ==
	        0) {
		return true;
	}

	GENERAL_NAMES*
	     names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	bool found = false;
	for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
		if (GENERAL_NAME_cmp(name, sk_GENERAL_NAME_value(names, i)) == 0) {
			found = true;
			break;
		}
	}
	GENERAL_NAMES_free(names);
	return found;
}

static libssig_status token_signature_check(
    CMS_ContentInfo* token,
    TS_TST_INFO*     info,
    timestamp_trust* trust,
    X509**           out_cert
) {
	if (CMS_verify(
	        token,
	        trust->certs,
	        NULL,
	        NULL,
	        NULL,
	        CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
	    ) != 1) {
		return LIBSSIG_ERROR_VERIFY;
	}

	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(token),
	    0
	);
	CMS_SignerInfo_get0_algs(signer, NULL, out_cert, NULL, NULL);
	if (!*out_cert ||
	    X509_check_purpose(*out_cert, X509_PURPOSE_TIMESTAMP_SIGN, 0) != 1 ||
	    !tsa_name_valid(info, *out_cert) ||
	    (CMS_signed_get_attr_by_NID(
	         signer,
	         NID_id_smime_aa_signingCertificate,
	         -1
	     ) < 0 &&
	     CMS_signed_get_attr_by_NID(
	         signer,
	         NID_id_smime_aa_signingCertificateV2,
	         -1
	     ) < 0)) {
		return LIBSSIG_ERROR_VERIFY;
	}

	STACK_OF(X509)* certs = CMS_get1_certs(token);
	if (!certs) {
		certs = sk_X509_new_null();
		if (!certs) {
			return LIBSSIG_ERROR_MEMORY;
		}
	}

	libssig_status status = libssig_verify_certs_append(certs, trust->certs);
	if (status == LIBSSIG_OK &&
	    !libssig_verify_ess_check(signer, *out_cert, certs)) {
		status = LIBSSIG_ERROR_VERIFY;
	}
	sk_X509_pop_free(certs, X509_free);
	return status;
}

static libssig_status result_copy(
    TS_TST_INFO*              info,
    X509*                     cert,
    libssig_verify_timestamp* result
) {
	struct tm generated;
	if (!ASN1_TIME_to_tm(TS_TST_INFO_get_time(info), &generated) ||
	    snprintf(
	        result->time,
	        sizeof(result->time),
	        "%04d-%02d-%02dT%02d:%02d:%02dZ",
	        generated.tm_year + 1900,
	        generated.tm_mon + 1,
	        generated.tm_mday,
	        generated.tm_hour,
	        generated.tm_min,
	        generated.tm_sec
	    ) != 20) {
		return LIBSSIG_ERROR_VERIFY;
	}

	int len = i2d_X509(cert, NULL);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}

	result->cert_der = malloc((size_t)len);
	if (!result->cert_der) {
		return LIBSSIG_ERROR_MEMORY;
	}

	unsigned char* cursor = result->cert_der;
	if (i2d_X509(cert, &cursor) != len) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	result->cert_der_len = (size_t)len;
	result->valid = true;
	return LIBSSIG_OK;
}

static libssig_status trust_check(
    CMS_ContentInfo*          token,
    X509*                     cert,
    timestamp_trust*          trust,
    libssig_verify_timestamp* result
) {
	if (!trust->requested || trust->store_status != LIBSSIG_OK) {
		return trust->store_status;
	}

	STACK_OF(X509)* certs = CMS_get1_certs(token);
	if (!certs) {
		certs = sk_X509_new_null();
	}

	libssig_status  status = certs ? libssig_verify_certs_append(
                                        certs,
                                        trust->certs
                                    )
	                               : LIBSSIG_ERROR_MEMORY;
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	if (status == LIBSSIG_OK &&
	    (!ctx || !X509_STORE_CTX_init(ctx, trust->store, cert, certs) ||
	     !X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_TIMESTAMP_SIGN))) {
		status = LIBSSIG_ERROR_CRYPTO;
	}

	if (status == LIBSSIG_OK) {
		if (trust->historical) {
			time_t at;
			if (!libssig_verify_time_parse(result->time, &at)) {
				X509_STORE_CTX_free(ctx);
				sk_X509_pop_free(certs, X509_free);
				return LIBSSIG_ERROR_TIMESTAMP;
			}
			X509_STORE_CTX_set_time(ctx, 0, at);
		}
		result->trust_checked = true;
		int ok = X509_verify_cert(ctx);
		result->trust_error = X509_STORE_CTX_get_error(ctx);
		time_t generated;
		if (ok == 1 && libssig_verify_time_parse(result->time, &generated)) {
			if (X509_cmp_time(X509_get0_notBefore(cert), &generated) > 0) {
				ok = 0;
				result->trust_error = X509_V_ERR_CERT_NOT_YET_VALID;
			} else if (X509_cmp_time(X509_get0_notAfter(cert), &generated) <
			           0) {
				ok = 0;
				result->trust_error = X509_V_ERR_CERT_HAS_EXPIRED;
			}
		}
		result->trusted = ok == 1;
		if (ok == 1) {
			libssig_trust_anchor_get(ctx, &result->anchor);
		}
		status = ok == 1 ? LIBSSIG_OK : LIBSSIG_ERROR_TRUST;
	}
	X509_STORE_CTX_free(ctx);
	sk_X509_pop_free(certs, X509_free);
	return status;
}

static libssig_status timestamp_check(
    CMS_SignerInfo*           signer,
    timestamp_trust*          trust,
    libssig_verify_timestamp* result
) {
	CMS_ContentInfo* token = NULL;
	TS_TST_INFO*     info = NULL;
	libssig_status status = attribute_decode(signer, &token, &result->present);
	if (status == LIBSSIG_OK) {
		info = info_decode(token);
		status = info ? LIBSSIG_OK : LIBSSIG_ERROR_FORMAT;
	}

	if (status == LIBSSIG_OK && (TS_TST_INFO_get_version(info) != 1 ||
	                             !libssig_timestamp_time_valid(info) ||
	                             !libssig_timestamp_imprint_matches(
	                                 TS_TST_INFO_get_msg_imprint(info),
	                                 signer
	                             ))) {
		status = LIBSSIG_ERROR_VERIFY;
	}

	X509* cert = NULL;
	if (status == LIBSSIG_OK) {
		status = token_signature_check(token, info, trust, &cert);
	}

	if (status == LIBSSIG_OK) {
		status = result_copy(info, cert, result);
	}

	if (status == LIBSSIG_OK) {
		status = trust_check(token, cert, trust, result);
	}
	result->status = status;
	TS_TST_INFO_free(info);
	CMS_ContentInfo_free(token);
	return status;
}

static libssig_status status_merge(
    libssig_status current,
    libssig_status status
) {
	if (status == LIBSSIG_OK || status == LIBSSIG_ERROR_NOT_FOUND) {
		return current;
	}

	if (status == LIBSSIG_ERROR_MEMORY || status == LIBSSIG_ERROR_CRYPTO) {
		return status;
	}

	if (status != LIBSSIG_ERROR_TRUST) {
		return LIBSSIG_ERROR_TIMESTAMP;
	}
	return current == LIBSSIG_OK ? LIBSSIG_ERROR_TRUST : current;
}

libssig_status libssig_verify_timestamps(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	timestamp_trust trust = {0};
	libssig_status  status = trust_load(params, &trust);
	if (status != LIBSSIG_OK) {
		trust_free(&trust);
		return status;
	}

	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	for (size_t i = 0; i < result->count; ++i) {
		libssig_status checked = timestamp_check(
		    sk_CMS_SignerInfo_value(signers, (int)i),
		    &trust,
		    &result->signers[i].timestamp
		);
		if (checked == LIBSSIG_ERROR_NOT_FOUND &&
		    (params->options & LIBSSIG_VERIFY_REQUIRE_TIMESTAMP)) {
			checked = LIBSSIG_ERROR_TIMESTAMP;
		}
		status = status_merge(status, checked);
		if (status == LIBSSIG_ERROR_MEMORY || status == LIBSSIG_ERROR_CRYPTO) {
			break;
		}
	}
	trust_free(&trust);
	return status;
}

libssig_status libssig_verify_timestamp_token(
    CMS_ContentInfo*             token,
    const libssig_verify_params* params,
    const EVP_MD*                digest,
    const unsigned char*         imprint,
    size_t                       imprint_len,
    libssig_verify_timestamp*    result
) {
	result->present = true;
	timestamp_trust trust = {0};
	libssig_status  status = trust_load(params, &trust);
	TS_TST_INFO*    info = info_decode(token);
	TS_MSG_IMPRINT* message = info ? TS_TST_INFO_get_msg_imprint(info) : NULL;
	X509_ALGOR* algorithm = message ? TS_MSG_IMPRINT_get_algo(message) : NULL;
	ASN1_OCTET_STRING* value = message ? TS_MSG_IMPRINT_get_msg(message) : NULL;
	if (status == LIBSSIG_OK &&
	    (!info || !digest || TS_TST_INFO_get_version(info) != 1 ||
	     !libssig_timestamp_time_valid(info) ||
	     OBJ_obj2nid(algorithm->algorithm) != EVP_MD_get_type(digest) ||
	     ASN1_STRING_length(value) != (int)imprint_len ||
	     CRYPTO_memcmp(ASN1_STRING_get0_data(value), imprint, imprint_len))) {
		status = LIBSSIG_ERROR_VERIFY;
	}
	X509* cert = NULL;
	if (status == LIBSSIG_OK) {
		status = token_signature_check(token, info, &trust, &cert);
	}
	if (status == LIBSSIG_OK) {
		status = result_copy(info, cert, result);
	}
	if (status == LIBSSIG_OK) {
		status = trust_check(token, cert, &trust, result);
	}
	result->status = status;
	TS_TST_INFO_free(info);
	trust_free(&trust);
	return status;
}
