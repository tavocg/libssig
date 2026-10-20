/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ades_internal.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

libssig_status libssig_ades_stamps(
    CMS_ContentInfo*             cms,
    const libssig_extend_params* params
) {
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	if (sk_CMS_SignerInfo_num(signers) <= 0) {
		return LIBSSIG_ERROR_FORMAT;
	}
	for (int i = 0; i < sk_CMS_SignerInfo_num(signers); ++i) {
		CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, i);
		if (CMS_unsigned_get_attr_by_NID(
		        signer,
		        NID_id_smime_aa_timeStampToken,
		        -1
		    ) >= 0) {
			continue;
		}
		ASN1_OCTET_STRING* signature = CMS_SignerInfo_get0_signature(signer);
		unsigned char      hash[EVP_MAX_MD_SIZE];
		unsigned int       len = 0;
		bool               ok = EVP_Digest(
            ASN1_STRING_get0_data(signature),
            (size_t)ASN1_STRING_length(signature),
            hash,
            &len,
            libssig_timestamp_digest(params->hash),
            NULL
        );
		libssig_signature query = {0}, response = {0};
		libssig_status
		    status = ok ? libssig_ades_query(hash, len, params->hash, &query)
		                : LIBSSIG_ERROR_CRYPTO;
		if (status == LIBSSIG_OK) {
			status = libssig_ades_response(params->services, &query, &response);
		}
		const unsigned char* cursor = response.data;
		TS_RESP*             reply = status == LIBSSIG_OK
		                                 ? d2i_TS_RESP(NULL, &cursor, (long)response.len)
		                                 : NULL;
		unsigned char*       bytes = NULL;
		int encoded_len = reply ? i2d_PKCS7(TS_RESP_get_token(reply), &bytes)
		                        : 0;
		if (status == LIBSSIG_OK &&
		    (encoded_len <= 0 || !CMS_unsigned_add1_attr_by_NID(
		                             signer,
		                             NID_id_smime_aa_timeStampToken,
		                             V_ASN1_SEQUENCE,
		                             bytes,
		                             encoded_len
		                         ))) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
		TS_RESP_free(reply);
		OPENSSL_free(bytes);
		libssig_signature_free(&query);
		libssig_signature_free(&response);
		if (status != LIBSSIG_OK) {
			return status;
		}
	}
	libssig_verify_params defaults = {
	    .options = LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
	};
	libssig_verify_params trust = params->services->trust
	                                  ? *params->services->trust
	                                  : defaults;
	trust.options |= LIBSSIG_VERIFY_REQUIRE_TIMESTAMP;
	libssig_verify_result result = {
	    .count = (size_t)sk_CMS_SignerInfo_num(signers)
	};
	result.signers = calloc(result.count, sizeof(*result.signers));
	if (!result.signers) {
		return LIBSSIG_ERROR_MEMORY;
	}
	libssig_status status = libssig_verify_timestamps(cms, &trust, &result);
	libssig_verify_free(&result);
	return status;
}
static libssig_status signatures_validate(
    const libssig_extend_params* params,
    CMS_ContentInfo*             cms
) {
	libssig_verify_params verify = {
	    .data = params->data,
	    .data_len = params->data_len,
	    .content = params->content,
	    .content_len = params->content_len
	};
	libssig_verify_result result = {0};
	libssig_status        checked = libssig_verify(&verify, &result);
	libssig_verify_free(&result);
	if (checked != LIBSSIG_OK) {
		return checked;
	}
	const int required[] = {
	    NID_pkcs9_contentType,
	    NID_pkcs9_messageDigest,
	    NID_pkcs9_signingTime,
	    NID_id_smime_aa_signingCertificateV2
	};
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	for (int i = 0; i < sk_CMS_SignerInfo_num(signers); ++i) {
		CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, i);
		for (size_t j = 0; j < sizeof(required) / sizeof(required[0]); ++j) {
			int pos = CMS_signed_get_attr_by_NID(signer, required[j], -1);
			if (pos < 0 ||
			    X509_ATTRIBUTE_count(CMS_signed_get_attr(signer, pos)) != 1 ||
			    CMS_signed_get_attr_by_NID(signer, required[j], pos) >= 0) {
				return LIBSSIG_ERROR_UNSUPPORTED;
			}
		}
	}
	STACK_OF(X509)* certs = CMS_get1_certs(cms);
	BIO* content = params->content ? BIO_new_mem_buf(
	                                     params->content,
	                                     (int)params->content_len
	                                 )
	                               : NULL;
	BIO* sink = BIO_new(BIO_s_null());
	bool ok = sink && (!params->content || content) &&
	          CMS_verify(
	              cms,
	              certs,
	              NULL,
	              content,
	              sink,
	              CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
	          ) == 1;
	BIO_free(content);
	BIO_free(sink);
	sk_X509_pop_free(certs, X509_free);
	return ok ? LIBSSIG_OK : LIBSSIG_ERROR_VERIFY;
}
libssig_status libssig_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
) {
	if (!output) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*output = (libssig_signature){0};
	if (!params || !params->data || !params->data_len ||
	    params->data_len > INT_MAX || params->content_len > INT_MAX ||
	    (!params->content && params->content_len) ||
	    !libssig_level_valid(params->level) ||
	    !libssig_timestamp_digest(params->hash) ||
	    (params->services && (params->services->ocsp_options &
	                          ~LIBSSIG_OCSP_ALLOW_MISSING_NONCE)) ||
	    (params->level != LIBSSIG_LEVEL_B_B &&
	     (!params->services || !params->services->exchange ||
	      !params->services->tsa_url))) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	if (params->data_len >= 5 && !memcmp(params->data, "%PDF-", 5)) {
		return libssig_pades_extend(params, output);
	}
	const unsigned char* cursor = params->data;
	CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)params->data_len
    );
	libssig_status status = cms && cursor == params->data + params->data_len &&
	                                OBJ_obj2nid(CMS_get0_type(cms)) ==
	                                    NID_pkcs7_signed
	                            ? LIBSSIG_OK
	                            : LIBSSIG_ERROR_FORMAT;
	if (status == LIBSSIG_OK && CMS_is_detached(cms) && !params->content) {
		status = LIBSSIG_ERROR_CONTENT_REQUIRED;
	}
	if (status == LIBSSIG_OK && !CMS_is_detached(cms) && params->content) {
		status = LIBSSIG_ERROR_ARGUMENT;
	}
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B) {
		const char* unsupported[] = {
		    LIBSSIG_ARCHIVE_OID,
		    "1.2.840.113549.1.9.16.2.27",
		    "1.2.840.113549.1.9.16.2.48",
		    "0.4.0.1733.2.2",
		    "1.2.840.113549.1.9.6"
		};
		STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
		for (int i = 0;
		     status == LIBSSIG_OK && i < sk_CMS_SignerInfo_num(signers);
		     ++i) {
			CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, i);
			for (size_t j = 0; j < sizeof(unsupported) / sizeof(unsupported[0]);
			     ++j) {
				ASN1_OBJECT* oid = OBJ_txt2obj(unsupported[j], 1);
				if (oid && CMS_unsigned_get_attr_by_OBJ(signer, oid, -1) >= 0) {
					status = LIBSSIG_ERROR_UNSUPPORTED;
				}
				ASN1_OBJECT_free(oid);
			}
		}
	}
	if (status == LIBSSIG_OK) {
		status = signatures_validate(params, cms);
	}
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B) {
		status = libssig_ades_stamps(cms, params);
	}
	libssig_validation_data validation = {0};
	if (status == LIBSSIG_OK && (params->level == LIBSSIG_LEVEL_B_LT ||
	                             params->level == LIBSSIG_LEVEL_B_LTA)) {
		status = libssig_validation_collect(cms, params->services, &validation);
		if (status == LIBSSIG_OK) {
			status = libssig_validation_embed(&cms, &validation);
		}
	}
	if (status == LIBSSIG_OK && params->level == LIBSSIG_LEVEL_B_LTA) {
		status = libssig_archive_apply(&cms, params);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_ades_encode(cms, output);
	}
	libssig_validation_free(&validation);
	CMS_ContentInfo_free(cms);
	return status;
}
