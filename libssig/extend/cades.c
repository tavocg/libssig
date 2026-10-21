/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <limits.h>
#include <stdlib.h>

static libssig_status signatures_validate(
    const libssig_extend_params* params,
    CMS_ContentInfo*             cms
) {
	libssig_verify_params verify = {
	    .data = params->data,
	    .data_len = params->data_len,
	    .content = params->content,
	    .content_len = params->content_len,
	    .options = LIBSSIG_VERIFY_CURRENT_TIME
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
libssig_status libssig_cades_v131_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
) {
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
		status = libssig_cades_v131_archive_apply(&cms, params);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_cms_encode(cms, output);
	}
	libssig_validation_free(&validation);
	CMS_ContentInfo_free(cms);
	return status;
}
