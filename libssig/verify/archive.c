/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/document.h>
#include <stdlib.h>
#include <string.h>

static bool index_matches(
    STACK_OF(ASN1_OCTET_STRING) * expected,
    STACK_OF(ASN1_OCTET_STRING) * actual
) {
	int count = sk_ASN1_OCTET_STRING_num(actual);
	int required = sk_ASN1_OCTET_STRING_num(expected);
	if (count > 4096 || required > count) {
		return false;
	}
	bool* used = calloc(count ? (size_t)count : 1, sizeof(bool));
	if (!used) {
		return false;
	}
	bool ok = true;
	for (int i = 0; ok && i < required; ++i) {
		ok = false;
		for (int j = 0; j < count; ++j) {
			if (!used[j] && ASN1_OCTET_STRING_cmp(
			                    sk_ASN1_OCTET_STRING_value(expected, i),
			                    sk_ASN1_OCTET_STRING_value(actual, j)
			                ) == 0) {
				used[j] = true;
				ok = true;
				break;
			}
		}
	}
	free(used);
	return ok;
}
static libssig_status archive_verify(
    CMS_ContentInfo*             cms,
    int                          signer_index,
    ASN1_TYPE*                   value,
    const libssig_verify_params* params,
    libssig_verify_timestamp*    result,
    bool*                        complete
) {
	if (!value || value->type != V_ASN1_SEQUENCE) {
		return LIBSSIG_ERROR_TIMESTAMP;
	}
	const unsigned char* cursor = ASN1_STRING_get0_data(value->value.sequence);
	CMS_ContentInfo*     token = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        ASN1_STRING_length(value->value.sequence)
    );
	STACK_OF(CMS_SignerInfo)* token_signers = token
	                                              ? CMS_get0_SignerInfos(token)
	                                              : NULL;
	CMS_SignerInfo* s = sk_CMS_SignerInfo_num(token_signers) == 1
	                        ? sk_CMS_SignerInfo_value(token_signers, 0)
	                        : NULL;
	ASN1_OBJECT*    oid = OBJ_txt2obj(LIBSSIG_HASH_INDEX_OID, 1);
	int pos = s && oid ? CMS_unsigned_get_attr_by_OBJ(s, oid, -1) : -1;
	X509_ATTRIBUTE* attr = pos >= 0 ? CMS_unsigned_get_attr(s, pos) : NULL;
	ASN1_TYPE*      index_value = attr && X509_ATTRIBUTE_count(attr) == 1 &&
                                     CMS_unsigned_get_attr_by_OBJ(s, oid, pos) <
                                         0
	                                  ? X509_ATTRIBUTE_get0_type(attr, 0)
	                                  : NULL;
	ASN1_OBJECT_free(oid);
	libssig_cades_v131_hash_index* index = NULL;
	if (index_value && index_value->type == V_ASN1_SEQUENCE) {
		cursor = ASN1_STRING_get0_data(index_value->value.sequence);
		index = d2i_libssig_cades_v131_hash_index(
		    NULL,
		    &cursor,
		    ASN1_STRING_length(index_value->value.sequence)
		);
	}
	int nid = index ? OBJ_obj2nid(index->algorithm->algorithm) : NID_undef;
	libssig_hash     hash = nid == NID_sha256   ? LIBSSIG_HASH_SHA256
	                        : nid == NID_sha384 ? LIBSSIG_HASH_SHA384
	                                            : LIBSSIG_HASH_SHA512;
	const EVP_MD*    md = nid == NID_sha256 || nid == NID_sha384 ||
                               nid == NID_sha512
	                          ? libssig_timestamp_digest(hash)
	                          : NULL;
	libssig_raw_cms* raw = libssig_cms_decode(cms);
	CMS_SignerInfo*  signer = sk_CMS_SignerInfo_value(
        CMS_get0_SignerInfos(cms),
        signer_index
    );
	libssig_cades_v131_hash_index*
	     current = raw && md ? libssig_cades_v131_archive_index(raw, signer, md)
	                         : NULL;
	bool ok = index && current && index_matches(index->certs, current->certs) &&
	          index_matches(index->revocations, current->revocations) &&
	          index_matches(index->attributes, current->attributes);
	if (ok) {
		*complete = sk_ASN1_OCTET_STRING_num(index->certs) ==
		                sk_ASN1_OCTET_STRING_num(current->certs) &&
		            sk_ASN1_OCTET_STRING_num(index->revocations) ==
		                sk_ASN1_OCTET_STRING_num(current->revocations) &&
		            sk_ASN1_OCTET_STRING_num(index->attributes) + 1 ==
		                sk_ASN1_OCTET_STRING_num(current->attributes);
	}
	unsigned char         imprint[EVP_MAX_MD_SIZE];
	unsigned int          imprint_len = 0;
	libssig_extend_params context = {
	    .content = params->content,
	    .content_len = params->content_len,
	    .hash = hash
	};
	if (ok) {
		ok = libssig_cades_v131_archive_imprint(
		    cms,
		    raw,
		    (size_t)signer_index,
		    &context,
		    ASN1_STRING_get0_data(index_value->value.sequence),
		    (size_t)ASN1_STRING_length(index_value->value.sequence),
		    imprint,
		    &imprint_len
		);
	}
	libssig_verify_params anchor = *params;
	if (*complete) {
		anchor.options &= ~LIBSSIG_VERIFY_HISTORICAL;
	}
	libssig_status status = ok ? libssig_verify_timestamp_token(
	                                 token,
	                                 &anchor,
	                                 md,
	                                 imprint,
	                                 imprint_len,
	                                 result
	                             )
	                           : LIBSSIG_ERROR_TIMESTAMP;
	libssig_cades_v131_hash_index_free(current);
	libssig_cades_v131_hash_index_free(index);
	libssig_raw_cms_free(raw);
	CMS_ContentInfo_free(token);
	return status;
}
libssig_status libssig_cades_v131_verify_archives(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	ASN1_OBJECT* oid = OBJ_txt2obj(LIBSSIG_ARCHIVE_OID, 1);
	if (!oid) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	libssig_status status = LIBSSIG_OK;
	for (size_t i = 0; status == LIBSSIG_OK && i < result->count; ++i) {
		result->signers[i].archive.status = LIBSSIG_ERROR_NOT_FOUND;
		CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
		    CMS_get0_SignerInfos(cms),
		    (int)i
		);

		int  pos = -1;
		bool found = false;
		int  count = 0;
		while ((pos = CMS_unsigned_get_attr_by_OBJ(signer, oid, pos)) >= 0) {
			if (++count > 1024) {
				status = LIBSSIG_ERROR_TIMESTAMP;
				break;
			}
			X509_ATTRIBUTE*          attr = CMS_unsigned_get_attr(signer, pos);
			libssig_verify_timestamp stamp = {.present = true};
			bool                     complete = false;
			status = X509_ATTRIBUTE_count(attr) == 1
			             ? archive_verify(
			                   cms,
			                   (int)i,
			                   X509_ATTRIBUTE_get0_type(attr, 0),
			                   params,
			                   &stamp,
			                   &complete
			               )
			             : LIBSSIG_ERROR_TIMESTAMP;
			stamp.status = status;
			if (complete || !found || status != LIBSSIG_OK) {
				free(result->signers[i].archive.cert_der);
				result->signers[i].archive = stamp;
				stamp.cert_der = NULL;
			}
			found = found || complete;
			free(stamp.cert_der);
			if (status != LIBSSIG_OK) {
				break;
			}
		}
		if (status == LIBSSIG_OK &&
		    (params->options & LIBSSIG_VERIFY_HISTORICAL) && count && !found) {
			status = LIBSSIG_ERROR_TIMESTAMP;
		}
		if (status == LIBSSIG_OK && count > 1 &&
		    (params->options & LIBSSIG_VERIFY_HISTORICAL)) {
			libssig_raw_cms*        raw = libssig_cms_decode(cms);
			libssig_validation_data evidence = {
			    .certs = CMS_get1_certs(cms),
			    .revocations = raw ? raw->signed_data->revocations : NULL
			};
			if (!raw || !evidence.certs) {
				status = LIBSSIG_ERROR_EVIDENCE;
			}
			pos = -1;
			while (status == LIBSSIG_OK &&
			       (pos = CMS_unsigned_get_attr_by_OBJ(signer, oid, pos)) >=
			           0) {
				X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(signer, pos);
				libssig_verify_timestamp stamp = {0};
				bool                     complete = false;
				status = archive_verify(
				    cms,
				    (int)i,
				    X509_ATTRIBUTE_get0_type(attr, 0),
				    params,
				    &stamp,
				    &complete
				);
				if (status == LIBSSIG_OK && !complete) {
					status = libssig_document_evidence_stamp_check(
					    &stamp,
					    &result->signers[i].archive,
					    &evidence,
					    params
					);
				}
				free(stamp.cert_der);
			}
			sk_X509_pop_free(evidence.certs, X509_free);
			libssig_raw_cms_free(raw);
		}
	}
	ASN1_OBJECT_free(oid);
	return status == LIBSSIG_OK || status == LIBSSIG_ERROR_TRUST
	           ? status
	           : LIBSSIG_ERROR_TIMESTAMP;
}
