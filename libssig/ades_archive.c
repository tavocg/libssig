/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ades_internal.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static libssig_raw_cms* raw_decode(CMS_ContentInfo* cms) {
	unsigned char*       bytes = NULL;
	int                  len = i2d_CMS_ContentInfo(cms, &bytes);
	const unsigned char* cursor = bytes;
	libssig_raw_cms*     raw = len > 0 ? d2i_libssig_raw_cms(NULL, &cursor, len)
	                                   : NULL;
	OPENSSL_free(bytes);
	return raw;
}
static libssig_status raw_replace(libssig_raw_cms* raw, CMS_ContentInfo** cms) {
	unsigned char*       bytes = NULL;
	int                  len = i2d_libssig_raw_cms(raw, &bytes);
	const unsigned char* cursor = bytes;
	CMS_ContentInfo*     replaced = len > 0
	                                    ? d2i_CMS_ContentInfo(NULL, &cursor, len)
	                                    : NULL;
	OPENSSL_free(bytes);
	if (!replaced) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	CMS_ContentInfo_free(*cms);
	*cms = replaced;
	return LIBSSIG_OK;
}
libssig_status libssig_validation_embed(
    CMS_ContentInfo**              cms,
    const libssig_validation_data* data
) {
	for (int i = 0; i < sk_X509_num(data->certs); ++i) {
		X509* cert = sk_X509_value(data->certs, i);
		STACK_OF(X509)* existing = CMS_get1_certs(*cms);
		bool found = false;
		for (int j = 0; j < sk_X509_num(existing); ++j) {
			if (X509_cmp(cert, sk_X509_value(existing, j)) == 0) {
				found = true;
				break;
			}
		}
		sk_X509_pop_free(existing, X509_free);
		if (!found && !CMS_add1_cert(*cms, cert)) {
			return LIBSSIG_ERROR_CRYPTO;
		}
	}
	libssig_raw_cms* raw = raw_decode(*cms);
	if (!raw) {
		return LIBSSIG_ERROR_FORMAT;
	}
	if (!raw->signed_data->revocations) {
		raw->signed_data->revocations = sk_ASN1_TYPE_new_null();
	}
	bool ok = raw->signed_data->revocations != NULL;
	for (int i = 0; ok && i < sk_ASN1_TYPE_num(data->revocations); ++i) {
		ASN1_TYPE* value = ASN1_TYPE_new();
		ok = value && ASN1_TYPE_set1(
		                  value,
		                  sk_ASN1_TYPE_value(data->revocations, i)->type,
		                  sk_ASN1_TYPE_value(data->revocations, i)->value.ptr
		              );
		if (ok) {
			ok = sk_ASN1_TYPE_push(raw->signed_data->revocations, value) != 0;
		}
		if (!ok) {
			ASN1_TYPE_free(value);
		}
	}
	for (int i = 0; ok && i < sk_ASN1_TYPE_num(raw->signed_data->revocations);
	     ++i) {
		if (sk_ASN1_TYPE_value(raw->signed_data->revocations, i)->type ==
		    V_ASN1_OTHER) {
			ok = ASN1_INTEGER_set(raw->signed_data->version, 5);
		}
	}
	libssig_status status = ok ? raw_replace(raw, cms) : LIBSSIG_ERROR_CRYPTO;
	libssig_raw_cms_free(raw);
	return status;
}
static bool hash_push(
    STACK_OF(ASN1_OCTET_STRING) * values,
    const EVP_MD*        md,
    const unsigned char* a,
    size_t               a_len,
    const unsigned char* b,
    size_t               b_len
) {
	EVP_MD_CTX*   ctx = EVP_MD_CTX_new();
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int  len = 0;
	bool          ok = ctx && EVP_DigestInit_ex(ctx, md, NULL) &&
	          EVP_DigestUpdate(ctx, a, a_len) &&
	          (!b_len || EVP_DigestUpdate(ctx, b, b_len)) &&
	          EVP_DigestFinal_ex(ctx, hash, &len);
	ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
	ok = ok && value && ASN1_OCTET_STRING_set(value, hash, (int)len);
	if (ok) {
		ok = sk_ASN1_OCTET_STRING_push(values, value) != 0;
	}
	if (!ok) {
		ASN1_OCTET_STRING_free(value);
	}
	EVP_MD_CTX_free(ctx);
	return ok;
}
static bool index_values(
    STACK_OF(ASN1_TYPE) * source,
    STACK_OF(ASN1_OCTET_STRING) * target,
    const EVP_MD* md
) {
	for (int i = 0; i < sk_ASN1_TYPE_num(source); ++i) {
		unsigned char* bytes = NULL;
		int  len = i2d_ASN1_TYPE(sk_ASN1_TYPE_value(source, i), &bytes);
		bool ok = len > 0 && hash_push(target, md, bytes, (size_t)len, NULL, 0);
		OPENSSL_free(bytes);
		if (!ok) {
			return false;
		}
	}
	return true;
}
static libssig_hash_index* index_create(
    libssig_raw_cms* raw,
    CMS_SignerInfo*  signer,
    const EVP_MD*    md
) {
	libssig_hash_index* index = libssig_hash_index_new();
	if (!index) {
		return NULL;
	}
	X509_ALGOR_set_md(index->algorithm, md);
	bool ok = index_values(raw->signed_data->certs, index->certs, md) &&
	          index_values(
	              raw->signed_data->revocations,
	              index->revocations,
	              md
	          );
	for (int i = 0; ok && i < CMS_unsigned_get_attr_count(signer); ++i) {
		X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(signer, i);
		unsigned char*  oid = NULL;
		int oid_len = i2d_ASN1_OBJECT(X509_ATTRIBUTE_get0_object(attr), &oid);
		for (int j = 0; ok && j < X509_ATTRIBUTE_count(attr); ++j) {
			unsigned char* bytes = NULL;
			int len = i2d_ASN1_TYPE(X509_ATTRIBUTE_get0_type(attr, j), &bytes);
			ok = oid_len > 0 && len > 0 &&
			     hash_push(
			         index->attributes,
			         md,
			         oid,
			         (size_t)oid_len,
			         bytes,
			         (size_t)len
			     );
			OPENSSL_free(bytes);
		}
		OPENSSL_free(oid);
	}
	if (!ok) {
		libssig_hash_index_free(index);
		index = NULL;
	}
	return index;
}
/* Feed the DER fields of SignerInfo, excluding its SEQUENCE header and
 * unsignedAttrs. The field encodings are preserved by ASN1_ANY above. */
static bool signer_hash(EVP_MD_CTX* ctx, ASN1_TYPE* signer) {
	unsigned char*       bytes = NULL;
	int                  len = i2d_ASN1_TYPE(signer, &bytes);
	const unsigned char* cursor = bytes;
	long                 body_len = 0;
	int                  tag = 0, cls = 0;
	bool                 ok = len > 0 &&
	          !(ASN1_get_object(&cursor, &body_len, &tag, &cls, len) & 0x80) &&
	          tag == V_ASN1_SEQUENCE && cls == V_ASN1_UNIVERSAL;
	const unsigned char* end = ok ? cursor + body_len : cursor;
	while (ok && cursor < end) {
		const unsigned char* start = cursor;
		long                 value_len = 0;
		int                  flags = ASN1_get_object(
            &cursor,
            &value_len,
            &tag,
            &cls,
            (long)(end - cursor)
        );
		ok = !(flags & 0x81) && value_len >= 0 && value_len <= end - cursor;
		if (!ok) {
			break;
		}
		cursor += value_len;
		if (cls == V_ASN1_CONTEXT_SPECIFIC && tag == 1) {
			ok = cursor == end;
			break;
		}
		ok = EVP_DigestUpdate(ctx, start, (size_t)(cursor - start));
	}
	OPENSSL_free(bytes);
	return ok;
}
static bool archive_imprint(
    CMS_ContentInfo*             cms,
    libssig_raw_cms*             raw,
    size_t                       index,
    const libssig_extend_params* params,
    const unsigned char*         hash_index,
    size_t                       hash_index_len,
    unsigned char*               hash,
    unsigned int*                hash_len
) {
	const EVP_MD*        md = libssig_timestamp_digest(params->hash);
	ASN1_OCTET_STRING**  attached = CMS_get0_content(cms);
	const unsigned char* content = attached && *attached
	                                   ? ASN1_STRING_get0_data(*attached)
	                                   : params->content;
	size_t               content_len = attached && *attached
	                                       ? (size_t)ASN1_STRING_length(*attached)
	                                       : params->content_len;
	if (!md || (!content && CMS_is_detached(cms))) {
		return false;
	}
	unsigned char  content_hash[EVP_MAX_MD_SIZE];
	unsigned int   content_hash_len = 0;
	unsigned char* type = NULL;
	int         type_len = i2d_ASN1_OBJECT(CMS_get0_eContentType(cms), &type);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	bool        ok = type_len > 0 && ctx &&
	          EVP_Digest(
	              content,
	              content_len,
	              content_hash,
	              &content_hash_len,
	              md,
	              NULL
	          ) &&
	          EVP_DigestInit_ex(ctx, md, NULL) &&
	          EVP_DigestUpdate(ctx, type, (size_t)type_len) &&
	          EVP_DigestUpdate(ctx, content_hash, content_hash_len) &&
	          signer_hash(
	              ctx,
	              sk_ASN1_TYPE_value(raw->signed_data->signers, (int)index)
	          ) &&
	          EVP_DigestUpdate(ctx, hash_index, hash_index_len) &&
	          EVP_DigestFinal_ex(ctx, hash, hash_len);
	EVP_MD_CTX_free(ctx);
	OPENSSL_free(type);
	return ok;
}
static libssig_status archive_token(
    const libssig_extend_params* params,
    const libssig_signature*     query,
    const unsigned char*         hash_index,
    int                          index_len,
    libssig_signature*           token_der
) {
	libssig_signature response = {0};
	libssig_status    status = libssig_ades_response(
        params->services,
        query,
        &response
    );
	const unsigned char* cursor = response.data;
	TS_RESP*             reply = status == LIBSSIG_OK
	                                 ? d2i_TS_RESP(NULL, &cursor, (long)response.len)
	                                 : NULL;
	unsigned char*       bytes = NULL;
	int len = reply ? i2d_PKCS7(TS_RESP_get_token(reply), &bytes) : 0;
	cursor = bytes;
	CMS_ContentInfo* token = len > 0 ? d2i_CMS_ContentInfo(NULL, &cursor, len)
	                                 : NULL;
	STACK_OF(CMS_SignerInfo)* signers = token ? CMS_get0_SignerInfos(token)
	                                          : NULL;
	if (status == LIBSSIG_OK) {
		CMS_SignerInfo* s = sk_CMS_SignerInfo_num(signers) == 1
		                        ? sk_CMS_SignerInfo_value(signers, 0)
		                        : NULL;
		ASN1_OBJECT*    oid = OBJ_txt2obj(LIBSSIG_HASH_INDEX_OID, 1);
		bool            ok = s && oid &&
		          CMS_unsigned_add1_attr_by_OBJ(
		              s,
		              oid,
		              V_ASN1_SEQUENCE,
		              hash_index,
		              index_len
		          );
		ASN1_OBJECT_free(oid);
		status = ok ? libssig_ades_encode(token, token_der)
		            : LIBSSIG_ERROR_CRYPTO;
	}
	CMS_ContentInfo_free(token);
	TS_RESP_free(reply);
	OPENSSL_free(bytes);
	libssig_signature_free(&response);
	return status;
}
libssig_status libssig_archive_apply(
    CMS_ContentInfo**            cms,
    const libssig_extend_params* params
) {
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(*cms);
	for (int i = 0; i < sk_CMS_SignerInfo_num(signers); ++i) {
		CMS_SignerInfo*     signer = sk_CMS_SignerInfo_value(signers, i);
		libssig_raw_cms*    raw = raw_decode(*cms);
		libssig_hash_index* index = raw ? index_create(
		                                      raw,
		                                      signer,
		                                      libssig_timestamp_digest(
		                                          params->hash
		                                      )
		                                  )
		                                : NULL;
		unsigned char*      encoded = NULL;
		int           len = index ? i2d_libssig_hash_index(index, &encoded) : 0;
		unsigned char imprint[EVP_MAX_MD_SIZE];
		unsigned int  imprint_len = 0;
		bool          ok = len > 0 && archive_imprint(
                                 *cms,
                                 raw,
                                 (size_t)i,
                                 params,
                                 encoded,
                                 (size_t)len,
                                 imprint,
                                 &imprint_len
                             );
		libssig_signature request = {0}, token = {0};
		libssig_status    status = ok ? libssig_ades_query(
                                         imprint,
                                         imprint_len,
                                         params->hash,
                                         &request
                                     )
		                              : LIBSSIG_ERROR_CRYPTO;
		if (status == LIBSSIG_OK) {
			status = archive_token(params, &request, encoded, len, &token);
		}
		if (status == LIBSSIG_OK) {
			ASN1_OBJECT* oid = OBJ_txt2obj(LIBSSIG_ARCHIVE_OID, 1);
			ok = oid && CMS_unsigned_add1_attr_by_OBJ(
			                signer,
			                oid,
			                V_ASN1_SEQUENCE,
			                token.data,
			                (int)token.len
			            );
			ASN1_OBJECT_free(oid);
			if (!ok) {
				status = LIBSSIG_ERROR_CRYPTO;
			}
		}
		libssig_signature_free(&request);
		libssig_signature_free(&token);
		OPENSSL_free(encoded);
		libssig_hash_index_free(index);
		libssig_raw_cms_free(raw);
		if (status != LIBSSIG_OK) {
			return status;
		}
	}
	return LIBSSIG_OK;
}

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
    libssig_verify_timestamp*    result
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
	libssig_hash_index* index = NULL;
	if (index_value && index_value->type == V_ASN1_SEQUENCE) {
		cursor = ASN1_STRING_get0_data(index_value->value.sequence);
		index = d2i_libssig_hash_index(
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
	libssig_raw_cms* raw = raw_decode(cms);
	CMS_SignerInfo*  signer = sk_CMS_SignerInfo_value(
        CMS_get0_SignerInfos(cms),
        signer_index
    );
	libssig_hash_index* current = raw && md ? index_create(raw, signer, md)
	                                        : NULL;
	bool ok = index && current && index_matches(index->certs, current->certs) &&
	          index_matches(index->revocations, current->revocations) &&
	          index_matches(index->attributes, current->attributes);
	if (ok && (params->options & LIBSSIG_VERIFY_HISTORICAL)) {
		ok = sk_ASN1_OCTET_STRING_num(index->certs) ==
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
		ok = archive_imprint(
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
	anchor.options &= ~LIBSSIG_VERIFY_HISTORICAL;
	libssig_status status = ok ? libssig_verify_timestamp_token(
	                                 token,
	                                 &anchor,
	                                 md,
	                                 imprint,
	                                 imprint_len,
	                                 result
	                             )
	                           : LIBSSIG_ERROR_TIMESTAMP;
	libssig_hash_index_free(current);
	libssig_hash_index_free(index);
	libssig_raw_cms_free(raw);
	CMS_ContentInfo_free(token);
	return status;
}
libssig_status libssig_verify_archives(
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
		int pos = -1;
		while ((pos = CMS_unsigned_get_attr_by_OBJ(signer, oid, pos)) >= 0) {
			X509_ATTRIBUTE*          attr = CMS_unsigned_get_attr(signer, pos);
			libssig_verify_timestamp stamp = {.present = true};
			status = X509_ATTRIBUTE_count(attr) == 1
			             ? archive_verify(
			                   cms,
			                   (int)i,
			                   X509_ATTRIBUTE_get0_type(attr, 0),
			                   params,
			                   &stamp
			               )
			             : LIBSSIG_ERROR_TIMESTAMP;
			stamp.status = status;
			free(result->signers[i].archive.cert_der);
			result->signers[i].archive = stamp;
			if (status != LIBSSIG_OK) {
				break;
			}
		}
	}
	ASN1_OBJECT_free(oid);
	return status == LIBSSIG_OK || status == LIBSSIG_ERROR_TRUST
	           ? status
	           : LIBSSIG_ERROR_TIMESTAMP;
}
