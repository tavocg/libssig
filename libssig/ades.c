/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ades.h>

ASN1_SEQUENCE(libssig_raw_signed_data) =
    {
        ASN1_SIMPLE(libssig_raw_signed_data, version, ASN1_INTEGER),
        ASN1_SET_OF(libssig_raw_signed_data, algorithms, ASN1_ANY),
        ASN1_SIMPLE(libssig_raw_signed_data, content, ASN1_ANY),
        ASN1_IMP_SET_OF_OPT(libssig_raw_signed_data, certs, ASN1_ANY, 0),
        ASN1_IMP_SET_OF_OPT(libssig_raw_signed_data, revocations, ASN1_ANY, 1),
        ASN1_SET_OF(libssig_raw_signed_data, signers, ASN1_ANY),
} ASN1_SEQUENCE_END(libssig_raw_signed_data) IMPLEMENT_ASN1_FUNCTIONS(libssig_raw_signed_data)

        ASN1_SEQUENCE(libssig_raw_cms) =
            {
                ASN1_SIMPLE(libssig_raw_cms, type, ASN1_OBJECT),
                ASN1_EXP(
                    libssig_raw_cms,
                    signed_data,
                    libssig_raw_signed_data,
                    0
                ),
} ASN1_SEQUENCE_END(libssig_raw_cms) IMPLEMENT_ASN1_FUNCTIONS(libssig_raw_cms)

                ASN1_SEQUENCE(libssig_cades_v131_hash_index) =
                    {
                        ASN1_SIMPLE(
                            libssig_cades_v131_hash_index,
                            algorithm,
                            X509_ALGOR
                        ),
                        ASN1_SEQUENCE_OF(
                            libssig_cades_v131_hash_index,
                            certs,
                            ASN1_OCTET_STRING
                        ),
                        ASN1_SEQUENCE_OF(
                            libssig_cades_v131_hash_index,
                            revocations,
                            ASN1_OCTET_STRING
                        ),
                        ASN1_SEQUENCE_OF(
                            libssig_cades_v131_hash_index,
                            attributes,
                            ASN1_OCTET_STRING
                        ),
} ASN1_SEQUENCE_END(libssig_cades_v131_hash_index) IMPLEMENT_ASN1_FUNCTIONS(libssig_cades_v131_hash_index)

                        libssig_raw_cms
                    * libssig_cms_decode(CMS_ContentInfo * cms) {
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
	libssig_raw_cms* raw = libssig_cms_decode(*cms);
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
libssig_cades_v131_hash_index* libssig_cades_v131_archive_index(
    libssig_raw_cms* raw,
    CMS_SignerInfo*  signer,
    const EVP_MD*    md
) {
	libssig_cades_v131_hash_index* index = libssig_cades_v131_hash_index_new();
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
		libssig_cades_v131_hash_index_free(index);
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
bool libssig_cades_v131_archive_imprint(
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

bool libssig_level_valid(libssig_level level) {
	return level == LIBSSIG_LEVEL_B_B || level == LIBSSIG_LEVEL_B_T ||
	       level == LIBSSIG_LEVEL_B_LT || level == LIBSSIG_LEVEL_B_LTA;
}
libssig_status libssig_cms_encode(
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

void libssig_validation_free(libssig_validation_data* data) {
	sk_X509_pop_free(data->certs, X509_free);
	sk_ASN1_TYPE_pop_free(data->revocations, ASN1_TYPE_free);
	*data = (libssig_validation_data){0};
}
