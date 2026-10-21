/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <stdlib.h>
#include <string.h>

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
		libssig_raw_cms*    raw = libssig_cms_decode(*cms);
		libssig_hash_index* index = raw ? libssig_archive_index(
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
		bool          ok = len > 0 && libssig_archive_imprint(
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
