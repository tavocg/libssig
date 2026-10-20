/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_ADES_INTERNAL_H
#define LIBSSIG_ADES_INTERNAL_H
#include <libssig/timestamp_internal.h>
#include <openssl/asn1t.h>
#include <openssl/ocsp.h>

DEFINE_STACK_OF(ASN1_OCTET_STRING)

#define LIBSSIG_ARCHIVE_OID "0.4.0.1733.2.4"
#define LIBSSIG_HASH_INDEX_OID "0.4.0.19122.1.5"

typedef struct {
	ASN1_INTEGER* version;
	STACK_OF(ASN1_TYPE) * algorithms;
	ASN1_TYPE* content;
	STACK_OF(ASN1_TYPE) * certs;
	STACK_OF(ASN1_TYPE) * revocations;
	STACK_OF(ASN1_TYPE) * signers;
} libssig_raw_signed_data;
DECLARE_ASN1_FUNCTIONS(libssig_raw_signed_data)
typedef struct {
	ASN1_OBJECT*             type;
	libssig_raw_signed_data* signed_data;
} libssig_raw_cms;
DECLARE_ASN1_FUNCTIONS(libssig_raw_cms)

typedef struct {
	X509_ALGOR* algorithm;
	STACK_OF(ASN1_OCTET_STRING) * certs;
	STACK_OF(ASN1_OCTET_STRING) * revocations;
	STACK_OF(ASN1_OCTET_STRING) * attributes;
} libssig_hash_index;
DECLARE_ASN1_FUNCTIONS(libssig_hash_index)

typedef struct {
	STACK_OF(X509) * certs;
	STACK_OF(ASN1_TYPE) * revocations;
} libssig_validation_data;

libssig_status libssig_verify_archives(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
libssig_status libssig_verify_timestamp_token(
    CMS_ContentInfo*             token,
    const libssig_verify_params* params,
    const EVP_MD*                digest,
    const unsigned char*         imprint,
    size_t                       imprint_len,
    libssig_verify_timestamp*    result
);
bool           libssig_level_valid(libssig_level level);
libssig_status libssig_ades_encode(
    CMS_ContentInfo*   cms,
    libssig_signature* output
);
libssig_status libssig_ades_fetch(
    const libssig_sign_services* services,
    libssig_fetch_kind           kind,
    const char*                  url,
    const unsigned char*         data,
    size_t                       len,
    libssig_signature*           response
);
libssig_status libssig_ades_query(
    const unsigned char* imprint,
    size_t               len,
    libssig_hash         hash,
    libssig_signature*   request
);
libssig_status libssig_ades_response(
    const libssig_sign_services* services,
    const libssig_signature*     request,
    libssig_signature*           response
);
libssig_status libssig_validation_tsa_certs(
    PKCS7*                       token,
    const libssig_sign_services* services,
    STACK_OF(X509) * *chain
);
libssig_status libssig_validation_collect(
    CMS_ContentInfo*             cms,
    const libssig_sign_services* services,
    libssig_validation_data*     validation
);
void           libssig_validation_free(libssig_validation_data* data);
libssig_status libssig_validation_embed(
    CMS_ContentInfo**              cms,
    const libssig_validation_data* data
);
libssig_status libssig_ades_stamps(
    CMS_ContentInfo*             cms,
    const libssig_extend_params* params
);
libssig_status libssig_archive_apply(
    CMS_ContentInfo**            cms,
    const libssig_extend_params* params
);
libssig_status libssig_pades_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
);
libssig_status libssig_pades_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
libssig_status libssig_pades_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         signature
);
#endif
