/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_ADES_H
#define LIBSSIG_ADES_H

#include <libssig/hash.h>
#include <libssig/libssig.h>
#include <openssl/asn1t.h>
#include <openssl/cms.h>

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
} libssig_cades_v131_hash_index;
DECLARE_ASN1_FUNCTIONS(libssig_cades_v131_hash_index)

typedef struct {
	STACK_OF(X509) * certs;
	STACK_OF(ASN1_TYPE) * revocations;
} libssig_validation_data;

libssig_raw_cms*               libssig_cms_decode(CMS_ContentInfo* cms);
libssig_cades_v131_hash_index* libssig_cades_v131_archive_index(
    libssig_raw_cms* raw,
    CMS_SignerInfo*  signer,
    const EVP_MD*    md
);
bool libssig_cades_v131_archive_imprint(
    CMS_ContentInfo*             cms,
    libssig_raw_cms*             raw,
    size_t                       index,
    const libssig_extend_params* params,
    const unsigned char*         hash_index,
    size_t                       hash_index_len,
    unsigned char*               hash,
    unsigned int*                hash_len
);
libssig_status libssig_validation_embed(
    CMS_ContentInfo**              cms,
    const libssig_validation_data* data
);
bool           libssig_level_valid(libssig_level level);
libssig_status libssig_cms_encode(
    CMS_ContentInfo*   cms,
    libssig_signature* output
);
void libssig_validation_free(libssig_validation_data* data);

#endif
