/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ades_internal.h>

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

                ASN1_SEQUENCE(libssig_hash_index) = {
                    ASN1_SIMPLE(libssig_hash_index, algorithm, X509_ALGOR),
                    ASN1_SEQUENCE_OF(
                        libssig_hash_index,
                        certs,
                        ASN1_OCTET_STRING
                    ),
                    ASN1_SEQUENCE_OF(
                        libssig_hash_index,
                        revocations,
                        ASN1_OCTET_STRING
                    ),
                    ASN1_SEQUENCE_OF(
                        libssig_hash_index,
                        attributes,
                        ASN1_OCTET_STRING
                    ),
} ASN1_SEQUENCE_END(libssig_hash_index) IMPLEMENT_ASN1_FUNCTIONS(libssig_hash_index)
