/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_DOCUMENT_H
#define LIBSSIG_DOCUMENT_H
#include <libssig/libssig.h>
#include <libssig/validation.h>

#define LIBSSIG_DOCUMENT_LIMIT (32u * 1024u * 1024u)
/* Internal byte/crypto services shared by the JSON and XML implementations. */
bool libssig_bytes_append(
    libssig_signature* bytes,
    const void*        data,
    size_t             len
);
char* libssig_base64(const void* data, size_t len, bool url);
bool  libssig_base64_read(
     const char*        text,
     size_t             len,
     bool               url,
     libssig_signature* bytes
 );
bool libssig_document_digest(
    const void*    data,
    size_t         len,
    libssig_hash   hash,
    unsigned char* digest,
    unsigned int*  out_len
);
bool libssig_document_signature_check(
    X509*                    cert,
    libssig_algo             algo,
    libssig_hash             hash,
    const void*              data,
    size_t                   len,
    const libssig_signature* signature
);
libssig_status libssig_document_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const libssig_signature*   input,
    libssig_signature*         output
);
libssig_status libssig_document_stamp(
    const libssig_signature*     input,
    libssig_hash                 hash,
    const libssig_sign_services* services,
    libssig_signature*           token
);
libssig_status libssig_document_stamp_verify(
    const libssig_signature*     input,
    const libssig_signature*     token,
    const libssig_verify_params* params,
    libssig_verify_timestamp*    result
);
libssig_status libssig_document_validate(
    X509*                          cert,
    const libssig_validation_data* evidence,
    const libssig_verify_params*   params,
    libssig_verify_result*         result
);
libssig_format libssig_document_format(const unsigned char* data, size_t len);

libssig_status libssig_jades_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         output
);
libssig_status libssig_xades_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         output
);
libssig_status libssig_jades_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
);
libssig_status libssig_xades_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
);
libssig_status libssig_jades_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
libssig_status libssig_xades_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
libssig_status libssig_document_evidence_verify(
    X509*                          cert,
    const libssig_validation_data* evidence,
    const libssig_verify_params*   params,
    libssig_verify_result*         result,
    bool                           historical
);
libssig_status libssig_document_timestamp_request(
    const libssig_timestamp_request_params* params,
    libssig_signature*                      output
);
libssig_status libssig_document_timestamp(
    const libssig_timestamp_params* params,
    libssig_signature*              output
);
libssig_status libssig_document_evidence_stamp_check(
    const libssig_verify_timestamp* stamp,
    const libssig_verify_timestamp* archive,
    const libssig_validation_data*  evidence,
    const libssig_verify_params*    params
);
#endif
