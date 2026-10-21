/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/document.h>
#include <libssig/pdf.h>
#include <limits.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <string.h>

static libssig_status dss_certs(qpdf_data pdf, BIO* pem) {
	qpdf_oh dss = qpdf_oh_get_key(pdf, qpdf_get_root(pdf), "/DSS");
	if (qpdf_oh_is_null(pdf, dss)) {
		return LIBSSIG_OK;
	}
	qpdf_oh certs = qpdf_oh_get_key(pdf, dss, "/Certs");
	if (qpdf_oh_is_null(pdf, certs)) {
		return LIBSSIG_OK;
	}
	if (!qpdf_oh_is_array(pdf, certs) ||
	    qpdf_oh_get_array_n_items(pdf, certs) > 1024) {
		return LIBSSIG_ERROR_FORMAT;
	}
	for (int i = 0; i < qpdf_oh_get_array_n_items(pdf, certs); ++i) {
		qpdf_oh        stream = qpdf_oh_get_array_item(pdf, certs, i);
		unsigned char* data = NULL;
		size_t         len = 0;
		if (!qpdf_oh_is_stream(pdf, stream) ||
		    qpdf_oh_get_stream_data(
		        pdf,
		        stream,
		        qpdf_dl_all,
		        NULL,
		        &data,
		        &len
		    ) != QPDF_SUCCESS ||
		    len > 16 * 1024 * 1024) {
			free(data);
			return LIBSSIG_ERROR_FORMAT;
		}
		const unsigned char* cursor = data;
		X509*                cert = d2i_X509(NULL, &cursor, (long)len);
		bool                 ok = cert && cursor == data + len &&
		          PEM_write_bio_X509(pem, cert) == 1;
		X509_free(cert);
		free(data);
		if (!ok) {
			return LIBSSIG_ERROR_FORMAT;
		}
	}
	return LIBSSIG_OK;
}
static libssig_status result_append(
    libssig_verify_result* result,
    libssig_verify_result* item
) {
	if (result->count + item->count > 1024) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_verify_signer* signers = realloc(
	    result->signers,
	    (result->count + item->count) * sizeof(*signers)
	);
	if (!signers && item->count) {
		return LIBSSIG_ERROR_MEMORY;
	}
	result->signers = signers;
	if (item->count) {
		memcpy(
		    signers + result->count,
		    item->signers,
		    item->count * sizeof(*signers)
		);
	}
	bool first = result->count == 0;
	result->count += item->count;
	result->signature_valid = item->signature_valid &&
	                          (first || result->signature_valid);
	result->trusted = item->trusted && (first || result->trusted);
	result->trust_checked = item->trust_checked &&
	                        (first || result->trust_checked);
	free(item->signers);
	*item = (libssig_verify_result){0};
	return LIBSSIG_OK;
}
static libssig_status document_stamp(
    const libssig_pdf_signature* signature,
    const libssig_verify_params* params,
    libssig_verify_timestamp*    result
) {
	const unsigned char* cursor = signature->cms.data;
	CMS_ContentInfo*     token = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)signature->cms.len
    );
	ASN1_OCTET_STRING** content = token ? CMS_get0_content(token) : NULL;
	cursor = content && *content ? ASN1_STRING_get0_data(*content) : NULL;
	TS_TST_INFO*    info = cursor ? d2i_TS_TST_INFO(
                                     NULL,
                                     &cursor,
                                     ASN1_STRING_length(*content)
                                 )
	                              : NULL;
	TS_MSG_IMPRINT* message = info ? TS_TST_INFO_get_msg_imprint(info) : NULL;
	int nid = message ? OBJ_obj2nid(TS_MSG_IMPRINT_get_algo(message)->algorithm)
	                  : NID_undef;
	const EVP_MD*  md = nid == NID_sha256   ? EVP_sha256()
	                    : nid == NID_sha384 ? EVP_sha384()
	                    : nid == NID_sha512 ? EVP_sha512()
	                                        : NULL;
	unsigned char  hash[EVP_MAX_MD_SIZE];
	unsigned int   len = 0;
	libssig_status status = md && EVP_Digest(
	                                  signature->content.data,
	                                  signature->content.len,
	                                  hash,
	                                  &len,
	                                  md,
	                                  NULL
	                              )
	                            ? libssig_verify_timestamp_token(
	                                  token,
	                                  params,
	                                  md,
	                                  hash,
	                                  len,
	                                  result
	                              )
	                            : LIBSSIG_ERROR_TIMESTAMP;
	TS_TST_INFO_free(info);
	CMS_ContentInfo_free(token);
	return status;
}
static libssig_status fields_verify(
    qpdf_data                    pdf,
    qpdf_oh                      fields,
    int                          depth,
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	if (depth > 16 || !qpdf_oh_is_array(pdf, fields) ||
	    qpdf_oh_get_array_n_items(pdf, fields) > 1024) {
		return LIBSSIG_ERROR_FORMAT;
	}
	libssig_status status = LIBSSIG_OK;
	for (int i = 0; i < qpdf_oh_get_array_n_items(pdf, fields); ++i) {
		qpdf_oh field = qpdf_oh_get_array_item(pdf, fields, i);
		qpdf_oh kids = qpdf_oh_get_key_if_dict(pdf, field, "/Kids");
		if (!qpdf_oh_is_null(pdf, kids)) {
			libssig_status
			    child = fields_verify(pdf, kids, depth + 1, params, result);
			if (child != LIBSSIG_OK) {
				return child;
			}
		}
		qpdf_oh value = qpdf_oh_get_key_if_dict(pdf, field, "/V");
		qpdf_oh type = qpdf_oh_get_key_if_dict(pdf, field, "/FT");
		if (!qpdf_oh_is_name_and_equals(pdf, type, "/Sig") ||
		    qpdf_oh_is_null(pdf, value)) {
			continue;
		}
		libssig_pdf_signature signature = {0};
		libssig_status        current = libssig_pdf_signature_read(
            pdf,
            value,
            params,
            &signature
        );
		if (current == LIBSSIG_OK && !signature.timestamp) {
			libssig_verify_params cms = *params;
			cms.options &= ~LIBSSIG_VERIFY_HISTORICAL;
			cms.options |= LIBSSIG_VERIFY_CURRENT_TIME;
			cms.current_revocations = NULL;
			cms.current_revocation_count = 0;
			cms.data = signature.cms.data;
			cms.data_len = signature.cms.len;
			cms.content = signature.content.data;
			cms.content_len = signature.content.len;
			libssig_verify_result item = {0};
			current = libssig_verify(&cms, &item);
			const unsigned char* cursor = signature.cms.data;
			CMS_ContentInfo*     parsed = item.count ? d2i_CMS_ContentInfo(
                                                       NULL,
                                                       &cursor,
                                                       (long)signature.cms.len
                                                   )
			                                         : NULL;
			if (parsed) {
				libssig_verify_profiles_detect(parsed, true, false, &item);
			}
			CMS_ContentInfo_free(parsed);
			if (item.count) {
				libssig_status appended = result_append(result, &item);
				if (appended != LIBSSIG_OK) {
					current = appended;
				}
			}
			libssig_verify_free(&item);
		} else if (current == LIBSSIG_OK) {
			libssig_verify_timestamp archive = {.present = true};
			libssig_verify_params    anchor = *params;
			anchor.options &= ~LIBSSIG_VERIFY_HISTORICAL;
			current = document_stamp(&signature, &anchor, &archive);
			if (result->count) {
				free(result->signers[result->count - 1].archive.cert_der);
				result->signers[result->count - 1].archive = archive;
			} else {
				free(archive.cert_der);
			}
		}
		libssig_signature_free(&signature.cms);
		libssig_signature_free(&signature.content);
		if (current != LIBSSIG_OK) {
			status = current;
		}
	}
	return status;
}
static libssig_status dss_revocations(
    qpdf_data   pdf,
    const char* key,
    STACK_OF(ASN1_TYPE) * items
) {
	qpdf_oh dss = qpdf_oh_get_key(pdf, qpdf_get_root(pdf), "/DSS");
	qpdf_oh array = qpdf_oh_get_key_if_dict(pdf, dss, key);
	if (qpdf_oh_is_null(pdf, array)) {
		return LIBSSIG_OK;
	}
	if (!qpdf_oh_is_array(pdf, array) ||
	    qpdf_oh_get_array_n_items(pdf, array) > 1024) {
		return LIBSSIG_ERROR_EVIDENCE;
	}
	for (int i = 0; i < qpdf_oh_get_array_n_items(pdf, array); ++i) {
		qpdf_oh        stream = qpdf_oh_get_array_item(pdf, array, i);
		unsigned char* data = NULL;
		size_t         len = 0;
		bool           ok = qpdf_oh_is_stream(pdf, stream) &&
		          qpdf_oh_get_stream_data(
		              pdf,
		              stream,
		              qpdf_dl_all,
		              NULL,
		              &data,
		              &len
		          ) == QPDF_SUCCESS &&
		          len > 0 && len <= 16 * 1024 * 1024;
		const unsigned char* cursor = data;
		ASN1_TYPE* value = ok ? d2i_ASN1_TYPE(NULL, &cursor, (long)len) : NULL;
		ok = value && cursor == data + len && sk_ASN1_TYPE_push(items, value);
		free(data);
		if (!ok) {
			ASN1_TYPE_free(value);
			return LIBSSIG_ERROR_EVIDENCE;
		}
	}
	return LIBSSIG_OK;
}

/* Initially support the single signature + final document timestamp produced
 * by this library. Reject ambiguous field trees and unsigned later revisions.
 */
static libssig_status pdf_validation(
    qpdf_data                    pdf,
    const libssig_verify_params* params,
    libssig_verify_result*       result,
    bool                         historical
) {
	qpdf_oh form = qpdf_oh_get_key(pdf, qpdf_get_root(pdf), "/AcroForm");
	qpdf_oh fields = qpdf_oh_get_key_if_dict(pdf, form, "/Fields");
	if (result->count != 1 ||
	    (historical ? (qpdf_oh_get_array_n_items(pdf, fields) < 2 ||
	                   qpdf_oh_get_array_n_items(pdf, fields) > 1024)
	                : qpdf_oh_get_array_n_items(pdf, fields) != 1)) {
		return LIBSSIG_ERROR_EVIDENCE;
	}
	libssig_pdf_signature document = {0}, archive = {0};
	qpdf_oh               first = qpdf_oh_get_array_item(pdf, fields, 0);
	qpdf_oh               last = historical ? qpdf_oh_get_array_item(
                                    pdf,
                                    fields,
                                    qpdf_oh_get_array_n_items(pdf, fields) - 1
                                )
	                                        : 0;
	libssig_status        status = libssig_pdf_signature_read(
        pdf,
        qpdf_oh_get_key(pdf, first, "/V"),
        params,
        &document
    );
	if (status == LIBSSIG_OK && historical) {
		status = libssig_pdf_signature_read(
		    pdf,
		    qpdf_oh_get_key(pdf, last, "/V"),
		    params,
		    &archive
		);
	}
	if (status == LIBSSIG_OK && historical &&
	    (document.timestamp || !archive.timestamp ||
	     archive.end != params->data_len ||
	     document.end > archive.hole_start)) {
		status = LIBSSIG_ERROR_EVIDENCE;
	}
	STACK_OF(ASN1_TYPE)* revocations = sk_ASN1_TYPE_new_null();
	if (status == LIBSSIG_OK) {
		status = revocations ? dss_revocations(pdf, "/OCSPs", revocations)
		                     : LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK) {
		status = dss_revocations(pdf, "/CRLs", revocations);
	}
	const unsigned char* cursor = document.cms.data;
	CMS_ContentInfo*     cms = cursor ? d2i_CMS_ContentInfo(
                                        NULL,
                                        &cursor,
                                        (long)document.cms.len
                                    )
	                                  : NULL;
	STACK_OF(X509)* certs = cms ? CMS_get1_certs(cms) : NULL;
	if (status == LIBSSIG_OK &&
	    (!cms || !CMS_set1_signers_certs(cms, certs, 0))) {
		status = LIBSSIG_ERROR_FORMAT;
	}
	if (status == LIBSSIG_OK) {
		free(result->signers[0].timestamp.cert_der);
		result->signers[0].timestamp = (libssig_verify_timestamp){0};
		status = libssig_verify_timestamps(cms, params, result);
	}
	if (status == LIBSSIG_OK) {
		BIO* pem = BIO_new(BIO_s_mem());
		status = pem ? dss_certs(pdf, pem) : LIBSSIG_ERROR_MEMORY;
		char* data = NULL;
		long  len = pem ? BIO_get_mem_data(pem, &data) : 0;
		STACK_OF(X509)* protected_certs = NULL;
		if (status == LIBSSIG_OK) {
			status = libssig_verify_certs_parse(
			    len > 0 ? (unsigned char*)data : NULL,
			    (size_t)(len > 0 ? len : 0),
			    &protected_certs
			);
		}
		if (status == LIBSSIG_OK) {
			status = libssig_validation_verify(
			    cms,
			    params,
			    revocations,
			    protected_certs,
			    historical,
			    result
			);
		}

		if (status == LIBSSIG_OK && historical) {
			libssig_validation_data evidence = {
			    .certs = protected_certs,
			    .revocations = revocations
			};
			size_t previous = document.end;
			for (int i = 1; status == LIBSSIG_OK &&
			                i + 1 < qpdf_oh_get_array_n_items(pdf, fields);
			     ++i) {
				qpdf_oh field = qpdf_oh_get_array_item(pdf, fields, i);
				libssig_pdf_signature old = {0};
				status = libssig_pdf_signature_read(
				    pdf,
				    qpdf_oh_get_key_if_dict(pdf, field, "/V"),
				    params,
				    &old
				);
				if (status == LIBSSIG_OK &&
				    (!old.timestamp || old.end <= previous ||
				     old.end > archive.hole_start)) {
					status = LIBSSIG_ERROR_EVIDENCE;
				}
				libssig_verify_timestamp stamp = {0};
				if (status == LIBSSIG_OK) {
					status = document_stamp(&old, params, &stamp);
				}
				if (status == LIBSSIG_OK) {
					status = libssig_document_evidence_stamp_check(
					    &stamp,
					    &result->signers[0].archive,
					    &evidence,
					    params
					);
				}
				previous = old.end;
				free(stamp.cert_der);
				libssig_signature_free(&old.cms);
				libssig_signature_free(&old.content);
			}
		}
		sk_X509_pop_free(protected_certs, X509_free);
		BIO_free(pem);
	}
	if (historical && status != LIBSSIG_OK &&
	    result->signers[0].history == LIBSSIG_HISTORY_NOT_CHECKED) {
		result->signers[0].history = status == LIBSSIG_ERROR_TRUST
		                                 ? LIBSSIG_HISTORY_UNTRUSTED
		                                 : LIBSSIG_HISTORY_INCOMPLETE;
	}
	sk_X509_pop_free(certs, X509_free);
	CMS_ContentInfo_free(cms);
	sk_ASN1_TYPE_pop_free(revocations, ASN1_TYPE_free);
	libssig_signature_free(&document.cms);
	libssig_signature_free(&document.content);
	libssig_signature_free(&archive.cms);
	libssig_signature_free(&archive.content);
	return status;
}

libssig_status libssig_pades_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	if (params->content || params->content_len || params->data_len > INT_MAX) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	qpdf_data pdf = qpdf_init();
	if (!pdf) {
		return LIBSSIG_ERROR_MEMORY;
	}
	qpdf_silence_errors(pdf);
	qpdf_set_suppress_warnings(pdf, QPDF_TRUE);
	qpdf_set_attempt_recovery(pdf, QPDF_FALSE);
	libssig_status status = qpdf_read_memory(
	                            pdf,
	                            "libssig verification",
	                            (const char*)params->data,
	                            params->data_len,
	                            NULL
	                        ) == QPDF_SUCCESS &&
	                                !qpdf_is_encrypted(pdf)
	                            ? LIBSSIG_OK
	                            : LIBSSIG_ERROR_FORMAT;
	BIO*           pem = BIO_new(BIO_s_mem());
	if (status == LIBSSIG_OK && !pem) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK) {
		status = dss_certs(pdf, pem);
	}
	libssig_verify_params copy = *params;
	STACK_OF(X509)* extra = NULL;
	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_parse(
		    params->intermediates_data,
		    params->intermediates_data_len,
		    &extra
		);
	}
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(extra); ++i) {
		if (!PEM_write_bio_X509(pem, sk_X509_value(extra, i))) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
	}
	sk_X509_pop_free(extra, X509_free);
	extra = NULL;
	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_parse(
		    params->tsa_intermediates_data,
		    params->tsa_intermediates_data_len,
		    &extra
		);
	}
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(extra); ++i) {
		if (!PEM_write_bio_X509(pem, sk_X509_value(extra, i))) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
	}
	char* bytes = NULL;
	long  len = pem ? BIO_get_mem_data(pem, &bytes) : 0;
	if (len > 0) {
		if (params->ca_data ||
		    (params->options & LIBSSIG_VERIFY_SYSTEM_TRUST)) {
			copy.intermediates_data = (unsigned char*)bytes;
			copy.intermediates_data_len = (size_t)len;
		}
		if (params->tsa_ca_data ||
		    (params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST)) {
			copy.tsa_intermediates_data = (unsigned char*)bytes;
			copy.tsa_intermediates_data_len = (size_t)len;
		}
	}
	if (status == LIBSSIG_OK) {
		qpdf_oh form = qpdf_oh_get_key(pdf, qpdf_get_root(pdf), "/AcroForm");
		qpdf_oh fields = qpdf_oh_get_key_if_dict(pdf, form, "/Fields");
		status = fields_verify(pdf, fields, 0, &copy, result);
		if (!result->count && status == LIBSSIG_OK) {
			status = LIBSSIG_ERROR_NOT_FOUND;
		}
	}
	qpdf_oh dss = qpdf_oh_get_key(pdf, qpdf_get_root(pdf), "/DSS");
	qpdf_oh ocsp = qpdf_oh_get_key_if_dict(pdf, dss, "/OCSPs");
	qpdf_oh crls = qpdf_oh_get_key_if_dict(pdf, dss, "/CRLs");
	bool    revocations = (!qpdf_oh_is_null(pdf, ocsp) &&
                        (!qpdf_oh_is_array(pdf, ocsp) ||
                         qpdf_oh_get_array_n_items(pdf, ocsp) > 0)) ||
	                   (!qpdf_oh_is_null(pdf, crls) &&
	                    (!qpdf_oh_is_array(pdf, crls) ||
	                     qpdf_oh_get_array_n_items(pdf, crls) > 0));
	libssig_verify_profiles_upgrade(revocations, result);
	bool automatic = !(params->options & LIBSSIG_VERIFY_CURRENT_TIME);
	bool historical = params->options & LIBSSIG_VERIFY_HISTORICAL;
	bool lt = false;
	for (size_t i = 0; i < result->count; ++i) {
		historical = historical ||
		             (automatic && result->signers[i].archive.present);
		lt = lt || (automatic && result->signers[i].level_detected &&
		            result->signers[i].level == LIBSSIG_LEVEL_B_LT);
	}
	if ((historical || lt) &&
	    (status == LIBSSIG_OK || status == LIBSSIG_ERROR_TRUST)) {
		if (historical) {
			copy.options |= LIBSSIG_VERIFY_HISTORICAL;
			for (size_t i = 0; i < result->count; ++i) {
				result->signers[i].history = LIBSSIG_HISTORY_INCOMPLETE;
			}
		}
		status = historical &&
		                 (copy.ocsp_count ||
		                  (copy.options & (LIBSSIG_VERIFY_REQUIRE_OCSP |
		                                   LIBSSIG_VERIFY_REQUIRE_TSA_OCSP)))
		             ? LIBSSIG_ERROR_ARGUMENT
		             : pdf_validation(pdf, &copy, result, historical);
	}
	if (qpdf_has_error(pdf)) {
		status = LIBSSIG_ERROR_FORMAT;
	}
	sk_X509_pop_free(extra, X509_free);
	BIO_free(pem);
	qpdf_cleanup(&pdf);
	result->detached = false;
	result->format = LIBSSIG_FORMAT_PADES;
	return status;
}
