/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/document.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* A deliberately bounded offline policy: a currently trusted archive anchors
 * the evidence. Earlier timestamps alone never authenticate old status data. */
typedef struct {
	STACK_OF(X509) * certs;
	STACK_OF(ASN1_TYPE) * revocations;
	X509_STORE* store;
	time_t      at, proof;
} history_context;

static bool interval_valid(
    const ASN1_TIME* current,
    const ASN1_TIME* next,
    const ASN1_TIME* produced,
    time_t           proof
) {
	time_t first, last, issued;
	return libssig_time_read(current, &first) &&
	       libssig_time_read(next, &last) &&
	       libssig_time_read(produced, &issued) && first <= issued &&
	       issued <= proof && first <= proof && proof <= last;
}

static bool extensions_valid(OCSP_BASICRESP* basic, OCSP_SINGLERESP* single) {
	for (int i = 0; i < OCSP_BASICRESP_get_ext_count(basic); ++i) {
		if (X509_EXTENSION_get_critical(OCSP_BASICRESP_get_ext(basic, i))) {
			return false;
		}
	}

	for (int i = 0; i < OCSP_SINGLERESP_get_ext_count(single); ++i) {
		if (X509_EXTENSION_get_critical(OCSP_SINGLERESP_get_ext(single, i))) {
			return false;
		}
	}

	return true;
}

static bool issuer_proof_valid(X509* issuer, history_context* ctx) {
	X509_STORE_CTX* verify = X509_STORE_CTX_new();
	bool            ok = verify &&
	          X509_STORE_CTX_init(verify, ctx->store, issuer, ctx->certs);
	if (ok) {
		X509_STORE_CTX_set_time(verify, 0, ctx->proof);
		ok = X509_verify_cert(verify) == 1;
	}
	X509_STORE_CTX_free(verify);
	return ok;
}

static bool responder_valid(
    OCSP_BASICRESP*  basic,
    X509*            issuer,
    history_context* ctx
) {
	X509* responder = NULL;
	if (!OCSP_resp_get0_signer(basic, &responder, ctx->certs)) {
		return false;
	}

	if (X509_cmp(responder, issuer)) {
		/* Delegation must be direct, with noCheck. Otherwise its own archived
		 * revocation path would have to be validated recursively. */
		int pos = X509_get_ext_by_NID(responder, NID_id_pkix_OCSP_noCheck, -1);
		X509_EXTENSION*    ext = pos >= 0 ? X509_get_ext(responder, pos) : NULL;
		ASN1_OCTET_STRING* value = ext ? X509_EXTENSION_get_data(ext) : NULL;
		if (!ext || X509_EXTENSION_get_critical(ext) ||
		    X509_get_ext_by_NID(responder, NID_id_pkix_OCSP_noCheck, pos) >=
		        0 ||
		    ASN1_STRING_length(value) != 2 ||
		    memcmp(ASN1_STRING_get0_data(value), "\x05\x00", 2) ||
		    X509_check_issued(issuer, responder) != X509_V_OK) {
			return false;
		}
	}

	time_t produced;
	if (!libssig_time_read(OCSP_resp_get0_produced_at(basic), &produced)) {
		return false;
	}

	X509_VERIFY_PARAM* param = X509_STORE_get0_param(ctx->store);
	X509_VERIFY_PARAM_set_time(param, produced);
	/* OCSP_basic_verify verifies signature, signer path and delegated EKU. */
	return OCSP_basic_verify(basic, ctx->certs, ctx->store, OCSP_NOEXPLICIT) ==
	       1;
}

static libssig_status revocation_status(
    time_t revoked,
    time_t at,
    long   reason
) {
	bool administrative = reason == CRL_REASON_AFFILIATION_CHANGED ||
	                      reason == CRL_REASON_SUPERSEDED ||
	                      reason == CRL_REASON_CESSATION_OF_OPERATION;
	return revoked > at && administrative ? LIBSSIG_OK : LIBSSIG_ERROR_REVOKED;
}

static libssig_status ocsp_check(
    OCSP_RESPONSE*   response,
    X509*            cert,
    X509*            issuer,
    history_context* ctx
) {
	OCSP_BASICRESP* basic = OCSP_response_get1_basic(response);
	if (basic && OCSP_resp_count(basic) > 1024) {
		OCSP_BASICRESP_free(basic);
		return LIBSSIG_ERROR_EVIDENCE;
	}

	libssig_status status = LIBSSIG_ERROR_EVIDENCE;
	for (int i = 0; basic && i < OCSP_resp_count(basic) && i < 1024; ++i) {
		OCSP_SINGLERESP*   single = OCSP_resp_get0(basic, i);
		const OCSP_CERTID* id = OCSP_SINGLERESP_get0_id(single);
		ASN1_OBJECT*       algorithm = NULL;
		OCSP_id_get0_info(NULL, &algorithm, NULL, NULL, (OCSP_CERTID*)id);
		const EVP_MD* md = EVP_get_digestbyobj(algorithm);
		OCSP_CERTID*  expected = md ? OCSP_cert_to_id(md, cert, issuer) : NULL;
		bool          matches = expected && OCSP_id_cmp(expected, id) == 0;
		OCSP_CERTID_free(expected);
		if (!matches || OCSP_resp_find(basic, (OCSP_CERTID*)id, -1) != i ||
		    OCSP_resp_find(basic, (OCSP_CERTID*)id, i) >= 0) {
			continue;
		}

		ASN1_GENERALIZEDTIME *revoked = NULL, *current = NULL, *next = NULL;
		int                   reason = -1;
		int                   state = OCSP_single_get0_status(
            single,
            &reason,
            &revoked,
            &current,
            &next
        );
		if (!extensions_valid(basic, single) ||
		    !interval_valid(
		        current,
		        next,
		        OCSP_resp_get0_produced_at(basic),
		        ctx->proof
		    ) ||
		    !issuer_proof_valid(issuer, ctx) ||
		    !responder_valid(basic, issuer, ctx)) {
			continue;
		}

		if (state == V_OCSP_CERTSTATUS_GOOD) {
			status = LIBSSIG_OK;
		} else if (state == V_OCSP_CERTSTATUS_REVOKED) {
			time_t revoked_at, produced;
			if (libssig_time_read(revoked, &revoked_at) &&
			    libssig_time_read(
			        OCSP_resp_get0_produced_at(basic),
			        &produced
			    ) &&
			    revoked_at <= produced) {
				/* Compromise has no reliable lower bound without invalidity
				 * evidence. Do not treat a later keyCompromise as safe. */
				status = revocation_status(revoked_at, ctx->at, reason);
			}
		}

		if (status == LIBSSIG_ERROR_REVOKED) {
			break;
		}
	}
	OCSP_BASICRESP_free(basic);
	return status;
}

static libssig_status crl_check(
    X509_CRL*        crl,
    X509*            cert,
    X509*            issuer,
    history_context* ctx
) {
	uint32_t usage = X509_get_key_usage(issuer);
	if (X509_NAME_cmp(
	        X509_CRL_get_issuer(crl),
	        X509_get_subject_name(issuer)
	    ) ||
	    (usage != UINT32_MAX && !(usage & KU_CRL_SIGN)) ||
	    X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0 ||
	    X509_CRL_get_ext_by_NID(crl, NID_issuing_distribution_point, -1) >= 0 ||
	    !interval_valid(
	        X509_CRL_get0_lastUpdate(crl),
	        X509_CRL_get0_nextUpdate(crl),
	        X509_CRL_get0_lastUpdate(crl),
	        ctx->proof
	    )) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	for (int i = 0; i < X509_CRL_get_ext_count(crl); ++i) {
		if (X509_EXTENSION_get_critical(X509_CRL_get_ext(crl, i))) {
			return LIBSSIG_ERROR_EVIDENCE;
		}
	}

	EVP_PKEY* key = X509_get_pubkey(issuer);
	bool      valid = key && X509_CRL_verify(crl, key) == 1 &&
	             issuer_proof_valid(issuer, ctx);
	EVP_PKEY_free(key);
	if (!valid) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	X509_REVOKED* entry = NULL;
	if (X509_CRL_get0_by_cert(crl, &entry, cert) != 1) {
		return LIBSSIG_OK;
	}

	for (int i = 0; i < X509_REVOKED_get_ext_count(entry); ++i) {
		if (X509_EXTENSION_get_critical(X509_REVOKED_get_ext(entry, i))) {
			return LIBSSIG_ERROR_EVIDENCE;
		}
	}

	int nids[] = {NID_invalidity_date, NID_crl_reason};
	for (size_t i = 0; i < sizeof(nids) / sizeof(nids[0]); ++i) {
		int pos = X509_REVOKED_get_ext_by_NID(entry, nids[i], -1);
		if (pos >= 0 && X509_REVOKED_get_ext_by_NID(entry, nids[i], pos) >= 0) {
			return LIBSSIG_ERROR_EVIDENCE;
		}
	}

	if (X509_REVOKED_get_ext_by_NID(entry, NID_certificate_issuer, -1) >= 0) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	time_t revoked;
	if (!libssig_time_read(X509_REVOKED_get0_revocationDate(entry), &revoked)) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	ASN1_GENERALIZEDTIME* invalid = X509_REVOKED_get_ext_d2i(
	    entry,
	    NID_invalidity_date,
	    NULL,
	    NULL
	);
	if (!invalid &&
	    X509_REVOKED_get_ext_by_NID(entry, NID_invalidity_date, -1) >= 0) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	time_t invalid_at;
	if (invalid &&
	    (!libssig_time_read(invalid, &invalid_at) || invalid_at < revoked)) {
		revoked = libssig_time_read(invalid, &invalid_at) ? invalid_at : 0;
	}
	ASN1_GENERALIZEDTIME_free(invalid);
	ASN1_ENUMERATED*
	     reason = X509_REVOKED_get_ext_d2i(entry, NID_crl_reason, NULL, NULL);
	long code = reason ? ASN1_ENUMERATED_get(reason) : -1;
	ASN1_ENUMERATED_free(reason);
	if ((code == -1 &&
	     X509_REVOKED_get_ext_by_NID(entry, NID_crl_reason, -1) >= 0) ||
	    code == CRL_REASON_REMOVE_FROM_CRL) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	return revocation_status(revoked, ctx->at, code);
}

/* CMS otherRevocationInfoFormat (RFC 5940) holds a complete OCSPResponse. */
static OCSP_RESPONSE* response_decode(const unsigned char* data, long len) {
	const unsigned char* cursor = data;
	long                 body = 0;
	int                  tag, cls;
	if ((ASN1_get_object(&cursor, &body, &tag, &cls, len) & 0x81) || tag != 1 ||
	    cls != V_ASN1_CONTEXT_SPECIFIC || body != len - (cursor - data)) {
		return NULL;
	}

	const unsigned char* end = cursor + body;
	ASN1_OBJECT*         oid = d2i_ASN1_OBJECT(NULL, &cursor, end - cursor);
	ASN1_OBJECT*         expected = OBJ_txt2obj("1.3.6.1.5.5.7.16.2", 1);
	bool                 ok = oid && expected && OBJ_cmp(oid, expected) == 0;
	ASN1_OBJECT_free(oid);
	ASN1_OBJECT_free(expected);
	OCSP_RESPONSE*
	    response = ok ? d2i_OCSP_RESPONSE(NULL, &cursor, end - cursor) : NULL;
	if (cursor != end) {
		OCSP_RESPONSE_free(response);
		return NULL;
	}

	return response;
}

static libssig_status certificate_status(
    X509*            cert,
    X509*            issuer,
    history_context* ctx
) {
	bool good = false;
	for (int i = 0; i < sk_ASN1_TYPE_num(ctx->revocations); ++i) {
		unsigned char* data = NULL;
		int len = i2d_ASN1_TYPE(sk_ASN1_TYPE_value(ctx->revocations, i), &data);
		const unsigned char* cursor = data;
		X509_CRL*            crl = len > 0 && data[0] == 0x30
		                               ? d2i_X509_CRL(NULL, &cursor, len)
		                               : NULL;
		OCSP_RESPONSE*       response = len > 0 && data[0] == 0xa1
		                                    ? response_decode(data, len)
		                                    : NULL;
		/* PDF DSS streams contain bare OCSPResponse DER. */
		if (!crl && len > 0 && data[0] == 0x30) {
			cursor = data;
			response = d2i_OCSP_RESPONSE(NULL, &cursor, len);
			if (cursor != data + len) {
				OCSP_RESPONSE_free(response);
				response = NULL;
			}
		}

		libssig_status status = crl ? crl_check(crl, cert, issuer, ctx)
		                        : response
		                            ? ocsp_check(response, cert, issuer, ctx)
		                            : LIBSSIG_ERROR_EVIDENCE;
		X509_CRL_free(crl);
		OCSP_RESPONSE_free(response);
		OPENSSL_free(data);
		if (status == LIBSSIG_ERROR_REVOKED) {
			return status;
		}
		good = good || status == LIBSSIG_OK;
	}

	return good ? LIBSSIG_OK : LIBSSIG_ERROR_EVIDENCE;
}

static libssig_status chain_check(
    X509*                 cert,
    bool                  tsa,
    history_context*      ctx,
    long*                 trust_error,
    libssig_trust_anchor* anchor
) {
	X509_STORE_CTX* verify = X509_STORE_CTX_new();
	bool            initialized = verify && X509_STORE_CTX_init(
                                     verify,
                                     ctx->store,
                                     cert,
                                     ctx->certs
                                 );
	if (initialized) {
		X509_STORE_CTX_set_time(verify, 0, ctx->at);
		X509_STORE_CTX_set_purpose(
		    verify,
		    tsa ? X509_PURPOSE_TIMESTAMP_SIGN : X509_PURPOSE_ANY
		);
	}

	int ok = initialized ? X509_verify_cert(verify) : -1;
	*trust_error = initialized ? X509_STORE_CTX_get_error(verify)
	                           : X509_V_ERR_OUT_OF_MEM;
	STACK_OF(X509)* chain = ok == 1 ? X509_STORE_CTX_get1_chain(verify) : NULL;
	if (ok == 1 && anchor) {
		libssig_trust_anchor_get(verify, anchor);
	}
	X509_STORE_CTX_free(verify);
	libssig_status status = ok == 1 && chain ? LIBSSIG_OK : LIBSSIG_ERROR_TRUST;
	for (int i = 0; status == LIBSSIG_OK && i + 1 < sk_X509_num(chain); ++i) {
		status = certificate_status(
		    sk_X509_value(chain, i),
		    sk_X509_value(chain, i + 1),
		    ctx
		);
	}
	sk_X509_pop_free(chain, X509_free);
	return status;
}

static libssig_status store_load(
    const libssig_verify_params* params,
    bool                         tsa,
    X509_STORE**                 store
) {
	libssig_verify_params trust = *params;
	if (tsa) {
		trust.fallback_ca_data = params->tsa_fallback_ca_data;
		trust.fallback_ca_data_len = params->tsa_fallback_ca_data_len;
		trust.ca_data = params->tsa_ca_data;
		trust.ca_data_len = params->tsa_ca_data_len;
		trust.options = (params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST)
		                    ? LIBSSIG_VERIFY_SYSTEM_TRUST
		                    : 0;
	}
	STACK_OF(X509)* roots = NULL;
	libssig_status status = libssig_verify_certs_parse(
	    trust.ca_data,
	    trust.ca_data_len,
	    &roots
	);
	if (status == LIBSSIG_OK) {
		status = libssig_verify_store_create(&trust, roots, store);
	}
	sk_X509_pop_free(roots, X509_free);
	return status;
}

static libssig_status tsa_chain(
    const libssig_verify_timestamp* stamp,
    history_context*                ctx
) {
	const unsigned char* cursor = stamp->cert_der;
	X509* cert = cursor ? d2i_X509(NULL, &cursor, (long)stamp->cert_der_len)
	                    : NULL;
	long  error = 0;
	libssig_status status = cert ? chain_check(cert, true, ctx, &error, NULL)
	                             : LIBSSIG_ERROR_EVIDENCE;
	X509_free(cert);
	return status;
}

static ASN1_TYPE* current_item_decode(const libssig_revocation_evidence* item) {
	const unsigned char* cursor = item->data;
	X509_CRL*            crl = d2i_X509_CRL(NULL, &cursor, (long)item->len);
	bool                 valid = crl && cursor == item->data + item->len;
	X509_CRL_free(crl);
	if (!valid) {
		cursor = item->data;
		OCSP_RESPONSE* response = d2i_OCSP_RESPONSE(
		    NULL,
		    &cursor,
		    (long)item->len
		);
		OCSP_BASICRESP* basic = response ? OCSP_response_get1_basic(response)
		                                 : NULL;
		valid = basic && cursor == item->data + item->len;
		OCSP_BASICRESP_free(basic);
		OCSP_RESPONSE_free(response);
	}
	cursor = item->data;
	return valid ? d2i_ASN1_TYPE(NULL, &cursor, (long)item->len) : NULL;
}

static libssig_status anchor_check(
    const libssig_verify_timestamp* archive,
    const libssig_verify_params*    params,
    history_context*                ctx
) {
	STACK_OF(ASN1_TYPE)* saved = ctx->revocations;
	STACK_OF(ASN1_TYPE)* current = sk_ASN1_TYPE_new_null();
	if (!current) {
		return LIBSSIG_ERROR_MEMORY;
	}

	libssig_status status = LIBSSIG_OK;
	for (int i = 0; i < sk_ASN1_TYPE_num(saved); ++i) {
		ASN1_TYPE* copy = ASN1_TYPE_new();
		ASN1_TYPE* item = sk_ASN1_TYPE_value(saved, i);
		if (!copy || !ASN1_TYPE_set1(copy, item->type, item->value.ptr) ||
		    !sk_ASN1_TYPE_push(current, copy)) {
			ASN1_TYPE_free(copy);
			status = LIBSSIG_ERROR_MEMORY;
			break;
		}
	}

	for (size_t i = 0;
	     status == LIBSSIG_OK && i < params->current_revocation_count;
	     ++i) {
		const libssig_revocation_evidence* item = &params
		                                               ->current_revocations[i];
		ASN1_TYPE* value = current_item_decode(item);
		if (!value || !sk_ASN1_TYPE_push(current, value)) {
			ASN1_TYPE_free(value);
			status = LIBSSIG_ERROR_EVIDENCE;
		}
	}
	STACK_OF(X509)* protected_certs = ctx->certs;
	STACK_OF(X509)* current_certs = NULL;
	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_parse(
		    params->tsa_intermediates_data,
		    params->tsa_intermediates_data_len,
		    &current_certs
		);
	}

	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_append(current_certs, protected_certs);
	}

	if (status == LIBSSIG_OK && sk_X509_num(current_certs) > 1024) {
		status = LIBSSIG_ERROR_EVIDENCE;
	}

	if (status == LIBSSIG_OK) {
		ctx->certs = current_certs;
	}

	if (status == LIBSSIG_OK) {
		ctx->at = time(NULL);
		ctx->proof = ctx->at;
		ctx->revocations = current;
		status = tsa_chain(archive, ctx);
		if (status == LIBSSIG_OK &&
		    libssig_verify_time_parse(archive->time, &ctx->at)) {
			status = tsa_chain(archive, ctx);
		}
	}
	ctx->certs = protected_certs;
	sk_X509_pop_free(current_certs, X509_free);
	ctx->revocations = saved;
	sk_ASN1_TYPE_pop_free(current, ASN1_TYPE_free);
	return status;
}

static libssig_status signer_check(
    X509*                        cert,
    libssig_verify_signer*       signer,
    const libssig_verify_params* params,
    history_context*             ctx,
    bool*                        chain_checked,
    bool                         historical
) {
	const libssig_verify_timestamp* stamp = &signer->timestamp;
	const libssig_verify_timestamp* archive = &signer->archive;
	if (!stamp->valid || (historical && !archive->valid)) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	if (!stamp->trusted || (historical && !archive->trusted)) {
		return LIBSSIG_ERROR_TRUST;
	}

	ctx->at = ctx->proof = time(NULL);
	if (historical) {
		if (!libssig_verify_time_parse(stamp->time, &ctx->at) ||
		    !libssig_verify_time_parse(archive->time, &ctx->proof) ||
		    ctx->at > ctx->proof) {
			return LIBSSIG_ERROR_EVIDENCE;
		}
		memcpy(
		    signer->validation_time,
		    stamp->time,
		    sizeof(signer->validation_time)
		);
	}
	libssig_status status = store_load(params, false, &ctx->store);
	if (status == LIBSSIG_OK) {
		*chain_checked = true;
		status = chain_check(
		    cert,
		    false,
		    ctx,
		    &signer->trust_error,
		    &signer->anchor
		);
	}
	X509_STORE_free(ctx->store);
	ctx->store = NULL;
	if (status == LIBSSIG_OK) {
		status = store_load(params, true, &ctx->store);
	}

	if (status == LIBSSIG_OK) {
		status = tsa_chain(stamp, ctx);
	}
	/* The last archive is the current-time trust bootstrap, not its own
	 * historical proof. Its status must therefore still be current. */
	if (status == LIBSSIG_OK && historical) {
		status = anchor_check(archive, params, ctx);
	}
	X509_STORE_free(ctx->store);
	ctx->store = NULL;
	signer->revocation_checked = status == LIBSSIG_OK ||
	                             status == LIBSSIG_ERROR_REVOKED;
	return status;
}

/* The full signature-timestamp attribute is archive-protected, including
 * certificates carried inside it. Unprotected external issuers are excluded. */
static libssig_status timestamp_certs_add(
    CMS_SignerInfo* s,
    STACK_OF(X509) * certs
) {
	int pos = CMS_unsigned_get_attr_by_NID(
	    s,
	    NID_id_smime_aa_timeStampToken,
	    -1
	);
	X509_ATTRIBUTE*  attr = pos >= 0 ? CMS_unsigned_get_attr(s, pos) : NULL;
	const ASN1_TYPE* value = attr ? X509_ATTRIBUTE_get0_type(attr, 0) : NULL;
	if (!value || value->type != V_ASN1_SEQUENCE) {
		return LIBSSIG_ERROR_EVIDENCE;
	}

	const unsigned char* cursor = ASN1_STRING_get0_data(value->value.sequence);
	CMS_ContentInfo*     token = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        ASN1_STRING_length(value->value.sequence)
    );
	STACK_OF(X509)* embedded = token ? CMS_get1_certs(token) : NULL;
	libssig_status status = token ? libssig_verify_certs_append(certs, embedded)
	                              : LIBSSIG_ERROR_EVIDENCE;
	sk_X509_pop_free(embedded, X509_free);
	CMS_ContentInfo_free(token);
	return status;
}

libssig_status libssig_validation_verify(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    STACK_OF(ASN1_TYPE) * revocations,
    const STACK_OF(X509) * protected_certs,
    bool                   historical,
    libssig_verify_result* result
) {
	history_context ctx = {
	    .certs = CMS_get1_certs(cms),
	    .revocations = revocations
	};
	libssig_status status = ctx.certs ? libssig_verify_certs_append(
	                                        ctx.certs,
	                                        protected_certs
	                                    )
	                                  : LIBSSIG_ERROR_MEMORY;
	STACK_OF(CMS_SignerInfo)* timestamps = CMS_get0_SignerInfos(cms);
	for (int i = 0;
	     status == LIBSSIG_OK && i < sk_CMS_SignerInfo_num(timestamps);
	     ++i) {
		if (!historical && result->signers[i].level != LIBSSIG_LEVEL_B_LT) {
			continue;
		}
		CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(timestamps, i);
		/* PAdES may provide trusted existence through a document timestamp,
		 * whose TSA chain is carried in the archive-protected DSS. */
		if (params->data_len >= 5 && !memcmp(params->data, "%PDF-", 5) &&
		    CMS_unsigned_get_attr_by_NID(
		        signer,
		        NID_id_smime_aa_timeStampToken,
		        -1
		    ) < 0) {
			continue;
		}
		status = timestamp_certs_add(signer, ctx.certs);
	}

	if (sk_ASN1_TYPE_num(revocations) > 1024 || sk_X509_num(ctx.certs) > 1024) {
		status = LIBSSIG_ERROR_EVIDENCE;
	}

	libssig_status loaded = status;
	result->trust_checked = true;
	result->trusted = true;
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	for (size_t i = 0; i < result->count; ++i) {
		if (!historical && result->signers[i].level != LIBSSIG_LEVEL_B_LT) {
			continue;
		}
		X509* cert = NULL;
		CMS_SignerInfo_get0_algs(
		    sk_CMS_SignerInfo_value(signers, (int)i),
		    NULL,
		    &cert,
		    NULL,
		    NULL
		);
		bool                   chain_checked = false;
		libssig_status         checked = loaded == LIBSSIG_OK ? signer_check(
                                                            cert,
                                                            &result->signers[i],
                                                            params,
                                                            &ctx,
                                                            &chain_checked,
                                                            historical
                                                        )
		                                                      : loaded;
		libssig_verify_signer* signer = &result->signers[i];
		signer->history = !historical             ? LIBSSIG_HISTORY_NOT_CHECKED
		                  : checked == LIBSSIG_OK ? LIBSSIG_HISTORY_VALID
		                  : checked == LIBSSIG_ERROR_REVOKED
		                      ? LIBSSIG_HISTORY_REVOKED
		                  : checked == LIBSSIG_ERROR_TRUST
		                      ? LIBSSIG_HISTORY_UNTRUSTED
		                      : LIBSSIG_HISTORY_INCOMPLETE;
		result->trust_checked = result->trust_checked && chain_checked;
		result->trusted = result->trusted && chain_checked &&
		                  signer->trust_error == 0;
		if (checked != LIBSSIG_OK) {
			if (status != LIBSSIG_ERROR_REVOKED) {
				status = checked;
			}
		}
	}
	sk_X509_pop_free(ctx.certs, X509_free);
	return status;
}

libssig_status libssig_history_verify(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    STACK_OF(ASN1_TYPE) * revocations,
    const STACK_OF(X509) * protected_certs,
    libssig_verify_result* result
) {
	return libssig_validation_verify(
	    cms,
	    params,
	    revocations,
	    protected_certs,
	    true,
	    result
	);
}

libssig_status libssig_document_evidence_verify(
    X509*                          cert,
    const libssig_validation_data* evidence,
    const libssig_verify_params*   params,
    libssig_verify_result*         result,
    bool                           historical
) {
	history_context ctx = {
	    .certs = evidence->certs,
	    .revocations = evidence->revocations
	};
	if (sk_X509_num(ctx.certs) > 1024 ||
	    sk_ASN1_TYPE_num(ctx.revocations) > 1024) {
		return LIBSSIG_ERROR_EVIDENCE;
	}
	bool                   checked = false;
	libssig_verify_signer* signer = &result->signers[0];
	libssig_status
	    status = signer_check(cert, signer, params, &ctx, &checked, historical);
	result->trust_checked = checked;
	result->trusted = status == LIBSSIG_OK;
	signer->history = !historical            ? LIBSSIG_HISTORY_NOT_CHECKED
	                  : status == LIBSSIG_OK ? LIBSSIG_HISTORY_VALID
	                  : status == LIBSSIG_ERROR_TRUST
	                      ? LIBSSIG_HISTORY_UNTRUSTED
	                  : status == LIBSSIG_ERROR_REVOKED
	                      ? LIBSSIG_HISTORY_REVOKED
	                      : LIBSSIG_HISTORY_INCOMPLETE;
	return status;
}

libssig_status libssig_document_evidence_stamp_check(
    const libssig_verify_timestamp* stamp,
    const libssig_verify_timestamp* archive,
    const libssig_validation_data*  evidence,
    const libssig_verify_params*    params
) {
	history_context ctx = {
	    .certs = evidence->certs,
	    .revocations = evidence->revocations
	};
	if (!stamp->valid || !stamp->trusted ||
	    !libssig_verify_time_parse(stamp->time, &ctx.at) ||
	    !libssig_verify_time_parse(archive->time, &ctx.proof) ||
	    ctx.at > ctx.proof) {
		return LIBSSIG_ERROR_EVIDENCE;
	}
	libssig_status status = store_load(params, true, &ctx.store);
	if (status == LIBSSIG_OK) {
		status = tsa_chain(stamp, &ctx);
	}
	X509_STORE_free(ctx.store);
	return status;
}
