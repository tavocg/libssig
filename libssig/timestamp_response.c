/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/timestamp_internal.h>
#include <openssl/err.h>
#include <time.h>

static libssig_status trust_load(
    const libssig_timestamp_params* params,
    X509_STORE**                    out_store,
    STACK_OF(X509) * *out_certs
) {
	STACK_OF(X509)* roots = NULL;
	libssig_status status = libssig_verify_certs_parse(
	    params->ca_data,
	    params->ca_data_len,
	    &roots
	);
	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_parse(
		    params->intermediates_data,
		    params->intermediates_data_len,
		    out_certs
		);
	}

	if (status == LIBSSIG_OK) {
		libssig_verify_params trust = {
		    .options = (params->options & LIBSSIG_TIMESTAMP_SYSTEM_TRUST)
		                   ? LIBSSIG_VERIFY_SYSTEM_TRUST
		                   : 0,
		};
		status = libssig_verify_store_create(&trust, roots, out_store);
	}
	sk_X509_pop_free(roots, X509_free);
	return status;
}

static bool response_time_valid(TS_RESP* response) {
	TS_TST_INFO*                info = TS_RESP_get_tst_info(response);
	const ASN1_GENERALIZEDTIME* generated = info ? TS_TST_INFO_get_time(info)
	                                             : NULL;
	time_t                      now = time(NULL);
	if (now == (time_t)-1) {
		return false;
	}

	ASN1_TIME* latest = ASN1_TIME_adj(NULL, now, 0, 300);
	int compared = generated && latest ? ASN1_TIME_compare(generated, latest)
	                                   : -2;
	ASN1_TIME_free(latest);
	return compared != -2 && compared <= 0;
}

static void trust_set(
    TS_VERIFY_CTX* ctx,
    X509_STORE*    store,
    STACK_OF(X509) * certs
) {
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
	TS_VERIFY_CTX_set0_store(ctx, store);
	TS_VERIFY_CTX_set0_certs(ctx, certs);
#else
	TS_VERIFY_CTX_set_store(ctx, store);
	TS_VERIFY_CTX_set_certs(ctx, certs);
#endif
}

static libssig_status response_error(void) {
	libssig_status status = LIBSSIG_ERROR_VERIFY;
	unsigned long  error;
	while ((error = ERR_get_error()) != 0) {
		if (ERR_GET_LIB(error) == ERR_LIB_TS &&
		    ERR_GET_REASON(error) == TS_R_CERTIFICATE_VERIFY_ERROR) {
			status = LIBSSIG_ERROR_TRUST;
		}
	}
	return status;
}

libssig_status libssig_timestamp_response(
    const libssig_timestamp_params* params,
    TS_REQ*                         request,
    TS_RESP*                        response
) {
	long granted = ASN1_INTEGER_get(
	    TS_STATUS_INFO_get0_status(TS_RESP_get_status_info(response))
	);
	if (granted != TS_STATUS_GRANTED &&
	    granted != TS_STATUS_GRANTED_WITH_MODS) {
		return LIBSSIG_ERROR_TIMESTAMP;
	}

	if (!response_time_valid(response)) {
		return LIBSSIG_ERROR_VERIFY;
	}

	X509_STORE* store = NULL;
	STACK_OF(X509)* certs = NULL;
	libssig_status status = trust_load(params, &store, &certs);
	if (status != LIBSSIG_OK) {
		X509_STORE_free(store);
		sk_X509_pop_free(certs, X509_free);
		return status;
	}

	TS_VERIFY_CTX* ctx = TS_REQ_to_TS_VERIFY_CTX(request, NULL);
	if (!ctx) {
		X509_STORE_free(store);
		sk_X509_pop_free(certs, X509_free);
		return LIBSSIG_ERROR_MEMORY;
	}

	trust_set(ctx, store, certs);
	TS_VERIFY_CTX_add_flags(ctx, TS_VFY_SIGNATURE);
	ERR_clear_error();
	int ok = TS_RESP_verify_response(ctx, response);
	status = ok == 1 ? LIBSSIG_OK : response_error();
	TS_VERIFY_CTX_free(ctx);
	return status;
}
