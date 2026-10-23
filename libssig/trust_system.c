/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/trust_system.h>
#include <limits.h>
#include <openssl/err.h>

#ifdef LIBSSIG_NATIVE_TRUST
typedef struct {
	STACK_OF(X509) * certificates;
	X509_STORE_CTX_verify_cb previous;
} native_store;
static CRYPTO_ONCE native_once = CRYPTO_ONCE_STATIC_INIT;
static int         native_index = -1;

static void native_free(
    void*           parent,
    void*           ptr,
    CRYPTO_EX_DATA* data,
    int             index,
    long            arg,
    void*           extra
) {
	(void)parent;
	(void)data;
	(void)index;
	(void)arg;
	(void)extra;
	native_store* state = ptr;
	if (state) {
		sk_X509_pop_free(state->certificates, X509_free);
		OPENSSL_free(state);
	}
}
static void native_init(void) {
	native_index = X509_STORE_get_ex_new_index(
	    0,
	    NULL,
	    NULL,
	    NULL,
	    native_free
	);
}
static bool contains(const STACK_OF(X509) * certs, X509* cert) {
	for (int i = 0; i < sk_X509_num(certs); ++i) {
		if (X509_cmp(sk_X509_value(certs, i), cert) == 0) {
			return true;
		}
	}
	return false;
}
static bool cached(X509_STORE* store, X509* cert) {
	STACK_OF(X509_OBJECT)* objects = X509_STORE_get1_objects(store);
	bool found = false;
	for (int i = 0; i < sk_X509_OBJECT_num(objects); ++i) {
		X509* existing = X509_OBJECT_get0_X509(
		    sk_X509_OBJECT_value(objects, i)
		);
		if (existing && X509_cmp(existing, cert) == 0) {
			found = true;
			break;
		}
	}
	sk_X509_OBJECT_pop_free(objects, X509_OBJECT_free);
	return found;
}
static int native_verify(int ok, X509_STORE_CTX* ctx) {
	native_store* state = X509_STORE_get_ex_data(
	    X509_STORE_CTX_get0_store(ctx),
	    native_index
	);
	/* A native decision never overrides an OpenSSL validation failure. */
	if (ok && X509_STORE_CTX_get_error_depth(ctx) == 0) {
		STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(ctx);
		int count = sk_X509_num(chain);
		if (count > 0 &&
		    contains(state->certificates, sk_X509_value(chain, count - 1)) &&
		    !libssig_trust_native_verify(ctx)) {
			X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
			return 0;
		}
	}
	return state->previous ? state->previous(ok, ctx) : ok;
}
libssig_status libssig_trust_native_append(
    STACK_OF(X509) * certs,
    const unsigned char* der,
    size_t               len
) {
	if (!der || !len || len > LONG_MAX) {
		return LIBSSIG_ERROR_FORMAT;
	}
	const unsigned char* cursor = der;
	X509*                cert = d2i_X509(NULL, &cursor, (long)len);
	if (!cert || cursor != der + len) {
		X509_free(cert);
		return LIBSSIG_ERROR_FORMAT;
	}
	if (!sk_X509_push(certs, cert)) {
		X509_free(cert);
		return LIBSSIG_ERROR_MEMORY;
	}
	return LIBSSIG_OK;
}
bool libssig_trust_native_matches(
    X509*                cert,
    const unsigned char* der,
    size_t               len
) {
	if (!der || !len || len > LONG_MAX) {
		return false;
	}
	const unsigned char* cursor = der;
	X509*                other = d2i_X509(NULL, &cursor, (long)len);
	bool match = other && cursor == der + len && X509_cmp(cert, other) == 0;
	X509_free(other);
	return match;
}
time_t libssig_trust_native_time(X509_STORE_CTX* ctx) {
	X509_VERIFY_PARAM* params = X509_STORE_CTX_get0_param(ctx);
	return X509_VERIFY_PARAM_get_flags(params) & X509_V_FLAG_USE_CHECK_TIME
	           ? X509_VERIFY_PARAM_get_time(params)
	           : time(NULL);
}
static libssig_status native_load(X509_STORE* store) {
	if (!CRYPTO_THREAD_run_once(&native_once, native_init) ||
	    native_index < 0) {
		return LIBSSIG_ERROR_MEMORY;
	}
	if (X509_STORE_get_ex_data(store, native_index)) {
		return LIBSSIG_OK;
	}
	native_store* state = OPENSSL_zalloc(sizeof(*state));
	if (!state) {
		return LIBSSIG_ERROR_MEMORY;
	}
	state->certificates = sk_X509_new_null();
	if (!state->certificates ||
	    !X509_STORE_set_ex_data(store, native_index, state)) {
		native_free(NULL, state, NULL, 0, 0, NULL);
		return LIBSSIG_ERROR_MEMORY;
	}
	state->previous = X509_STORE_get_verify_cb(store);
	X509_STORE_set_verify_cb(store, native_verify);
	STACK_OF(X509)* certificates = sk_X509_new_null();
	libssig_status status = certificates ? libssig_trust_native_certificates(
	                                           certificates
	                                       )
	                                     : LIBSSIG_ERROR_MEMORY;
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(certificates);
	     ++i) {
		X509* cert = sk_X509_value(certificates, i);
		/* Preserve explicit/default anchors already present in the store. */
		if (cached(store, cert)) {
			continue;
		}
		if (!X509_up_ref(cert)) {
			status = LIBSSIG_ERROR_MEMORY;
			break;
		}
		if (!sk_X509_push(state->certificates, cert)) {
			X509_free(cert);
			status = LIBSSIG_ERROR_MEMORY;
			break;
		}
		if (!X509_STORE_add_cert(store, cert)) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
	}
	sk_X509_pop_free(certificates, X509_free);
	return status;
}
#endif

libssig_status libssig_trust_store_load_system(X509_STORE* store) {
	if (!store) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	int defaults = X509_STORE_set_default_paths(store);
#ifdef LIBSSIG_NATIVE_TRUST
	/* Native installations need no OpenSSL CA bundle to use system trust. */
	if (!defaults) {
		ERR_clear_error();
	}
	return native_load(store);
#else
	return defaults == 1 ? LIBSSIG_OK : LIBSSIG_ERROR_TRUST;
#endif
}
