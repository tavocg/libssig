/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/trust.h>
#include <openssl/x509v3.h>

/* A final lookup supplies missing roots without overriding validation errors.
 */
typedef struct {
	STACK_OF(X509) * primary;
	STACK_OF(X509) * fallback;
	STACK_OF(X509) * used;
} trust_roots;

static CRYPTO_ONCE         method_once = CRYPTO_ONCE_STATIC_INIT;
static X509_LOOKUP_METHOD* method;
static int                 roots_index = -1;

static void roots_free(
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
	trust_roots* roots = ptr;
	if (roots) {
		sk_X509_pop_free(roots->primary, X509_free);
		sk_X509_pop_free(roots->fallback, X509_free);
		sk_X509_free(roots->used);
		OPENSSL_free(roots);
	}
}

static bool contains(const STACK_OF(X509) * certs, X509* cert) {
	for (int i = 0; i < sk_X509_num(certs); ++i) {
		if (X509_cmp(sk_X509_value(certs, i), cert) == 0) {
			return true;
		}
	}
	return false;
}

static int fallback_subject(
    X509_LOOKUP*     lookup,
    X509_LOOKUP_TYPE type,
    const X509_NAME* name,
    X509_OBJECT*     result
) {
	if (type != X509_LU_X509) {
		return 0;
	}

	trust_roots* roots = X509_LOOKUP_get_method_data(lookup);
	X509*        first = NULL;
	for (int i = 0; i < sk_X509_num(roots->fallback); ++i) {
		X509* cert = sk_X509_value(roots->fallback, i);
		if (X509_NAME_cmp(name, X509_get_subject_name(cert)) != 0) {
			continue;
		}

		/* Cache every candidate: equal subjects can have different keys. */
		if (!X509_STORE_add_cert(X509_LOOKUP_get_store(lookup), cert) ||
		    (!contains(roots->used, cert) &&
		     !sk_X509_push(roots->used, cert))) {
			return 0;
		}
		if (!first) {
			first = cert;
		}
	}
	return first ? X509_OBJECT_set1_X509(result, first) : 0;
}

/* A cached primary certificate can have the right DN but a different AKI.
 * Consult fallback candidates only when primary issuer selection found none. */
static int fallback_issuer(X509** issuer, X509_STORE_CTX* ctx,
#ifdef LIBSSIG_OPENSSL_CONST_ISSUER
                           const X509* cert
#else
                           X509* cert
#endif
) {
	int found = X509_STORE_CTX_get1_issuer(issuer, ctx, cert);
	if (found != 0) {
		return found;
	}

	X509_STORE*  store = X509_STORE_CTX_get0_store(ctx);
	trust_roots* roots = X509_STORE_get_ex_data(store, roots_index);
	X509_LOOKUP* lookup = roots ? X509_STORE_add_lookup(store, method) : NULL;
	X509_OBJECT* object = lookup ? X509_OBJECT_new() : NULL;
	int          loaded = object ? fallback_subject(
                              lookup,
                              X509_LU_X509,
                              X509_get_issuer_name(cert),
                              object
                          )
	                             : 0;
	X509_OBJECT_free(object);
	return loaded ? X509_STORE_CTX_get1_issuer(issuer, ctx, cert) : 0;
}

static void method_create(void) {
	roots_index = X509_STORE_get_ex_new_index(0, NULL, NULL, NULL, roots_free);
	X509_LOOKUP_METHOD* created = X509_LOOKUP_meth_new(
	    "libssig fallback roots"
	);
	if (roots_index >= 0 && created &&
	    X509_LOOKUP_meth_set_get_by_subject(created, fallback_subject)) {
		method = created;
	} else {
		X509_LOOKUP_meth_free(created);
	}
}

static bool roots_valid(const STACK_OF(X509) * roots) {
	if (sk_X509_num(roots) > 1024) {
		return false;
	}

	for (int i = 0; i < sk_X509_num(roots); ++i) {
		X509* cert = sk_X509_value(roots, i);
		if (X509_check_ca(cert) <= 0 ||
		    X509_NAME_cmp(
		        X509_get_subject_name(cert),
		        X509_get_issuer_name(cert)
		    ) ||
		    X509_verify(cert, X509_get0_pubkey(cert)) != 1) {
			return false;
		}
	}
	return true;
}

static libssig_status roots_create(
    const STACK_OF(X509) * primary,
    const unsigned char* data,
    size_t               len,
    trust_roots**        out_roots
) {
	trust_roots* roots = OPENSSL_zalloc(sizeof(*roots));
	if (!roots) {
		return LIBSSIG_ERROR_MEMORY;
	}

	libssig_status status = libssig_verify_certs_parse(
	    data,
	    len,
	    &roots->fallback
	);
	roots->primary = sk_X509_new_null();
	roots->used = sk_X509_new_null();
	if (status == LIBSSIG_OK && (!roots->primary || !roots->used)) {
		status = LIBSSIG_ERROR_MEMORY;
	}

	if (status == LIBSSIG_OK && !roots_valid(roots->fallback)) {
		status = LIBSSIG_ERROR_FORMAT;
	}

	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_append(roots->primary, primary);
	}

	if (status != LIBSSIG_OK) {
		roots_free(NULL, roots, NULL, 0, 0, NULL);
	} else {
		*out_roots = roots;
	}
	return status;
}

libssig_status libssig_trust_fallback_add(
    X509_STORE* store,
    const STACK_OF(X509) * primary,
    const unsigned char* data,
    size_t               len
) {
	if (len > 16u * 1024u * 1024u ||
	    !libssig_ocsp_buffer_valid(data, len, false)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if (!CRYPTO_THREAD_run_once(&method_once, method_create) || !method) {
		return LIBSSIG_ERROR_MEMORY;
	}

	trust_roots*   roots = NULL;
	libssig_status status = roots_create(primary, data, len, &roots);
	if (status != LIBSSIG_OK) {
		return status;
	}

	X509_LOOKUP* lookup = data ? X509_STORE_add_lookup(store, method) : NULL;
	if ((data && (!lookup || !X509_LOOKUP_set_method_data(lookup, roots))) ||
	    !X509_STORE_set_ex_data(store, roots_index, roots)) {
		roots_free(NULL, roots, NULL, 0, 0, NULL);
		return LIBSSIG_ERROR_MEMORY;
	}

	if (data) {
		X509_STORE_set_get_issuer(store, fallback_issuer);
	}
	return LIBSSIG_OK;
}

void libssig_trust_anchor_get(
    X509_STORE_CTX*       ctx,
    libssig_trust_anchor* anchor
) {
	*anchor = (libssig_trust_anchor){0};
	if (!ctx || X509_STORE_CTX_get_error(ctx) != X509_V_OK || roots_index < 0) {
		return;
	}

	STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(ctx);
	int          count = sk_X509_num(chain);
	X509*        root = count > 0 ? sk_X509_value(chain, count - 1) : NULL;
	trust_roots* roots = X509_STORE_get_ex_data(
	    X509_STORE_CTX_get0_store(ctx),
	    roots_index
	);
	unsigned int len = 0;
	if (!root || !roots ||
	    !X509_digest(root, EVP_sha256(), anchor->sha256, &len) || len != 32) {
		return;
	}
	anchor->source = contains(roots->primary, root) ? LIBSSIG_TRUST_ADDITIONAL
	                 : contains(roots->used, root)  ? LIBSSIG_TRUST_FALLBACK
	                                                : LIBSSIG_TRUST_SYSTEM;
}
