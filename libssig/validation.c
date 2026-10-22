/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/document.h>
#include <libssig/services.h>
#include <libssig/trust.h>
#include <libssig/validation.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
	ASN1_OBJECT* format;
	ASN1_TYPE*   value;
} other_revocation;
ASN1_SEQUENCE(other_revocation) =
    {
        ASN1_SIMPLE(other_revocation, format, ASN1_OBJECT),
        ASN1_SIMPLE(other_revocation, value, ASN1_ANY),
} ASN1_SEQUENCE_END(other_revocation) IMPLEMENT_ASN1_FUNCTIONS(other_revocation)

        static bool cert_add(STACK_OF(X509) * certs, X509* cert) {
	for (int i = 0; i < sk_X509_num(certs); ++i) {
		if (X509_cmp(sk_X509_value(certs, i), cert) == 0) {
			return true;
		}
	}
	if (!X509_up_ref(cert)) {
		return false;
	}
	if (sk_X509_push(certs, cert)) {
		return true;
	}
	X509_free(cert);
	return false;
}
static libssig_status bundle_add(
    libssig_validation_data* data,
    const unsigned char*     bytes,
    size_t                   len
) {
	STACK_OF(X509)* certs = NULL;
	libssig_status status = libssig_verify_certs_parse(bytes, len, &certs);
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(certs); ++i) {
		if (!cert_add(data->certs, sk_X509_value(certs, i))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	sk_X509_pop_free(certs, X509_free);
	return status;
}
static libssig_verify_params trust_params(
    const libssig_sign_services* services,
    bool                         tsa
) {
	libssig_verify_params
	    params = services->trust
	                 ? *services->trust
	                 : (libssig_verify_params){
	                       .options = LIBSSIG_VERIFY_SYSTEM_TRUST |
	                                  LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
	                   };
	if (tsa) {
		params.fallback_ca_data = params.tsa_fallback_ca_data;
		params.fallback_ca_data_len = params.tsa_fallback_ca_data_len;
		params.ca_data = params.tsa_ca_data;
		params.ca_data_len = params.tsa_ca_data_len;
		params.intermediates_data = params.tsa_intermediates_data;
		params.intermediates_data_len = params.tsa_intermediates_data_len;
		params.options = params.options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
		                     ? LIBSSIG_VERIFY_SYSTEM_TRUST
		                     : 0;
	} else {
		params.options &= LIBSSIG_VERIFY_SYSTEM_TRUST;
	}
	return params;
}
static char* issuer_url(X509* cert) {
	AUTHORITY_INFO_ACCESS*
	      access = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
	char* url = NULL;
	for (int i = 0; !url && i < sk_ACCESS_DESCRIPTION_num(access); ++i) {
		ACCESS_DESCRIPTION* item = sk_ACCESS_DESCRIPTION_value(access, i);
		if (OBJ_obj2nid(item->method) != NID_ad_ca_issuers ||
		    item->location->type != GEN_URI) {
			continue;
		}
		ASN1_IA5STRING* value = item->location->d.uniformResourceIdentifier;
		int             len = ASN1_STRING_length(value);
		const unsigned char* text = ASN1_STRING_get0_data(value);
		if (len > 0 && !memchr(text, 0, (size_t)len)) {
			url = malloc((size_t)len + 1);
			if (url) {
				memcpy(url, text, (size_t)len);
				url[len] = 0;
			}
		}
	}
	AUTHORITY_INFO_ACCESS_free(access);
	return url;
}
static X509* issuer_find(X509* cert, STACK_OF(X509) * certs) {
	for (int i = 0; i < sk_X509_num(certs); ++i) {
		X509* issuer = sk_X509_value(certs, i);
		if (X509_check_issued(issuer, cert) != X509_V_OK) {
			continue;
		}
		EVP_PKEY* key = X509_get_pubkey(issuer);
		bool      ok = key && X509_verify(cert, key) == 1;
		EVP_PKEY_free(key);
		if (ok) {
			return issuer;
		}
	}
	return NULL;
}
static libssig_status chain_build(
    X509*                        cert,
    bool                         tsa,
    const libssig_sign_services* services,
    libssig_validation_data*     data,
    STACK_OF(X509) * *out_chain
) {
	libssig_verify_params params = trust_params(services, tsa);
	STACK_OF(X509)* roots = NULL;
	X509_STORE*    store = NULL;
	libssig_status status = libssig_verify_certs_parse(
	    params.ca_data,
	    params.ca_data_len,
	    &roots
	);
	if (status == LIBSSIG_OK) {
		status = libssig_verify_store_create(&params, roots, &store);
	}
	X509* pending = cert;
	for (int attempt = 0; status == LIBSSIG_OK && attempt < 16; ++attempt) {
		X509_STORE_CTX* ctx = X509_STORE_CTX_new();
		bool ok = ctx && X509_STORE_CTX_init(ctx, store, cert, data->certs);
		if (ok) {
			X509_STORE_CTX_set_purpose(
			    ctx,
			    tsa ? X509_PURPOSE_TIMESTAMP_SIGN : X509_PURPOSE_ANY
			);
		}
		if (ok && X509_verify_cert(ctx) == 1) {
			*out_chain = X509_STORE_CTX_get1_chain(ctx);
			X509_STORE_CTX_free(ctx);
			status = *out_chain ? LIBSSIG_OK : LIBSSIG_ERROR_MEMORY;
			break;
		}
		int error = ctx ? X509_STORE_CTX_get_error(ctx) : X509_V_ERR_OUT_OF_MEM;
		X509_STORE_CTX_free(ctx);
		if (error != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY &&
		    error != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) {
			status = LIBSSIG_ERROR_TRUST;
			break;
		}
		X509* issuer = issuer_find(pending, data->certs);
		if (issuer && issuer != pending) {
			pending = issuer;
			continue;
		}
		char*             url = issuer_url(pending);
		libssig_signature bytes = {0};
		status = url ? libssig_ades_fetch(
		                   services,
		                   LIBSSIG_FETCH_CERTIFICATE,
		                   url,
		                   NULL,
		                   0,
		                   &bytes
		               )
		             : LIBSSIG_ERROR_TRUST;
		int before = sk_X509_num(data->certs);
		if (status == LIBSSIG_OK) {
			status = bundle_add(data, bytes.data, bytes.len);
		}
		free(url);
		libssig_signature_free(&bytes);
		if (status == LIBSSIG_OK && before == sk_X509_num(data->certs)) {
			status = LIBSSIG_ERROR_TRUST;
		}
	}
	if (status == LIBSSIG_OK && !*out_chain) {
		status = LIBSSIG_ERROR_TRUST;
	}
	X509_STORE_free(store);
	sk_X509_pop_free(roots, X509_free);
	return status;
}
static bool revocation_add(
    libssig_validation_data* data,
    const unsigned char*     bytes,
    size_t                   len
) {
	const unsigned char* cursor = bytes;
	ASN1_TYPE*           response = d2i_ASN1_TYPE(NULL, &cursor, (long)len);
	other_revocation*    other = other_revocation_new();
	bool                 ok = response && cursor == bytes + len && other;
	if (ok) {
		ASN1_OBJECT_free(other->format);
		other->format = OBJ_txt2obj("1.3.6.1.5.5.7.16.2", 1);
		ASN1_TYPE_free(other->value);
		other->value = response;
		response = NULL;
	}
	unsigned char* encoded = NULL;
	int            encoded_len = ok ? i2d_other_revocation(other, &encoded) : 0;
	ASN1_TYPE*     item = ASN1_TYPE_new();
	ASN1_STRING*   value = ASN1_STRING_type_new(V_ASN1_OTHER);
	if (encoded_len > 0) {
		encoded[0] = 0xa1;
	}
	ok = encoded_len > 0 && item && value &&
	     ASN1_STRING_set(value, encoded, encoded_len);
	if (ok) {
		ASN1_TYPE_set(item, V_ASN1_OTHER, value);
		value = NULL;
		ok = sk_ASN1_TYPE_push(data->revocations, item) != 0;
		if (ok) {
			item = NULL;
		}
	}
	ASN1_TYPE_free(item);
	ASN1_STRING_free(value);
	ASN1_TYPE_free(response);
	other_revocation_free(other);
	OPENSSL_free(encoded);
	return ok;
}
static libssig_status ocsp_certificates(
    const libssig_signature* response,
    X509*                    issuer,
    libssig_validation_data* data
) {
	libssig_status       status = LIBSSIG_OK;
	const unsigned char* cursor = response->data;
	OCSP_RESPONSE*       reply = d2i_OCSP_RESPONSE(
        NULL,
        &cursor,
        (long)response->len
    );
	OCSP_BASICRESP* basic = reply ? OCSP_response_get1_basic(reply) : NULL;
	X509*           responder = NULL;
	bool valid = basic && OCSP_resp_get0_signer(basic, &responder, data->certs);
	if (valid && X509_cmp(responder, issuer)) {
		int index = X509_get_ext_by_NID(
		    responder,
		    NID_id_pkix_OCSP_noCheck,
		    -1
		);
		X509_EXTENSION*    ext = index >= 0 ? X509_get_ext(responder, index)
		                                    : NULL;
		ASN1_OCTET_STRING* value = ext ? X509_EXTENSION_get_data(ext) : NULL;
		valid = ext && !X509_EXTENSION_get_critical(ext) &&
		        X509_get_ext_by_NID(
		            responder,
		            NID_id_pkix_OCSP_noCheck,
		            index
		        ) < 0 &&
		        ASN1_STRING_length(value) == 2 &&
		        !memcmp(ASN1_STRING_get0_data(value), "\x05\x00", 2);
		if (!valid) {
			status = LIBSSIG_ERROR_UNSUPPORTED;
		}
	}
	if (!valid && status == LIBSSIG_OK) {
		status = LIBSSIG_ERROR_VERIFY;
	}
	const STACK_OF(X509)* embedded = basic ? OCSP_resp_get0_certs(basic) : NULL;
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(embedded); ++i) {
		if (!cert_add(data->certs, sk_X509_value(embedded, i))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	OCSP_BASICRESP_free(basic);
	OCSP_RESPONSE_free(reply);
	return status;
}

static libssig_status certificate_ocsp(
    X509*                        cert,
    X509*                        issuer,
    bool                         tsa,
    const libssig_sign_services* services,
    libssig_validation_data*     data
) {
	unsigned char *cert_der = NULL, *issuer_der = NULL;
	int            cert_len = i2d_X509(cert, &cert_der),
	    issuer_len = i2d_X509(issuer, &issuer_der);
	libssig_ocsp_request_params query = {
	    .cert_data = cert_der,
	    .cert_data_len = (size_t)(cert_len > 0 ? cert_len : 0),
	    .issuer_data = issuer_der,
	    .issuer_data_len = (size_t)(issuer_len > 0 ? issuer_len : 0)
	};
	libssig_ocsp_query request = {0};
	libssig_status     status = libssig_ocsp_request(&query, &request);
	libssig_signature  response = {0};
	if (status == LIBSSIG_OK) {
		status = LIBSSIG_ERROR_OCSP;
		for (size_t i = 0; i < request.urls.count && i < 16; ++i) {
			status = libssig_ades_fetch(
			    services,
			    LIBSSIG_FETCH_OCSP,
			    request.urls.items[i],
			    request.data,
			    request.len,
			    &response
			);
			if (status == LIBSSIG_OK) {
				break;
			}
		}
	}
	libssig_verify_params trust = trust_params(services, tsa);
	BIO*                  intermediates = BIO_new(BIO_s_mem());
	bool                  encoded = intermediates != NULL;
	for (int i = 0; encoded && i < sk_X509_num(data->certs); ++i) {
		encoded = PEM_write_bio_X509(
		              intermediates,
		              sk_X509_value(data->certs, i)
		          ) == 1;
	}
	char* pem = NULL;
	long  pem_len = encoded ? BIO_get_mem_data(intermediates, &pem) : 0;
	if (status == LIBSSIG_OK && (!encoded || pem_len <= 0)) {
		status = LIBSSIG_ERROR_CRYPTO;
	}
	if (status == LIBSSIG_OK) {
		libssig_ocsp_verify_params params = {
		    .cert_data = cert_der,
		    .cert_data_len = (size_t)cert_len,
		    .issuer_data = issuer_der,
		    .issuer_data_len = (size_t)issuer_len,
		    .request = request.data,
		    .request_len = request.len,
		    .response = response.data,
		    .response_len = response.len,
		    .fallback_ca_data = trust.fallback_ca_data,
		    .fallback_ca_data_len = trust.fallback_ca_data_len,
		    .ca_data = trust.ca_data,
		    .ca_data_len = trust.ca_data_len,
		    .intermediates_data = (const unsigned char*)pem,
		    .intermediates_data_len = (size_t)pem_len,
		    .options = (trust.options & LIBSSIG_VERIFY_SYSTEM_TRUST
		                    ? LIBSSIG_OCSP_SYSTEM_TRUST
		                    : 0) |
		               services->ocsp_options,
		    .max_age = services->max_age,
		    .clock_skew = services->clock_skew,
		};
		libssig_ocsp_result result = {0};
		status = libssig_ocsp_verify(&params, &result);
		if (status == LIBSSIG_OK && result.status != LIBSSIG_OCSP_GOOD) {
			status = result.status == LIBSSIG_OCSP_REVOKED
			             ? LIBSSIG_ERROR_REVOKED
			             : LIBSSIG_ERROR_OCSP;
		}
		if (status == LIBSSIG_OK) {
			status = ocsp_certificates(&response, issuer, data);
		}
		if (status == LIBSSIG_OK &&
		    !revocation_add(data, response.data, response.len)) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
	}
	BIO_free(intermediates);
	libssig_signature_free(&response);
	libssig_ocsp_request_free(&request);
	OPENSSL_free(cert_der);
	OPENSSL_free(issuer_der);
	return status;
}
static bool crl_time_valid(
    X509_CRL*                    crl,
    const libssig_sign_services* services
) {
	unsigned long age = services->max_age;
	unsigned long skew = services->clock_skew ? services->clock_skew : 300;
	if (age > INT_MAX || skew > INT_MAX) {
		return false;
	}
	time_t     now = time(NULL);
	ASN1_TIME* earliest = ASN1_TIME_adj(
	    NULL,
	    now,
	    0,
	    -(int)age - (int)(skew > INT_MAX - age ? 0 : skew)
	);
	ASN1_TIME*       latest = ASN1_TIME_adj(NULL, now, 0, (int)skew);
	ASN1_TIME*       cutoff = ASN1_TIME_adj(NULL, now, 0, -(int)skew);
	const ASN1_TIME* current = X509_CRL_get0_lastUpdate(crl);
	const ASN1_TIME* next = X509_CRL_get0_nextUpdate(crl);
	bool             ok = earliest && latest && cutoff && current && next &&
	          (!age || ASN1_TIME_compare(current, earliest) >= 0) &&
	          ASN1_TIME_compare(current, latest) <= 0 &&
	          ASN1_TIME_compare(next, cutoff) >= 0 &&
	          ASN1_TIME_compare(next, current) >= 0;
	ASN1_TIME_free(earliest);
	ASN1_TIME_free(latest);
	ASN1_TIME_free(cutoff);
	return ok;
}
static libssig_status crl_check(
    X509*                        cert,
    X509*                        issuer,
    const libssig_sign_services* services,
    const libssig_signature*     bytes,
    libssig_validation_data*     data
) {
	const unsigned char* cursor = bytes->data;
	X509_CRL*            crl = d2i_X509_CRL(NULL, &cursor, (long)bytes->len);
	EVP_PKEY*            key = X509_get_pubkey(issuer);
	uint32_t             usage = X509_get_key_usage(issuer);
	bool ok = crl && cursor == bytes->data + bytes->len && key &&
	          (usage == UINT32_MAX || (usage & KU_CRL_SIGN)) &&
	          X509_NAME_cmp(
	              X509_CRL_get_issuer(crl),
	              X509_get_subject_name(issuer)
	          ) == 0 &&
	          X509_CRL_verify(crl, key) == 1 && crl_time_valid(crl, services) &&
	          X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) < 0 &&
	          X509_CRL_get_ext_by_NID(crl, NID_issuing_distribution_point, -1) <
	              0;
	for (int i = 0; ok && i < X509_CRL_get_ext_count(crl); ++i) {
		if (X509_EXTENSION_get_critical(X509_CRL_get_ext(crl, i))) {
			ok = false;
		}
	}
	libssig_status status = ok ? LIBSSIG_OK : LIBSSIG_ERROR_OCSP;
	X509_REVOKED*  revoked = NULL;
	if (ok && X509_CRL_get0_by_cert(crl, &revoked, cert) == 1) {
		status = LIBSSIG_ERROR_REVOKED;
	}
	if (status == LIBSSIG_OK) {
		cursor = bytes->data;
		ASN1_TYPE* value = d2i_ASN1_TYPE(NULL, &cursor, (long)bytes->len);
		if (!value || !sk_ASN1_TYPE_push(data->revocations, value)) {
			ASN1_TYPE_free(value);
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	EVP_PKEY_free(key);
	X509_CRL_free(crl);
	return status;
}
static libssig_status certificate_crl(
    X509*                        cert,
    X509*                        issuer,
    const libssig_sign_services* services,
    libssig_validation_data*     data
) {
	CRL_DIST_POINTS* points = X509_get_ext_d2i(
	    cert,
	    NID_crl_distribution_points,
	    NULL,
	    NULL
	);
	libssig_status status = LIBSSIG_ERROR_OCSP;
	for (int i = 0; i < sk_DIST_POINT_num(points) && i < 16; ++i) {
		DIST_POINT* point = sk_DIST_POINT_value(points, i);
		if (!point->distpoint || point->distpoint->type != 0 ||
		    point->reasons || point->CRLissuer) {
			continue;
		}
		GENERAL_NAMES* names = point->distpoint->name.fullname;
		for (int j = 0; j < sk_GENERAL_NAME_num(names) && j < 16; ++j) {
			GENERAL_NAME* name = sk_GENERAL_NAME_value(names, j);
			if (name->type != GEN_URI) {
				continue;
			}
			ASN1_IA5STRING*      uri = name->d.uniformResourceIdentifier;
			int                  len = ASN1_STRING_length(uri);
			const unsigned char* value = ASN1_STRING_get0_data(uri);
			if (len <= 0 || memchr(value, 0, (size_t)len)) {
				continue;
			}
			char* url = malloc((size_t)len + 1);
			if (!url) {
				status = LIBSSIG_ERROR_MEMORY;
				break;
			}
			memcpy(url, value, (size_t)len);
			url[len] = 0;
			libssig_signature response = {0};
			status = libssig_ades_fetch(
			    services,
			    LIBSSIG_FETCH_CRL,
			    url,
			    NULL,
			    0,
			    &response
			);
			if (status == LIBSSIG_OK) {
				status = crl_check(cert, issuer, services, &response, data);
			}
			libssig_signature_free(&response);
			free(url);
			if (status == LIBSSIG_OK || status == LIBSSIG_ERROR_REVOKED) {
				break;
			}
		}
		if (status == LIBSSIG_OK || status == LIBSSIG_ERROR_REVOKED) {
			break;
		}
	}
	CRL_DIST_POINTS_free(points);
	return status;
}
static libssig_status chain_collect(
    X509*                        cert,
    bool                         tsa,
    const libssig_sign_services* services,
    libssig_validation_data*     data
) {
	STACK_OF(X509)* chain = NULL;
	libssig_status status = chain_build(cert, tsa, services, data, &chain);
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(chain); ++i) {
		X509* item = sk_X509_value(chain, i);
		if (!cert_add(data->certs, item)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		if (status == LIBSSIG_OK && i + 1 < sk_X509_num(chain)) {
			status = certificate_ocsp(
			    item,
			    sk_X509_value(chain, i + 1),
			    tsa,
			    services,
			    data
			);
			if (status == LIBSSIG_ERROR_OCSP ||
			    status == LIBSSIG_ERROR_ARGUMENT) {
				status = certificate_crl(
				    item,
				    sk_X509_value(chain, i + 1),
				    services,
				    data
				);
			}
		}
	}
	sk_X509_pop_free(chain, X509_free);
	return status;
}
static libssig_status timestamp_collect(
    CMS_SignerInfo*              signer,
    const libssig_sign_services* services,
    libssig_validation_data*     data
) {
	int index = CMS_unsigned_get_attr_by_NID(
	    signer,
	    NID_id_smime_aa_timeStampToken,
	    -1
	);
	X509_ATTRIBUTE* attr = index >= 0 ? CMS_unsigned_get_attr(signer, index)
	                                  : NULL;
	const ASN1_TYPE* value = attr && X509_ATTRIBUTE_count(attr) == 1
	                            ? X509_ATTRIBUTE_get0_type(attr, 0)
	                            : NULL;
	if (!value || value->type != V_ASN1_SEQUENCE) {
		return LIBSSIG_ERROR_TIMESTAMP;
	}
	const unsigned char* cursor = ASN1_STRING_get0_data(value->value.sequence);
	CMS_ContentInfo*     token = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        ASN1_STRING_length(value->value.sequence)
    );
	STACK_OF(X509)* certs = token ? CMS_get1_certs(token) : NULL;
	libssig_status status = LIBSSIG_OK;
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(certs); ++i) {
		if (!cert_add(data->certs, sk_X509_value(certs, i))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	STACK_OF(CMS_SignerInfo)* signers = token ? CMS_get0_SignerInfos(token)
	                                          : NULL;
	CMS_SignerInfo* s = sk_CMS_SignerInfo_num(signers) == 1
	                        ? sk_CMS_SignerInfo_value(signers, 0)
	                        : NULL;
	X509*           cert = NULL;
	if (s) {
		CMS_set1_signers_certs(token, certs, 0);
		CMS_SignerInfo_get0_algs(s, NULL, &cert, NULL, NULL);
	}
	if (status == LIBSSIG_OK) {
		status = cert ? chain_collect(cert, true, services, data)
		              : LIBSSIG_ERROR_TIMESTAMP;
	}
	sk_X509_pop_free(certs, X509_free);
	CMS_ContentInfo_free(token);
	return status;
}
libssig_status libssig_validation_collect(
    CMS_ContentInfo*             cms,
    const libssig_sign_services* services,
    libssig_validation_data*     data
) {
	data->certs = CMS_get1_certs(cms);
	data->revocations = sk_ASN1_TYPE_new_null();
	if (!data->certs || !data->revocations) {
		return LIBSSIG_ERROR_MEMORY;
	}
	libssig_verify_params doc = trust_params(services, false),
	                      tsa = trust_params(services, true);
	libssig_status status = bundle_add(
	    data,
	    doc.intermediates_data,
	    doc.intermediates_data_len
	);
	if (status == LIBSSIG_OK) {
		status = bundle_add(
		    data,
		    tsa.intermediates_data,
		    tsa.intermediates_data_len
		);
	}
	if (status == LIBSSIG_OK) {
		status = bundle_add(data, doc.ca_data, doc.ca_data_len);
	}
	if (status == LIBSSIG_OK) {
		status = bundle_add(data, tsa.ca_data, tsa.ca_data_len);
	}
	CMS_set1_signers_certs(cms, data->certs, 0);
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	for (int i = 0; status == LIBSSIG_OK && i < sk_CMS_SignerInfo_num(signers);
	     ++i) {
		CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, i);
		X509*           cert = NULL;
		CMS_SignerInfo_get0_algs(signer, NULL, &cert, NULL, NULL);
		status = cert ? chain_collect(cert, false, services, data)
		              : LIBSSIG_ERROR_VERIFY;
		if (status == LIBSSIG_OK) {
			status = timestamp_collect(signer, services, data);
		}
		ASN1_OBJECT* archive_oid = OBJ_txt2obj(LIBSSIG_ARCHIVE_OID, 1);
		int          pos = -1;
		while (status == LIBSSIG_OK && archive_oid &&
		       (pos = CMS_unsigned_get_attr_by_OBJ(signer, archive_oid, pos)) >=
		           0) {
			X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(signer, pos);
			for (int j = 0;
			     status == LIBSSIG_OK && j < X509_ATTRIBUTE_count(attr);
			     ++j) {
				const ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attr, j);
				if (!value || value->type != V_ASN1_SEQUENCE) {
					status = LIBSSIG_ERROR_TIMESTAMP;
					break;
				}
				libssig_signature timestamp = {
				    .data = (unsigned char*)
				        ASN1_STRING_get0_data(value->value.sequence),
				    .len = (size_t)ASN1_STRING_length(value->value.sequence)
				};
				status = libssig_validation_timestamp_collect(
				    &timestamp,
				    services,
				    data
				);
			}
		}
		ASN1_OBJECT_free(archive_oid);
	}
	return status;
}

libssig_status libssig_validation_tsa_certs(
    PKCS7*                       token,
    const libssig_sign_services* services,
    STACK_OF(X509) * *chain
) {
	libssig_validation_data data = {.certs = sk_X509_new_null()};
	if (!data.certs) {
		return LIBSSIG_ERROR_MEMORY;
	}
	libssig_verify_params trust = trust_params(services, true);
	libssig_status status = bundle_add(&data, trust.ca_data, trust.ca_data_len);
	if (status == LIBSSIG_OK) {
		status = bundle_add(
		    &data,
		    trust.intermediates_data,
		    trust.intermediates_data_len
		);
	}
	STACK_OF(X509)* signers = token ? PKCS7_get0_signers(token, NULL, 0) : NULL;
	STACK_OF(X509)* embedded = token && PKCS7_type_is_signed(token)
	                               ? token->d.sign->cert
	                               : NULL;
	for (int i = 0; status == LIBSSIG_OK && i < sk_X509_num(embedded); ++i) {
		if (!cert_add(data.certs, sk_X509_value(embedded, i))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	if (status == LIBSSIG_OK) {
		status = sk_X509_num(signers) == 1 ? chain_build(
		                                         sk_X509_value(signers, 0),
		                                         true,
		                                         services,
		                                         &data,
		                                         chain
		                                     )
		                                   : LIBSSIG_ERROR_TIMESTAMP;
	}
	sk_X509_free(signers);
	libssig_validation_free(&data);
	return status;
}

/* Certificate collection is independent of the document serialization. */
libssig_status libssig_validation_document_collect(
    X509*                        cert,
    const libssig_signature*     timestamp,
    const libssig_sign_services* services,
    libssig_validation_data*     data
) {
	data->certs = sk_X509_new_null();
	data->revocations = sk_ASN1_TYPE_new_null();
	if (!data->certs || !data->revocations || !cert_add(data->certs, cert)) {
		return LIBSSIG_ERROR_MEMORY;
	}
	libssig_verify_params doc = trust_params(services, false),
	                      tsa = trust_params(services, true);
	libssig_status status = bundle_add(
	    data,
	    doc.intermediates_data,
	    doc.intermediates_data_len
	);
	if (status == LIBSSIG_OK) {
		status = bundle_add(
		    data,
		    tsa.intermediates_data,
		    tsa.intermediates_data_len
		);
	}
	if (status == LIBSSIG_OK) {
		status = bundle_add(data, doc.ca_data, doc.ca_data_len);
	}
	if (status == LIBSSIG_OK) {
		status = bundle_add(data, tsa.ca_data, tsa.ca_data_len);
	}
	if (status == LIBSSIG_OK) {
		status = chain_collect(cert, false, services, data);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_validation_timestamp_collect(
		    timestamp,
		    services,
		    data
		);
	}
	return status;
}

bool libssig_validation_revocation_read(
    ASN1_TYPE*         item,
    libssig_signature* bytes,
    bool*              ocsp
) {
	*ocsp = item->type == V_ASN1_OTHER;
	unsigned char*    encoded = NULL;
	int               len = i2d_ASN1_TYPE(item, &encoded);
	other_revocation* other = NULL;
	if (*ocsp && len > 0) {
		encoded[0] = 0x30;
		const unsigned char* cursor = encoded;
		other = d2i_other_revocation(NULL, &cursor, len);
		OPENSSL_free(encoded);
		encoded = NULL;
		len = other ? i2d_ASN1_TYPE(other->value, &encoded) : 0;
	}
	bool ok = len > 0 && libssig_bytes_append(bytes, encoded, (size_t)len);
	OPENSSL_free(encoded);
	other_revocation_free(other);
	return ok;
}
bool libssig_validation_revocation_add(
    libssig_validation_data* data,
    const unsigned char*     bytes,
    size_t                   len,
    bool                     ocsp
) {
	if (len > 16 * 1024 * 1024 || sk_ASN1_TYPE_num(data->revocations) >= 1024) {
		return false;
	}
	if (ocsp) {
		return revocation_add(data, bytes, len);
	}
	const unsigned char* cursor = bytes;
	X509_CRL*            crl = d2i_X509_CRL(NULL, &cursor, (long)len);
	bool                 ok = crl && cursor == bytes + len;
	X509_CRL_free(crl);
	if (!ok) {
		return false;
	}
	cursor = bytes;
	ASN1_TYPE* value = d2i_ASN1_TYPE(NULL, &cursor, (long)len);
	if (value && sk_ASN1_TYPE_push(data->revocations, value)) {
		return true;
	}
	ASN1_TYPE_free(value);
	return false;
}

libssig_status libssig_validation_timestamp_collect(
    const libssig_signature*     timestamp,
    const libssig_sign_services* services,
    libssig_validation_data*     data
) {
	libssig_status       status = LIBSSIG_OK;
	const unsigned char* cursor = timestamp->data;
	CMS_ContentInfo*     token = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)timestamp->len
    );
	STACK_OF(X509)* embedded = token ? CMS_get1_certs(token) : NULL;
	if (status == LIBSSIG_OK) {
		status = token && cursor == timestamp->data + timestamp->len
		             ? libssig_verify_certs_append(data->certs, embedded)
		             : LIBSSIG_ERROR_TIMESTAMP;
	}
	STACK_OF(CMS_SignerInfo)* signers = token ? CMS_get0_SignerInfos(token)
	                                          : NULL;
	X509* tsa_cert = NULL;
	if (token && sk_CMS_SignerInfo_num(signers) == 1) {
		CMS_set1_signers_certs(token, data->certs, 0);
		CMS_SignerInfo_get0_algs(
		    sk_CMS_SignerInfo_value(signers, 0),
		    NULL,
		    &tsa_cert,
		    NULL,
		    NULL
		);
	}
	if (status == LIBSSIG_OK) {
		status = tsa_cert ? chain_collect(tsa_cert, true, services, data)
		                  : LIBSSIG_ERROR_TIMESTAMP;
	}
	sk_X509_pop_free(embedded, X509_free);
	CMS_ContentInfo_free(token);
	return status;
}
