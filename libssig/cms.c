/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/cms_internal.h>
#include <limits.h>
#include <openssl/cms.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>

static const EVP_MD* digest_get(libssig_hash hash) {
	switch (hash) {
	case LIBSSIG_HASH_SHA256:
		return EVP_sha256();
	case LIBSSIG_HASH_SHA384:
		return EVP_sha384();
	case LIBSSIG_HASH_SHA512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

static X509* certificate_decode(const libssig_certificate* cert) {
	if (!cert || !cert->der || !cert->der_len || cert->der_len > LONG_MAX) {
		return NULL;
	}

	const unsigned char* cursor = cert->der;
	X509*                x509 = d2i_X509(NULL, &cursor, (long)cert->der_len);
	if (!x509 || cursor != cert->der + cert->der_len) {
		X509_free(x509);
		return NULL;
	}
	return x509;
}

static ASN1_STRING* pss_parameters(const EVP_MD* digest) {
	RSA_PSS_PARAMS* pss = RSA_PSS_PARAMS_new();
	if (!pss) {
		return NULL;
	}

	pss->hashAlgorithm = X509_ALGOR_new();
	pss->maskGenAlgorithm = X509_ALGOR_new();
	pss->saltLength = ASN1_INTEGER_new();
	ASN1_STRING* encoded = NULL;
	if (pss->hashAlgorithm && pss->maskGenAlgorithm && pss->saltLength) {
		X509_ALGOR_set_md(pss->hashAlgorithm, digest);
		ASN1_STRING* mask = ASN1_item_pack(
		    pss->hashAlgorithm,
		    ASN1_ITEM_rptr(X509_ALGOR),
		    NULL
		);
		if (mask) {
			if (X509_ALGOR_set0(
			        pss->maskGenAlgorithm,
			        OBJ_nid2obj(NID_mgf1),
			        V_ASN1_SEQUENCE,
			        mask
			    )) {
				if (ASN1_INTEGER_set(pss->saltLength, EVP_MD_size(digest))) {
					encoded = ASN1_item_pack(
					    pss,
					    ASN1_ITEM_rptr(RSA_PSS_PARAMS),
					    NULL
					);
				}
			} else {
				ASN1_STRING_free(mask);
			}
		}
	}
	RSA_PSS_PARAMS_free(pss);
	return encoded;
}

static bool signature_algorithm_set(
    CMS_SignerInfo* signer,
    libssig_algo    algo,
    const EVP_MD*   digest
) {
	if (algo != LIBSSIG_ALGO_RSA_PSS) {
		return true;
	}

	ASN1_STRING* parameters = pss_parameters(digest);
	if (!parameters) {
		return false;
	}

	X509_ALGOR* algorithm = NULL;
	CMS_SignerInfo_get0_algs(signer, NULL, NULL, NULL, &algorithm);
	if (!X509_ALGOR_set0(
	        algorithm,
	        OBJ_nid2obj(NID_rsassaPss),
	        V_ASN1_SEQUENCE,
	        parameters
	    )) {
		ASN1_STRING_free(parameters);
		return false;
	}
	return true;
}

static bool ecdsa_signature_set(
    ASN1_OCTET_STRING*       output,
    const libssig_signature* raw
) {
	if (!raw->len || raw->len % 2 || raw->len / 2 > INT_MAX) {
		return false;
	}

	int        half = (int)(raw->len / 2);
	BIGNUM*    r = BN_bin2bn(raw->data, half, NULL);
	BIGNUM*    s = BN_bin2bn(raw->data + half, half, NULL);
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (!r || !s || !sig || !ECDSA_SIG_set0(sig, r, s)) {
		BN_free(r);
		BN_free(s);
		ECDSA_SIG_free(sig);
		return false;
	}

	unsigned char* der = NULL;
	int            len = i2d_ECDSA_SIG(sig, &der);
	bool           ok = len > 0 && ASN1_OCTET_STRING_set(output, der, len);
	OPENSSL_free(der);
	ECDSA_SIG_free(sig);
	return ok;
}

static bool signature_set(
    CMS_SignerInfo*          signer,
    libssig_algo             algo,
    const libssig_signature* raw
) {
	ASN1_OCTET_STRING* signature = CMS_SignerInfo_get0_signature(signer);
	if (algo == LIBSSIG_ALGO_ECDSA) {
		return ecdsa_signature_set(signature, raw);
	}

	return raw->len <= INT_MAX &&
	       ASN1_OCTET_STRING_set(signature, raw->data, (int)raw->len);
}

static CMS_ContentInfo* container_create(
    X509*                      cert,
    const libssig_sign_params* params,
    bool                       cades
) {
	CMS_ContentInfo* cms = CMS_sign(
	    NULL,
	    NULL,
	    NULL,
	    NULL,
	    CMS_PARTIAL | CMS_BINARY | CMS_DETACHED
	);
	EVP_PKEY*       public_key = X509_get_pubkey(cert);
	const EVP_MD*   digest = digest_get(params->hash);
	CMS_SignerInfo* signer = cms && public_key && digest
	                             ? CMS_add1_signer(
	                                   cms,
	                                   cert,
	                                   public_key,
	                                   digest,
	                                   CMS_NOSMIMECAP | CMS_PARTIAL |
	                                       (cades ? 0 : CMS_NOATTR)
	                               )
	                             : NULL;
	EVP_PKEY_free(public_key);
	if (!signer || !CMS_set_detached(cms, 1) ||
	    !signature_algorithm_set(signer, params->algo, digest) ||
	    (cades &&
	     !libssig_cades_attributes_add(signer, cert, params, digest))) {
		CMS_ContentInfo_free(cms);
		return NULL;
	}
	return cms;
}

static bool container_verify(
    CMS_ContentInfo*           cms,
    const libssig_sign_params* params
) {
	const unsigned char empty = 0;
	const void*         data = params->data ? params->data : &empty;
	BIO*                input = BIO_new_mem_buf(data, (int)params->data_len);
	BIO*                output = BIO_new(BIO_s_null());
	bool                ok = input && output &&
	          CMS_verify(
	              cms,
	              NULL,
	              NULL,
	              input,
	              output,
	              CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
	          ) == 1;
	BIO_free(input);
	BIO_free(output);
	return ok;
}

static libssig_status container_encode(
    CMS_ContentInfo*   cms,
    libssig_signature* output
) {
	int len = i2d_CMS_ContentInfo(cms, NULL);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}

	output->data = malloc((size_t)len);
	if (!output->data) {
		return LIBSSIG_ERROR_MEMORY;
	}

	unsigned char* cursor = output->data;
	if (i2d_CMS_ContentInfo(cms, &cursor) != len) {
		libssig_signature_free(output);
		return LIBSSIG_ERROR_CRYPTO;
	}
	output->len = (size_t)len;
	return LIBSSIG_OK;
}

static bool params_valid(
    const libssig_sign_params* params,
    const libssig_certificate* cert
) {
	return params && cert && params->id && cert->id && params->id_len &&
	       params->id_len == cert->id_len &&
	       !memcmp(params->id, cert->id, cert->id_len) &&
	       (params->data || !params->data_len) && params->data_len <= INT_MAX;
}

static libssig_status container_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    CMS_ContentInfo*           cms,
    bool                       cades,
    libssig_signature*         output
) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	libssig_sign_params signing = *params;
	unsigned char*      attributes = NULL;
	if (cades) {
		attributes = libssig_cades_attributes_encode(signer, &signing.data_len);
		if (!attributes) {
			return LIBSSIG_ERROR_CRYPTO;
		}
		signing.data = attributes;
	}

	libssig_signature raw = {0};
	libssig_status    status = libssig_session_sign(ctx, &signing, &raw);
	OPENSSL_free(attributes);
	if (status == LIBSSIG_OK) {
		bool ok = signature_set(signer, params->algo, &raw) &&
		          container_verify(cms, params);
		status = ok ? container_encode(cms, output) : LIBSSIG_ERROR_CRYPTO;
	}
	output->ck_rv = raw.ck_rv;
	libssig_signature_free(&raw);
	return status;
}

static libssig_status detached_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const libssig_certificate* cert,
    bool                       cades,
    libssig_signature*         output
) {
	if (!output) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*output = (libssig_signature){0};
	if (!params_valid(params, cert)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	X509* x509 = certificate_decode(cert);
	if (!x509) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	CMS_ContentInfo* cms = container_create(x509, params, cades);
	libssig_status
	    status = cms ? container_sign(ctx, params, cms, cades, output)
	                 : LIBSSIG_ERROR_CRYPTO;
	CMS_ContentInfo_free(cms);
	X509_free(x509);
	return status;
}

libssig_status libssig_cms_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const libssig_certificate* cert,
    libssig_signature*         output
) {
	return detached_sign(ctx, params, cert, false, output);
}

libssig_status libssig_cades_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const libssig_certificate* cert,
    libssig_signature*         output
) {
	return detached_sign(ctx, params, cert, true, output);
}
