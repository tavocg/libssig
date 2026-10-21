/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/sign/internal.h>
#include <openssl/cms.h>
#include <openssl/ec.h>
#include <openssl/ess.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static EVP_PKEY*           rsa;
static EVP_PKEY*           public_key;
static const unsigned char id[] = {0, 0xff, 1};
static unsigned int        key_count = 1, cursor, final_count, close_count;
static unsigned int        login_count, context_login_count, sign_count;
static CK_KEY_TYPE         key_type = CKK_RSA;
static CK_BBOOL            can_sign = CK_TRUE, always_authenticate;
static CK_RV find_rv = CKR_OK, final_rv = CKR_OK, attribute_rv = CKR_OK;
static CK_RV login_rv = CKR_OK, init_rv = CKR_OK, sign_rv = CKR_OK,
             close_rv = CKR_OK;
static bool protected_path, initialized, authenticated;
static bool fail_signature_write;

static CK_RV mock_slots_get(
    CK_BBOOL       present,
    CK_SLOT_ID_PTR slots,
    CK_ULONG_PTR   count
) {
	(void)present;
	if (slots) {
		slots[0] = 1;
	}
	*count = 1;
	return CKR_OK;
}

static CK_RV mock_token_info_get(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
	(void)slot;
	memset(info, 0, sizeof(*info));
	memset(info->label, ' ', sizeof(info->label));
	memcpy(info->label, "test", 4);
	info->flags = CKF_LOGIN_REQUIRED;
	if (protected_path) {
		info->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
	}
	return CKR_OK;
}

static CK_RV mock_session_open(
    CK_SLOT_ID            slot,
    CK_FLAGS              flags,
    CK_VOID_PTR           app,
    CK_NOTIFY             notify,
    CK_SESSION_HANDLE_PTR handle
) {
	(void)slot;
	(void)app;
	(void)notify;
	if (flags != CKF_SERIAL_SESSION) {
		return CKR_ARGUMENTS_BAD;
	}
	initialized = false;
	authenticated = false;
	*handle = 42;
	return CKR_OK;
}

static CK_RV mock_session_close(CK_SESSION_HANDLE handle) {
	(void)handle;
	++close_count;
	initialized = false;
	return close_rv;
}

static CK_RV mock_session_login(
    CK_SESSION_HANDLE handle,
    CK_USER_TYPE      user,
    CK_UTF8CHAR_PTR   pin,
    CK_ULONG          len
) {
	(void)handle;
	if (protected_path) {
		if (pin || len) {
			return CKR_ARGUMENTS_BAD;
		}
	} else if (!pin || len != 4 || memcmp(pin, "1234", 4)) {
		return CKR_PIN_INCORRECT;
	}
	if (user == CKU_USER) {
		++login_count;
	} else if (user == CKU_CONTEXT_SPECIFIC && initialized) {
		++context_login_count;
		authenticated = true;
	} else {
		return CKR_ARGUMENTS_BAD;
	}
	return login_rv;
}

static CK_RV mock_objects_find_init(
    CK_SESSION_HANDLE handle,
    CK_ATTRIBUTE_PTR  attrs,
    CK_ULONG          count
) {
	(void)handle;
	if (count != 2 || attrs[0].type != CKA_CLASS ||
	    *(CK_OBJECT_CLASS*)attrs[0].pValue != CKO_PRIVATE_KEY ||
	    attrs[1].type != CKA_ID || attrs[1].ulValueLen != sizeof(id) ||
	    memcmp(attrs[1].pValue, id, sizeof(id))) {
		return CKR_ARGUMENTS_BAD;
	}
	cursor = 0;
	return CKR_OK;
}

static CK_RV mock_objects_find(
    CK_SESSION_HANDLE    handle,
    CK_OBJECT_HANDLE_PTR objects,
    CK_ULONG             capacity,
    CK_ULONG_PTR         count
) {
	(void)handle;
	if (capacity != 1) {
		return CKR_ARGUMENTS_BAD;
	}
	*count = cursor < key_count ? 1 : 0;
	*objects = 100 + cursor++;
	return find_rv;
}

static CK_RV mock_objects_find_final(CK_SESSION_HANDLE handle) {
	(void)handle;
	++final_count;
	return final_rv;
}

static CK_RV mock_attributes_get(
    CK_SESSION_HANDLE handle,
    CK_OBJECT_HANDLE  key,
    CK_ATTRIBUTE_PTR  attrs,
    CK_ULONG          count
) {
	(void)handle;
	if (key != 100) {
		return CKR_KEY_HANDLE_INVALID;
	}
	if (attribute_rv != CKR_OK) {
		return attribute_rv;
	}
	for (CK_ULONG i = 0; i < count; ++i) {
		const void* value;
		size_t      len;
		switch (attrs[i].type) {
		case CKA_KEY_TYPE:
			value = &key_type;
			len = sizeof(key_type);
			break;
		case CKA_SIGN:
			value = &can_sign;
			len = sizeof(can_sign);
			break;
		case CKA_ALWAYS_AUTHENTICATE:
			value = &always_authenticate;
			len = sizeof(always_authenticate);
			break;
		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		if (attrs[i].ulValueLen < len) {
			return CKR_BUFFER_TOO_SMALL;
		}
		memcpy(attrs[i].pValue, value, len);
		attrs[i].ulValueLen = (CK_ULONG)len;
	}
	return CKR_OK;
}

static const EVP_MD*        digest;
static libssig_algo         algorithm;
static CK_MECHANISM_TYPE    expected_mechanism = CKM_SHA256_RSA_PKCS;
static CK_MECHANISM_TYPE    expected_hash = CKM_SHA256;
static CK_RSA_PKCS_MGF_TYPE expected_mgf = CKG_MGF1_SHA256;

static int padding_set(EVP_PKEY_CTX* ctx) {
	if (algorithm != LIBSSIG_ALGO_RSA_PSS) {
		return 1;
	}
	return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) > 0 &&
	       EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest) > 0 &&
	       EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, EVP_MD_get_size(digest)) > 0;
}

static CK_RV mock_sign_init(
    CK_SESSION_HANDLE handle,
    CK_MECHANISM_PTR  mechanism,
    CK_OBJECT_HANDLE  key
) {
	(void)handle;
	if (key != 100 || mechanism->mechanism != expected_mechanism) {
		return CKR_ARGUMENTS_BAD;
	}

	if (algorithm == LIBSSIG_ALGO_RSA_PSS) {
		if (!mechanism->pParameter ||
		    mechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
			return CKR_MECHANISM_PARAM_INVALID;
		}
		CK_RSA_PKCS_PSS_PARAMS* pss = mechanism->pParameter;
		if (pss->hashAlg != expected_hash || pss->mgf != expected_mgf ||
		    pss->sLen != (CK_ULONG)EVP_MD_get_size(digest)) {
			return CKR_MECHANISM_PARAM_INVALID;
		}
	} else if (mechanism->pParameter || mechanism->ulParameterLen) {
		return CKR_ARGUMENTS_BAD;
	}
	initialized = true;
	return init_rv;
}

static int ecdsa_raw(const unsigned char* der, size_t len, unsigned char* raw) {
	ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &der, (long)len);
	if (!sig) {
		return 0;
	}
	const BIGNUM *r, *s;
	ECDSA_SIG_get0(sig, &r, &s);
	int ok = BN_bn2binpad(r, raw, 32) == 32 &&
	         BN_bn2binpad(s, raw + 32, 32) == 32;
	ECDSA_SIG_free(sig);
	return ok;
}

static int signature_create(
    CK_BYTE_PTR  data,
    CK_ULONG     len,
    CK_BYTE_PTR  signature,
    CK_ULONG_PTR out_len
) {
	EVP_MD_CTX* md = EVP_MD_CTX_new();
	if (!md) {
		return 0;
	}
	EVP_PKEY_CTX*  key_ctx = NULL;
	unsigned char  der[80];
	size_t         size = algorithm == LIBSSIG_ALGO_ECDSA ? sizeof(der)
	                                                      : (size_t)*out_len;
	unsigned char* output = algorithm == LIBSSIG_ALGO_ECDSA ? der : signature;
	int ok = EVP_DigestSignInit(md, &key_ctx, digest, NULL, rsa) == 1 &&
	         padding_set(key_ctx) &&
	         EVP_DigestSign(md, output, &size, data, (size_t)len) == 1;
	if (ok && algorithm == LIBSSIG_ALGO_ECDSA) {
		ok = ecdsa_raw(der, size, signature);
		size = 64;
	}
	EVP_MD_CTX_free(md);
	*out_len = (CK_ULONG)size;
	return ok;
}

static CK_RV mock_sign(
    CK_SESSION_HANDLE handle,
    CK_BYTE_PTR       data,
    CK_ULONG          len,
    CK_BYTE_PTR       signature,
    CK_ULONG_PTR      signature_len
) {
	(void)handle;
	if (!initialized || (always_authenticate && !authenticated)) {
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (sign_rv != CKR_OK) {
		return sign_rv;
	}

	if (!signature) {
		*signature_len = algorithm == LIBSSIG_ALGO_ECDSA
		                     ? 64
		                     : (CK_ULONG)EVP_PKEY_get_size(rsa);
		return CKR_OK;
	}

	if (fail_signature_write) {
		return CKR_DEVICE_ERROR;
	}

	int ok = signature_create(data, len, signature, signature_len);
	initialized = false;
	++sign_count;
	return ok ? CKR_OK : CKR_GENERAL_ERROR;
}

static int ecdsa_der(const libssig_signature* signature, unsigned char* der) {
	if (signature->len != 64) {
		return 0;
	}
	BIGNUM*    r = BN_bin2bn(signature->data, 32, NULL);
	BIGNUM*    s = BN_bin2bn(signature->data + 32, 32, NULL);
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (!r || !s || !sig || !ECDSA_SIG_set0(sig, r, s)) {
		BN_free(r);
		BN_free(s);
		ECDSA_SIG_free(sig);
		return 0;
	}
	int len = i2d_ECDSA_SIG(sig, &der);
	ECDSA_SIG_free(sig);
	return len;
}

static int signature_verify(
    const libssig_signature* signature,
    const unsigned char*     data,
    size_t                   len
) {
	EVP_MD_CTX* md = EVP_MD_CTX_new();
	if (!md) {
		return 0;
	}
	unsigned char        der[80];
	const unsigned char* bytes = signature->data;
	size_t               size = signature->len;
	if (algorithm == LIBSSIG_ALGO_ECDSA) {
		int der_len = ecdsa_der(signature, der);
		if (der_len <= 0) {
			EVP_MD_CTX_free(md);
			return 0;
		}
		bytes = der;
		size = (size_t)der_len;
	}
	EVP_PKEY_CTX* key_ctx = NULL;
	int ok = EVP_DigestVerifyInit(md, &key_ctx, digest, NULL, public_key) ==
	             1 &&
	         padding_set(key_ctx) &&
	         EVP_DigestVerify(md, bytes, size, data, len) == 1;
	EVP_MD_CTX_free(md);
	return ok;
}

static const char* fixture_directory;
static bool        mime_override_only;

static X509* cms_certificate_create(EVP_PKEY* key) {
	X509* cert = X509_new();
	if (!cert) {
		return NULL;
	}
	bool ok = X509_set_version(cert, 2) &&
	          ASN1_INTEGER_set(X509_get_serialNumber(cert), 2) &&
	          X509_gmtime_adj(X509_getm_notBefore(cert), 0) &&
	          X509_gmtime_adj(X509_getm_notAfter(cert), 3600) &&
	          X509_set_pubkey(cert, key);
	X509_NAME* name = X509_get_subject_name(cert);
	ok = ok &&
	     X509_NAME_add_entry_by_txt(
	         name,
	         "CN",
	         MBSTRING_ASC,
	         (const unsigned char*)"CMS test",
	         -1,
	         -1,
	         0
	     ) &&
	     X509_set_issuer_name(cert, name) &&
	     X509_sign(cert, key, EVP_sha256()) > 0;
	if (!ok) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static int cms_verify(
    const libssig_signature* output,
    const unsigned char*     data,
    size_t                   len
) {
	const unsigned char* cursor = output->data;
	CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)output->len
    );
	CHECK(
	    cms && cursor == output->data + output->len && CMS_is_detached(cms) == 1
	);
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	CHECK(sk_CMS_SignerInfo_num(signers) == 1);
	CHECK(
	    CMS_signed_get_attr_count(sk_CMS_SignerInfo_value(signers, 0)) < 0 ||
	    CMS_signed_get_attr_count(sk_CMS_SignerInfo_value(signers, 0)) == 5
	);
	STACK_OF(X509)* certs = CMS_get1_certs(cms);
	CHECK(sk_X509_num(certs) == 1);
	sk_X509_pop_free(certs, X509_free);
	BIO* input = BIO_new_mem_buf(data, (int)len);
	BIO* sink = BIO_new(BIO_s_null());
	int  verified = CMS_verify(
        cms,
        NULL,
        NULL,
        input,
        sink,
        CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
    );
	BIO_free(input);
	BIO_free(sink);
	CMS_ContentInfo_free(cms);
	return verified == 1 ? 0 : -1;
}

static int fixture_write(
    const char*          name,
    const unsigned char* data,
    size_t               len
) {
	if (!fixture_directory) {
		return 0;
	}
	char path[4096];
	int  size = snprintf(path, sizeof(path), "%s/%s", fixture_directory, name);
	CHECK(size > 0 && (size_t)size < sizeof(path));
	FILE* file = fopen(path, "wb");
	CHECK(file);
	bool written = fwrite(data, 1, len, file) == len;
	int  closed = fclose(file);
	CHECK(written && closed == 0);
	return 0;
}

static int cades_cardinality_check(CMS_ContentInfo* cms) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	CHECK(CMS_signed_get_attr_count(signer) == 5);
	const int nids[] = {
	    NID_pkcs9_contentType,
	    NID_pkcs9_messageDigest,
	    NID_pkcs9_signingTime,
	    NID_id_smime_aa_signingCertificateV2
	};
	for (size_t i = 0; i < sizeof(nids) / sizeof(nids[0]); ++i) {
		int index = CMS_signed_get_attr_by_NID(signer, nids[i], -1);
		CHECK(
		    index >= 0 && CMS_signed_get_attr_by_NID(signer, nids[i], index) < 0
		);
		CHECK(X509_ATTRIBUTE_count(CMS_signed_get_attr(signer, index)) == 1);
	}
	return 0;
}

static int cades_mime_check(
    CMS_ContentInfo*               cms,
    const libssig_key_sign_params* params
) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	ASN1_OBJECT* mime_oid = OBJ_txt2obj(LIBSSIG_CADES_MIME_TYPE_OID, 1);
	CHECK(mime_oid);
	int mime_index = CMS_signed_get_attr_by_OBJ(signer, mime_oid, -1);
	CHECK(
	    mime_index >= 0 &&
	    CMS_signed_get_attr_by_OBJ(signer, mime_oid, mime_index) < 0
	);
	ASN1_STRING* mime = CMS_signed_get0_data_by_OBJ(
	    signer,
	    mime_oid,
	    -3,
	    V_ASN1_UTF8STRING
	);
	const char* expected_mime = params->mime_type ? params->mime_type
	                                              : "application/octet-stream";
	CHECK(mime && ASN1_STRING_length(mime) == (int)strlen(expected_mime));
	CHECK(!memcmp(
	    ASN1_STRING_get0_data(mime),
	    expected_mime,
	    strlen(expected_mime)
	));
	ASN1_OBJECT_free(mime_oid);
	return 0;
}

static int cades_content_check(
    CMS_ContentInfo*               cms,
    const libssig_key_sign_params* params
) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	ASN1_OBJECT* type = CMS_signed_get0_data_by_OBJ(
	    signer,
	    OBJ_nid2obj(NID_pkcs9_contentType),
	    -3,
	    V_ASN1_OBJECT
	);
	CHECK(type && OBJ_obj2nid(type) == NID_pkcs7_data);
	ASN1_OCTET_STRING* hash = CMS_signed_get0_data_by_OBJ(
	    signer,
	    OBJ_nid2obj(NID_pkcs9_messageDigest),
	    -3,
	    V_ASN1_OCTET_STRING
	);
	unsigned char expected[EVP_MAX_MD_SIZE];
	unsigned int  len = 0;
	CHECK(
	    EVP_Digest(params->data, params->data_len, expected, &len, digest, NULL)
	);
	CHECK(hash && ASN1_STRING_length(hash) == (int)len);
	CHECK(!memcmp(ASN1_STRING_get0_data(hash), expected, len));
	return 0;
}

static int cades_time_check(CMS_ContentInfo* cms) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	int index = CMS_signed_get_attr_by_NID(signer, NID_pkcs9_signingTime, -1);
	ASN1_TYPE* time = X509_ATTRIBUTE_get0_type(
	    CMS_signed_get_attr(signer, index),
	    0
	);
	CHECK(
	    time &&
	    (time->type == V_ASN1_UTCTIME || time->type == V_ASN1_GENERALIZEDTIME)
	);
	CHECK(ASN1_TIME_check((ASN1_TIME*)time->value.asn1_string));
	return 0;
}

static int cades_certificate_check(CMS_ContentInfo* cms) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	ASN1_STRING* sequence = CMS_signed_get0_data_by_OBJ(
	    signer,
	    OBJ_nid2obj(NID_id_smime_aa_signingCertificateV2),
	    -3,
	    V_ASN1_SEQUENCE
	);
	CHECK(sequence);
	const unsigned char* cursor = ASN1_STRING_get0_data(sequence);
	ESS_SIGNING_CERT_V2* ess = d2i_ESS_SIGNING_CERT_V2(
	    NULL,
	    &cursor,
	    ASN1_STRING_length(sequence)
	);
	STACK_OF(X509)* certs = CMS_get1_certs(cms);
	CHECK(ess && OSSL_ESS_check_signing_certs(NULL, ess, certs, 1) == 1);
	ESS_SIGNING_CERT_V2_free(ess);
	sk_X509_pop_free(certs, X509_free);
	return 0;
}

static int cades_attributes_check(
    CMS_ContentInfo*               cms,
    const libssig_key_sign_params* params
) {
	CHECK(cades_cardinality_check(cms) == 0);
	CHECK(cades_mime_check(cms, params) == 0);
	CHECK(cades_content_check(cms, params) == 0);
	CHECK(cades_time_check(cms) == 0);
	CHECK(cades_certificate_check(cms) == 0);
	return 0;
}

static int cades_certificate_hash_corrupt(
    CMS_ContentInfo*               cms,
    const libssig_context*         ctx,
    const libssig_key_sign_params* params
) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	int index = CMS_signed_get_attr_by_NID(
	    signer,
	    NID_id_smime_aa_signingCertificateV2,
	    -1
	);
	ASN1_STRING* sequence = CMS_signed_get0_data_by_OBJ(
	    signer,
	    OBJ_nid2obj(NID_id_smime_aa_signingCertificateV2),
	    -3,
	    V_ASN1_SEQUENCE
	);
	CHECK(sequence);
	int            len = ASN1_STRING_length(sequence);
	unsigned char* encoded = OPENSSL_memdup(
	    ASN1_STRING_get0_data(sequence),
	    (size_t)len
	);
	CHECK(encoded && len > 0);
	encoded[len - 1] ^= 1; /* Last byte of the cert hash; issuerSerial is
	                          omitted. */
	X509_ATTRIBUTE_free(CMS_signed_delete_attr(signer, index));
	CHECK(CMS_signed_add1_attr_by_NID(
	    signer,
	    NID_id_smime_aa_signingCertificateV2,
	    V_ASN1_SEQUENCE,
	    encoded,
	    len
	));
	OPENSSL_free(encoded);
	libssig_key_sign_params signing = *params;
	unsigned char*          attributes = libssig_cades_v131_attributes_encode(
        signer,
        &signing.data_len
    );
	CHECK(attributes);
	signing.data = attributes;
	libssig_signature raw = {0};
	CHECK(libssig_session_sign(ctx, &signing, &raw) == LIBSSIG_OK);
	OPENSSL_free(attributes);
	CHECK(ASN1_OCTET_STRING_set(
	    CMS_SignerInfo_get0_signature(signer),
	    raw.data,
	    (int)raw.len
	));
	libssig_signature_free(&raw);
	unsigned char* der = NULL;
	len = i2d_CMS_ContentInfo(cms, &der);
	CHECK(len > 0);
	libssig_signature output = {.data = der, .len = (size_t)len};
	/* Signature remains valid; independent -cades verification must reject the
	 * ESS hash. */
	CHECK(cms_verify(&output, params->data, params->data_len) == 0);
	CHECK(fixture_write("cades-bad-cert.p7s", der, (size_t)len) == 0);
	libssig_verify_params request = {
	    .data = der,
	    .data_len = (size_t)len,
	    .content = params->data,
	    .content_len = params->data_len,
	};
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&request, &result) == LIBSSIG_ERROR_VERIFY);
	CHECK(!result.signature_valid && !result.signers);
	libssig_verify_free(&result);
	OPENSSL_free(der);
	return 0;
}

static int verify_roundtrip(
    const libssig_signature*   signature,
    const libssig_sign_params* params,
    bool                       attached
) {
	const unsigned char   empty = 0;
	libssig_verify_params request = {
	    .data = signature->data,
	    .data_len = signature->len,
	    .content = attached ? NULL : (params->data ? params->data : &empty),
	    .content_len = attached ? 0 : params->data_len,
	};
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&request, &result) == LIBSSIG_OK);
	CHECK(result.signature_valid && result.detached == !attached);
	CHECK(result.count == 1 && !result.trust_checked && !result.trusted);
	CHECK(result.signers[0].cert_der_len == params->cert->der_len);
	CHECK(!memcmp(
	    result.signers[0].cert_der,
	    params->cert->der,
	    params->cert->der_len
	));
	if (params->format == LIBSSIG_FORMAT_CADES) {
		CHECK(result.signers[0].mime_type);
	}
	libssig_verify_free(&result);
	return 0;
}

static libssig_status public_sign(
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    const libssig_certificate*     cert,
    libssig_format                 format,
    libssig_signature*             output
) {
	libssig_sign_params request = {
	    .level = LIBSSIG_LEVEL_B_B,
	    .token = params->token,
	    .cert = cert,
	    .data = params->data,
	    .data_len = params->data_len,
	    .pin = params->pin,
	    .pin_len = params->pin_len,
	    .algo = params->algo,
	    .hash = params->hash,
	    .format = format,
	    .mime_type = params->mime_type,
	};
	libssig_signature invalid = {0};
	request.options = 0x80000000u;
	CHECK(libssig_sign(ctx, &request, &invalid) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(!invalid.data && !invalid.len);
	request.options = LIBSSIG_SIGN_DETACHED;
	libssig_status status = libssig_sign(ctx, &request, output);
	if (status != LIBSSIG_OK) {
		return status;
	}

	CHECK(verify_roundtrip(output, &request, false) == 0);
	request.options = 0;
	libssig_signature attached = {0};
	CHECK(libssig_sign(ctx, &request, &attached) == LIBSSIG_OK);
	CHECK(verify_roundtrip(&attached, &request, true) == 0);
	char name[80];
	snprintf(
	    name,
	    sizeof(name),
	    "attached-%s-%d-%d.p7m",
	    format == LIBSSIG_FORMAT_CADES ? "cades" : "cms",
	    (int)params->algo,
	    (int)params->hash
	);
	CHECK(fixture_write(name, attached.data, attached.len) == 0);
	libssig_signature_free(&attached);
	return LIBSSIG_OK;
}

static int public_algorithms_invalid_check(
    const libssig_context*     ctx,
    const libssig_sign_params* base
) {
	libssig_signature   signature = {0};
	libssig_sign_params request = *base;
	unsigned int        closes = close_count;
	request.algo = (libssig_algo)99;
	CHECK(libssig_sign(ctx, &request, &signature) == LIBSSIG_ERROR_UNSUPPORTED);
	request = *base;
	request.hash = (libssig_hash)99;
	CHECK(libssig_sign(ctx, &request, &signature) == LIBSSIG_ERROR_UNSUPPORTED);
	request = *base;
	request.format = (libssig_format)99;
	CHECK(libssig_sign(ctx, &request, &signature) == LIBSSIG_ERROR_UNSUPPORTED);
	request = *base;
	request.mime_type = "text/plain\r\ninvalid";
	CHECK(libssig_sign(ctx, &request, &signature) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(
	    close_count == closes && !signature.data && !signature.len &&
	    !signature.ck_rv
	);
	return 0;
}

static int public_inputs_invalid_check(
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    const libssig_certificate*     cert
) {
	libssig_sign_params base = {
	    .level = LIBSSIG_LEVEL_B_B,
	    .token = params->token,
	    .cert = cert,
	    .data = params->data,
	    .data_len = params->data_len,
	    .pin = params->pin,
	    .pin_len = params->pin_len,
	};
	libssig_sign_params cases[6];
	for (size_t i = 0; i < 6; ++i) {
		cases[i] = base;
	}
	cases[0].token = NULL;
	cases[1].cert = NULL;
	cases[2].pin = NULL;
	cases[2].pin_len = 1;
	cases[3].data = NULL;
	cases[3].data_len = 1;
	cases[4].data_len = (size_t)INT_MAX + 1;
	libssig_certificate invalid = *cert;
	const unsigned char malformed[] = {0};
	invalid.der = (unsigned char*)malformed;
	invalid.der_len = sizeof(malformed);
	cases[5].cert = &invalid;
	libssig_signature signature = {0};
	unsigned int      closes = close_count;
	for (size_t i = 0; i < 6; ++i) {
		CHECK(
		    libssig_sign(ctx, &cases[i], &signature) == LIBSSIG_ERROR_ARGUMENT
		);
		CHECK(!signature.data && !signature.len && !signature.ck_rv);
	}
	CHECK(close_count == closes);
	CHECK(public_algorithms_invalid_check(ctx, &base) == 0);
	return 0;
}

static int cades_check(
    const libssig_context*     ctx,
    libssig_key_sign_params*   params,
    const libssig_certificate* cert
) {
	libssig_signature output = {0};
	CHECK(
	    public_sign(ctx, params, cert, LIBSSIG_FORMAT_CADES, &output) ==
	    LIBSSIG_OK
	);
	CHECK(cms_verify(&output, params->data, params->data_len) == 0);
	const unsigned char altered[] = {0, 0xff, 43};
	CHECK(cms_verify(&output, altered, sizeof(altered)) == -1);
	const unsigned char* cursor = output.data;
	CMS_ContentInfo* cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)output.len);
	CHECK(cms && cades_attributes_check(cms, params) == 0);
	char name[64];
	snprintf(name, sizeof(name), "cades-%d-%d.p7s", params->algo, params->hash);
	CHECK(fixture_write(name, output.data, output.len) == 0);
	STACK_OF(X509)* certs = CMS_get1_certs(cms);
	BIO* pem = BIO_new(BIO_s_mem());
	CHECK(pem && PEM_write_bio_X509(pem, sk_X509_value(certs, 0)));
	char* bytes = NULL;
	long  len = BIO_get_mem_data(pem, &bytes);
	snprintf(name, sizeof(name), "cades-%d-%d.pem", params->algo, params->hash);
	CHECK(
	    len > 0 &&
	    fixture_write(name, (const unsigned char*)bytes, (size_t)len) == 0
	);
	BIO_free(pem);
	sk_X509_pop_free(certs, X509_free);
	if (params->algo == LIBSSIG_ALGO_RSA_PKCS &&
	    params->hash == LIBSSIG_HASH_SHA256) {
		CHECK(cades_certificate_hash_corrupt(cms, ctx, params) == 0);
	}
	CMS_ContentInfo_free(cms);
	libssig_signature_free(&output);
	return 0;
}

static int cades_mime_detection_check(
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    const libssig_certificate*     cert
) {
	const unsigned char text[] = "Texto para detección automática de MIME.\n";
	const unsigned char
	    pdf[] = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
	const unsigned char* contents[] = {text, pdf, NULL};
	const size_t         lens[] = {sizeof(text) - 1, sizeof(pdf) - 1, 0};
	const char*          expected[] =
	    {"text/plain", "application/pdf", "application/x-empty"};
	for (size_t i = 0; i < 3; ++i) {
		libssig_key_sign_params signing = *params;
		signing.data = contents[i];
		signing.data_len = lens[i];
		signing.mime_type = NULL;
		libssig_signature output = {0};
		CHECK(
		    public_sign(ctx, &signing, cert, LIBSSIG_FORMAT_CADES, &output) ==
		    LIBSSIG_OK
		);
		CHECK(
		    cms_verify(
		        &output,
		        signing.data ? signing.data : (const unsigned char*)"",
		        signing.data_len
		    ) == 0
		);
		const unsigned char* cursor = output.data;
		CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
            NULL,
            &cursor,
            (long)output.len
        );
		signing.mime_type = expected[i];
		CHECK(cms && cades_mime_check(cms, &signing) == 0);
		CMS_ContentInfo_free(cms);
		libssig_signature_free(&output);
	}
	return 0;
}

static int pades_check(
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    const libssig_certificate*     cert
) {
	static const unsigned char pdf
	    [] = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 "
	         "0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 "
	         "obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] "
	         ">>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n "
	         "\n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 "
	         "/Root 1 0 R >>\nstartxref\n186\n%%EOF\n";
	libssig_sign_params request = {
	    .level = LIBSSIG_LEVEL_B_B,
	    .format = LIBSSIG_FORMAT_PADES,
	    .token = params->token,
	    .cert = cert,
	    .pin = params->pin,
	    .pin_len = params->pin_len,
	    .algo = params->algo,
	    .hash = params->hash,
	    .data = pdf,
	    .data_len = sizeof(pdf) - 1,
	};
	libssig_signature output = {0};
	CHECK(libssig_sign(ctx, &request, &output) == LIBSSIG_OK);
	CHECK(
	    output.len > sizeof(pdf) && !memcmp(output.data, pdf, sizeof(pdf) - 1)
	);
	char name[80];
	snprintf(name, sizeof(name), "pades-%d-%d.pdf", params->algo, params->hash);
	CHECK(fixture_write(name, output.data, output.len) == 0);
	libssig_signature_free(&output);
	return 0;
}

static int cms_check(
    const libssig_context*   ctx,
    libssig_key_sign_params* params
) {
	X509* x509 = cms_certificate_create(rsa);
	CHECK(x509);
	unsigned char* der = NULL;
	int            len = i2d_X509(x509, &der);
	X509_free(x509);
	CHECK(len > 0);
	libssig_certificate cert = {
	    .id = (unsigned char*)params->id,
	    .id_len = params->id_len,
	    .der = der,
	    .der_len = (size_t)len
	};
	CHECK(pades_check(ctx, params, &cert) == 0);
	libssig_signature output = {0};
	CHECK(
	    public_sign(ctx, params, &cert, LIBSSIG_FORMAT_CMS, &output) ==
	    LIBSSIG_OK
	);
	CHECK(cms_verify(&output, params->data, params->data_len) == 0);
	CHECK(cades_check(ctx, params, &cert) == 0);
	if (params->algo == LIBSSIG_ALGO_RSA_PKCS &&
	    params->hash == LIBSSIG_HASH_SHA256) {
		CHECK(public_inputs_invalid_check(ctx, params, &cert) == 0);
		CHECK(cades_mime_detection_check(ctx, params, &cert) == 0);
		params->mime_type = "application/pdf";
		CHECK(cades_check(ctx, params, &cert) == 0);
		params->mime_type = NULL;
	}
	const unsigned char altered[] = {0, 0xff, 43};
	CHECK(cms_verify(&output, altered, sizeof(altered)) == -1);
	char name[64];
	snprintf(name, sizeof(name), "cms-%d-%d.p7s", params->algo, params->hash);
	CHECK(fixture_write(name, output.data, output.len) == 0);
	CHECK(fixture_write("input.bin", params->data, params->data_len) == 0);
	CHECK(fixture_write("altered.bin", altered, sizeof(altered)) == 0);
	libssig_signature_free(&output);

	size_t id_len = cert.id_len;
	cert.id_len = 0;
	CHECK(
	    libssig_cms_sign(ctx, params, &cert, &output) == LIBSSIG_ERROR_ARGUMENT
	);
	cert.id_len = id_len;
	if (params->algo == LIBSSIG_ALGO_RSA_PKCS &&
	    params->hash == LIBSSIG_HASH_SHA256) {
		sign_rv = CKR_DEVICE_ERROR;
		CHECK(
		    libssig_cms_sign(ctx, params, &cert, &output) ==
		    LIBSSIG_ERROR_PKCS11
		);
		CHECK(output.ck_rv == CKR_DEVICE_ERROR && !output.data && !output.len);
		sign_rv = CKR_OK;
	}
	if (params->algo == LIBSSIG_ALGO_RSA_PKCS &&
	    params->hash == LIBSSIG_HASH_SHA256) {
		const unsigned char* saved_data = params->data;
		size_t               saved_len = params->data_len;
		params->data = NULL;
		params->data_len = 0;
		CHECK(libssig_cms_sign(ctx, params, &cert, &output) == LIBSSIG_OK);
		CHECK(cms_verify(&output, (const unsigned char*)"", 0) == 0);
		libssig_signature_free(&output);
		CHECK(
		    libssig_cades_v131_sign(ctx, params, &cert, &output) == LIBSSIG_OK
		);
		CHECK(cms_verify(&output, (const unsigned char*)"", 0) == 0);
		libssig_signature_free(&output);
		params->data = saved_data;
		params->data_len = saved_len;

		EVP_PKEY*     wrong_key = NULL;
		EVP_PKEY_CTX* gen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		CHECK(gen && EVP_PKEY_keygen_init(gen) == 1);
		CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(gen, 2048) == 1);
		CHECK(EVP_PKEY_keygen(gen, &wrong_key) == 1);
		EVP_PKEY_CTX_free(gen);
		X509* wrong = cms_certificate_create(wrong_key);
		CHECK(wrong);
		unsigned char* wrong_der = NULL;
		int            wrong_len = i2d_X509(wrong, &wrong_der);
		CHECK(wrong_len > 0);
		cert.der = wrong_der;
		cert.der_len = (size_t)wrong_len;
		CHECK(
		    libssig_cms_sign(ctx, params, &cert, &output) ==
		    LIBSSIG_ERROR_CRYPTO
		);
		CHECK(!output.data && !output.len);
		OPENSSL_free(wrong_der);
		X509_free(wrong);
		EVP_PKEY_free(wrong_key);
	}
	OPENSSL_free(der);
	return 0;
}

static int algorithms_check(
    const libssig_context*   ctx,
    libssig_key_sign_params* params
) {
	const EVP_MD* hashes[] = {EVP_sha256(), EVP_sha384(), EVP_sha512()};
	const CK_MECHANISM_TYPE mechanisms[3][3] = {
	    {CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS},
	    {CKM_SHA256_RSA_PKCS_PSS,
	     CKM_SHA384_RSA_PKCS_PSS,
	     CKM_SHA512_RSA_PKCS_PSS},
	    {CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512},
	};
	const CK_MECHANISM_TYPE pkcs_hashes[] =
	    {CKM_SHA256, CKM_SHA384, CKM_SHA512};
	const CK_RSA_PKCS_MGF_TYPE mgfs[] =
	    {CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512};
	EVP_PKEY*     ec = NULL;
	EVP_PKEY_CTX* gen = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	CHECK(gen && EVP_PKEY_keygen_init(gen) == 1);
	CHECK(
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen, NID_X9_62_prime256v1) == 1
	);
	CHECK(EVP_PKEY_keygen(gen, &ec) == 1);
	EVP_PKEY_CTX_free(gen);
	EVP_PKEY *          saved_rsa = rsa, *saved_public = public_key;
	const unsigned char message[] = {0, 0xff, 42};
	params->data = message;
	params->data_len = sizeof(message);
	params->id_len = sizeof(id);
	for (int i = LIBSSIG_ALGO_RSA_PKCS; i <= LIBSSIG_ALGO_ECDSA; ++i) {
		algorithm = (libssig_algo)i;
		params->algo = algorithm;
		rsa = algorithm == LIBSSIG_ALGO_ECDSA ? ec : saved_rsa;
		public_key = algorithm == LIBSSIG_ALGO_ECDSA ? ec : saved_public;
		key_type = algorithm == LIBSSIG_ALGO_ECDSA ? CKK_EC : CKK_RSA;
		for (int j = LIBSSIG_HASH_SHA256; j <= LIBSSIG_HASH_SHA512; ++j) {
			params->hash = (libssig_hash)j;
			digest = hashes[j];
			expected_mechanism = mechanisms[i][j];
			expected_hash = pkcs_hashes[j];
			expected_mgf = mgfs[j];
			libssig_signature signature = {0};
			CHECK(libssig_session_sign(ctx, params, &signature) == LIBSSIG_OK);
			CHECK(signature_verify(&signature, message, sizeof(message)));
			CHECK(!signature_verify(
			    &signature,
			    (const unsigned char*)"altered",
			    7
			));
			libssig_signature_free(&signature);
			if (mime_override_only) {
				X509* cert = cms_certificate_create(rsa);
				CHECK(cert);
				unsigned char* der = NULL;
				int            len = i2d_X509(cert, &der);
				CHECK(len > 0);
				libssig_certificate selected = {
				    .id = (unsigned char*)params->id,
				    .id_len = params->id_len,
				    .der = der,
				    .der_len = (size_t)len
				};
				params->mime_type = "application/pdf";
				CHECK(cades_check(ctx, params, &selected) == 0);
				OPENSSL_free(der);
				X509_free(cert);
			} else {
				CHECK(cms_check(ctx, params) == 0);
			}
		}
	}
	rsa = saved_rsa;
	public_key = saved_public;
	EVP_PKEY_free(ec);
	libssig_signature signature = {0};
	unsigned int      closes = close_count;
	params->algo = (libssig_algo)99;
	CHECK(
	    libssig_session_sign(ctx, params, &signature) ==
	    LIBSSIG_ERROR_UNSUPPORTED
	);
	params->algo = LIBSSIG_ALGO_RSA_PKCS;
	params->hash = (libssig_hash)99;
	CHECK(
	    libssig_session_sign(ctx, params, &signature) ==
	    LIBSSIG_ERROR_UNSUPPORTED
	);
	CHECK(close_count == closes && !signature.data);
	return 0;
}

int main(int argc, char** argv) {
	mime_override_only = argc == 2 && !strcmp(argv[1], "--mime-override-only");
	fixture_directory = argc == 2 && !mime_override_only ? argv[1] : NULL;
	digest = EVP_sha256();
	EVP_PKEY_CTX* keygen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	CHECK(keygen);
	CHECK(EVP_PKEY_keygen_init(keygen) == 1);
	CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(keygen, 2048) == 1);
	CHECK(EVP_PKEY_keygen(keygen, &rsa) == 1);
	EVP_PKEY_CTX_free(keygen);

	X509* cert = X509_new();
	CHECK(cert);
	CHECK(X509_set_version(cert, 2) == 1);
	CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
	CHECK(X509_gmtime_adj(X509_getm_notBefore(cert), 0));
	CHECK(X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
	CHECK(X509_set_pubkey(cert, rsa) == 1);
	X509_NAME* subject = X509_get_subject_name(cert);
	CHECK(
	    X509_NAME_add_entry_by_txt(
	        subject,
	        "CN",
	        MBSTRING_ASC,
	        (const unsigned char*)"libssig test",
	        -1,
	        -1,
	        0
	    ) == 1
	);
	CHECK(X509_set_issuer_name(cert, subject) == 1);
	CHECK(X509_sign(cert, rsa, EVP_sha256()) > 0);
	public_key = X509_get_pubkey(cert);
	CHECK(public_key);
	X509_free(cert);

	CK_FUNCTION_LIST module = {0};
	module.C_GetSlotList = mock_slots_get;
	module.C_GetTokenInfo = mock_token_info_get;
	module.C_OpenSession = mock_session_open;
	module.C_CloseSession = mock_session_close;
	module.C_Login = mock_session_login;
	module.C_FindObjectsInit = mock_objects_find_init;
	module.C_FindObjects = mock_objects_find;
	module.C_FindObjectsFinal = mock_objects_find_final;
	module.C_GetAttributeValue = mock_attributes_get;
	module.C_SignInit = mock_sign_init;
	module.C_Sign = mock_sign;
	CK_FUNCTION_LIST*           modules[] = {&module, NULL};
	struct libssig_context_impl impl = {.modules = modules};
	libssig_context             ctx = {.impl = &impl};
	libssig_token               token = {.uri = "pkcs11:token=test"};
	const unsigned char         data[] = {0, 1, 0xff, 0, 2};
	libssig_key_sign_params     params = {
	        .token = &token,
	        .id = id,
	        .id_len = sizeof(id),
	        .pin = (const unsigned char*)"1234",
	        .pin_len = 4,
	        .data = data,
	        .data_len = sizeof(data),
	        .options = LIBSSIG_SIGN_DETACHED,
    };
	libssig_signature signature = {0};
	CHECK(libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_OK);
	CHECK(signature.len == 256 && signature.ck_rv == CKR_OK);
	CHECK(signature_verify(&signature, data, sizeof(data)));
	unsigned char altered[] = {0, 1, 0xff, 0, 3};
	CHECK(!signature_verify(&signature, altered, sizeof(altered)));
	libssig_signature_free(&signature);
	CHECK(!signature.data && !signature.len);
	CHECK(
	    login_count == 1 && final_count == 1 && close_count == 1 &&
	    sign_count == 1
	);

	key_count = 0;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) ==
	    LIBSSIG_ERROR_NOT_FOUND
	);
	key_count = 2;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) ==
	    LIBSSIG_ERROR_AMBIGUOUS
	);
	key_count = 1;
	key_type = CKK_EC;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) ==
	    LIBSSIG_ERROR_UNSUPPORTED
	);
	key_type = CKK_RSA;
	can_sign = CK_FALSE;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) ==
	    LIBSSIG_ERROR_UNSUPPORTED
	);
	can_sign = CK_TRUE;
	CHECK(!signature.data && !signature.len && sign_count == 1);

	find_rv = CKR_DEVICE_ERROR;
	final_rv = CKR_GENERAL_ERROR;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(signature.ck_rv == CKR_DEVICE_ERROR && final_count == 6);
	find_rv = CKR_OK;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(signature.ck_rv == CKR_GENERAL_ERROR);
	final_rv = CKR_OK;
	attribute_rv = CKR_ATTRIBUTE_SENSITIVE;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(signature.ck_rv == CKR_ATTRIBUTE_SENSITIVE);
	attribute_rv = CKR_OK;
	login_rv = CKR_PIN_INCORRECT;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(signature.ck_rv == CKR_PIN_INCORRECT);
	login_rv = CKR_OK;
	init_rv = CKR_MECHANISM_INVALID;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(signature.ck_rv == CKR_MECHANISM_INVALID);
	init_rv = CKR_OK;
	sign_rv = CKR_DEVICE_ERROR;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(signature.ck_rv == CKR_DEVICE_ERROR && !signature.data);
	sign_rv = CKR_OK;
	fail_signature_write = true;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(
	    signature.ck_rv == CKR_DEVICE_ERROR && !signature.data && !signature.len
	);
	fail_signature_write = false;
	close_rv = CKR_DEVICE_ERROR;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(
	    signature.ck_rv == CKR_DEVICE_ERROR && !signature.data && !signature.len
	);
	close_rv = CKR_OK;

	always_authenticate = CK_TRUE;
	CHECK(libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_OK);
	CHECK(
	    context_login_count == 1 &&
	    signature_verify(&signature, data, sizeof(data))
	);
	libssig_signature_free(&signature);
	protected_path = true;
	params.pin = NULL;
	params.pin_len = 0;
	params.data = NULL;
	params.data_len = 0;
	CHECK(libssig_session_sign(&ctx, &params, &signature) == LIBSSIG_OK);
	CHECK(
	    context_login_count == 2 &&
	    signature_verify(&signature, (const unsigned char*)"", 0)
	);
	libssig_signature_free(&signature);
	unsigned int closes = close_count;
	CHECK(
	    libssig_session_sign(NULL, &params, &signature) ==
	    LIBSSIG_ERROR_ARGUMENT
	);
	CHECK(
	    libssig_session_sign(&ctx, NULL, &signature) == LIBSSIG_ERROR_ARGUMENT
	);
	CHECK(libssig_session_sign(&ctx, &params, NULL) == LIBSSIG_ERROR_ARGUMENT);
	params.id_len = 0;
	CHECK(
	    libssig_session_sign(&ctx, &params, &signature) ==
	    LIBSSIG_ERROR_ARGUMENT
	);
	CHECK(close_count == closes);
	CHECK(algorithms_check(&ctx, &params) == 0);
	libssig_signature_free(NULL);
	EVP_PKEY_free(public_key);
	EVP_PKEY_free(rsa);
	return 0;
}
