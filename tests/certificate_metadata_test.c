/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static unsigned char* ders[5];
static size_t         lens[5];
static unsigned int   cursor;
static unsigned int   finalize_count;

static int extension_add(X509* cert, int nid, const char* value) {
	X509_EXTENSION*
	    extension = X509V3_EXT_conf_nid(NULL, NULL, nid, (char*)value);
	if (!extension) {
		return 0;
	}
	int ok = X509_add_ext(cert, extension, -1);
	X509_EXTENSION_free(extension);
	return ok;
}

static int policies_add(X509* cert) {
	CERTIFICATEPOLICIES* policies = sk_POLICYINFO_new_null();
	POLICYINFO*          policy = POLICYINFO_new();
	if (!policies || !policy) {
		CERTIFICATEPOLICIES_free(policies);
		POLICYINFO_free(policy);
		return 0;
	}
	ASN1_OBJECT_free(policy->policyid);
	policy->policyid = OBJ_txt2obj("1.2.3.4.5", 1);
	if (!policy->policyid || !sk_POLICYINFO_push(policies, policy)) {
		POLICYINFO_free(policy);
		CERTIFICATEPOLICIES_free(policies);
		return 0;
	}
	int ok = X509_add1_ext_i2d(cert, NID_certificate_policies, policies, 0, 0);
	CERTIFICATEPOLICIES_free(policies);
	return ok;
}

static X509* certificate_create(EVP_PKEY* key) {
	X509* cert = X509_new();
	if (!cert) {
		return NULL;
	}
	if (!X509_set_version(cert, 2) ||
	    !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) ||
	    !X509_gmtime_adj(X509_getm_notBefore(cert), 0) ||
	    !X509_gmtime_adj(X509_getm_notAfter(cert), 3600) ||
	    !X509_set_pubkey(cert, key)) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static int certificate_encode(X509* cert, EVP_PKEY* key, size_t index) {
	CHECK(X509_sign(cert, key, EVP_sha256()) > 0);
	int len = i2d_X509(cert, &ders[index]);
	CHECK(len > 0);
	lens[index] = (size_t)len;
	return 0;
}

static CK_RV mock_find_init(
    CK_SESSION_HANDLE handle,
    CK_ATTRIBUTE_PTR  attrs,
    CK_ULONG          count
) {
	(void)handle;
	(void)attrs;
	(void)count;
	cursor = 0;
	return CKR_OK;
}

static CK_RV mock_find(
    CK_SESSION_HANDLE    handle,
    CK_OBJECT_HANDLE_PTR object,
    CK_ULONG             capacity,
    CK_ULONG_PTR         count
) {
	(void)handle;
	(void)capacity;
	*count = cursor < 5 ? 1 : 0;
	*object = ++cursor;
	return CKR_OK;
}

static CK_RV mock_find_final(CK_SESSION_HANDLE handle) {
	(void)handle;
	++finalize_count;
	return CKR_OK;
}

static CK_RV mock_attribute(
    CK_SESSION_HANDLE handle,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_PTR  attribute,
    CK_ULONG          count
) {
	(void)handle;
	(void)count;
	if (attribute->type != CKA_VALUE) {
		attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	size_t index = (size_t)object - 1;
	if (!ders[index]) {
		attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	if (attribute->pValue) {
		if (attribute->ulValueLen < lens[index]) {
			return CKR_BUFFER_TOO_SMALL;
		}
		memcpy(attribute->pValue, ders[index], lens[index]);
	}
	attribute->ulValueLen = (CK_ULONG)lens[index];
	return CKR_OK;
}

static int enumeration_check(void) {
	CK_FUNCTION_LIST module = {0};
	module.C_FindObjectsInit = mock_find_init;
	module.C_FindObjects = mock_find;
	module.C_FindObjectsFinal = mock_find_final;
	module.C_GetAttributeValue = mock_attribute;
	libssig_session          s = {.module = &module, .open = true};
	libssig_certificate_list certs = {0};
	CK_RV                    rv = CKR_OK;
	CHECK(libssig_certificates_collect(&s, &certs, 0, &rv) == LIBSSIG_OK);
	CHECK(certs.count == 1 && rv == CKR_OK && finalize_count == 1);
	CHECK(
	    certs.items[0].key_usage == (LIBSSIG_KEY_USAGE_DIGITAL_SIGNATURE |
	                                 LIBSSIG_KEY_USAGE_CONTENT_COMMITMENT)
	);
	CHECK(certs.items[0].key_usage_names.count == 2);
	CHECK(
	    !strcmp(certs.items[0].key_usage_names.items[1], "content-commitment")
	);
	CHECK(certs.items[0].extended_key_usage_present);
	CHECK(certs.items[0].extended_key_usage.count == 2);
	CHECK(
	    !strcmp(certs.items[0].extended_key_usage.items[0], "1.3.6.1.5.5.7.3.4")
	);
	CHECK(!strcmp(certs.items[0].extended_key_usage.items[1], "1.2.3.99"));
	CHECK(certs.items[0].certificate_policies_present);
	CHECK(certs.items[0].certificate_policies.count == 1);
	CHECK(!strcmp(certs.items[0].certificate_policies.items[0], "1.2.3.4.5"));
	libssig_certificates_free(&certs);
	CHECK(!certs.items && !certs.count);

	CHECK(
	    libssig_certificates_collect(
	        &s,
	        &certs,
	        LIBSSIG_CERTIFICATES_ALL,
	        &rv
	    ) == LIBSSIG_OK
	);
	CHECK(certs.count == 5 && finalize_count == 2);
	CHECK(
	    certs.items[0].key_usage == (LIBSSIG_KEY_USAGE_DIGITAL_SIGNATURE |
	                                 LIBSSIG_KEY_USAGE_KEY_ENCIPHERMENT)
	);
	CHECK(
	    !strcmp(certs.items[0].extended_key_usage.items[0], "1.3.6.1.5.5.7.3.2")
	);
	CHECK(certs.items[2].metadata_status == LIBSSIG_CERTIFICATE_METADATA_VALID);
	CHECK(
	    !certs.items[2].key_usage_present &&
	    !certs.items[2].key_usage_names.count
	);
	CHECK(
	    !certs.items[2].extended_key_usage_present &&
	    !certs.items[2].certificate_policies_present
	);
	CHECK(
	    certs.items[3].metadata_status == LIBSSIG_CERTIFICATE_METADATA_INVALID
	);
	CHECK(
	    certs.items[4].metadata_status ==
	    LIBSSIG_CERTIFICATE_METADATA_UNAVAILABLE
	);
	libssig_certificates_free(&certs);
	libssig_certificates_free(&certs);

	CK_FUNCTION_LIST*           modules[] = {&module, NULL};
	struct libssig_context_impl impl = {.modules = modules};
	libssig_context             ctx = {.impl = &impl};
	libssig_token               token = {.uri = "pkcs11:token=test"};
	CHECK(
	    libssig_certificates(&ctx, &token, &certs, ~0u) ==
	    LIBSSIG_ERROR_ARGUMENT
	);
	CHECK(!certs.items && !certs.count && finalize_count == 2);
	return 0;
}

static int invalid_metadata_check(X509* cert, EVP_PKEY* key) {
	/* Duplicated known extensions must not classify as signing certificates. */
	CHECK(
	    extension_add(cert, NID_key_usage, "digitalSignature,nonRepudiation")
	);
	unsigned char* der = NULL;
	CHECK(X509_sign(cert, key, EVP_sha256()) > 0);
	int len = i2d_X509(cert, &der);
	CHECK(len > 0);
	libssig_certificate result = {.der = der, .der_len = (size_t)len};
	CHECK(libssig_certificate_metadata_read(&result) == LIBSSIG_OK);
	CHECK(result.metadata_status == LIBSSIG_CERTIFICATE_METADATA_INVALID);
	CHECK(!result.key_usage_present && !result.key_usage_names.items);
	CHECK(
	    !result.extended_key_usage.items && !result.certificate_policies.items
	);
	libssig_certificate_metadata_clear(&result);
	OPENSSL_free(der);

	/* A valid certificate followed by garbage is not accepted. */
	unsigned char* trailing = OPENSSL_malloc(lens[1] + 1);
	CHECK(trailing);
	memcpy(trailing, ders[1], lens[1]);
	trailing[lens[1]] = 0;
	result = (libssig_certificate){.der = trailing, .der_len = lens[1] + 1};
	CHECK(libssig_certificate_metadata_read(&result) == LIBSSIG_OK);
	CHECK(result.metadata_status == LIBSSIG_CERTIFICATE_METADATA_INVALID);
	libssig_certificate_metadata_clear(&result);
	OPENSSL_free(trailing);
	return 0;
}

static int malformed_extension_check(EVP_PKEY* key) {
	X509* cert = certificate_create(key);
	CHECK(cert);
	CHECK(
	    extension_add(cert, NID_key_usage, "digitalSignature,nonRepudiation")
	);
	ASN1_OCTET_STRING* bytes = ASN1_OCTET_STRING_new();
	CHECK(
	    bytes &&
	    ASN1_OCTET_STRING_set(bytes, (const unsigned char*)"invalid", 7)
	);
	X509_EXTENSION*
	    ext = X509_EXTENSION_create_by_NID(NULL, NID_ext_key_usage, 0, bytes);
	CHECK(ext && X509_add_ext(cert, ext, -1));
	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(bytes);
	CHECK(X509_sign(cert, key, EVP_sha256()) > 0);
	unsigned char* der = NULL;
	int            len = i2d_X509(cert, &der);
	CHECK(len > 0);
	libssig_certificate result = {.der = der, .der_len = (size_t)len};
	CHECK(libssig_certificate_metadata_read(&result) == LIBSSIG_OK);
	CHECK(result.metadata_status == LIBSSIG_CERTIFICATE_METADATA_INVALID);
	CHECK(!result.key_usage && !result.key_usage_names.items);
	CHECK(
	    !result.extended_key_usage_present && !result.extended_key_usage.items
	);
	libssig_certificate_metadata_clear(&result);
	OPENSSL_free(der);
	X509_free(cert);
	return 0;
}

int main(void) {
	EVP_PKEY*     key = NULL;
	EVP_PKEY_CTX* gen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	CHECK(gen && EVP_PKEY_keygen_init(gen) == 1);
	CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(gen, 2048) == 1);
	CHECK(EVP_PKEY_keygen(gen, &key) == 1);
	EVP_PKEY_CTX_free(gen);

	X509* auth = certificate_create(key);
	X509* signing = certificate_create(key);
	X509* unknown = certificate_create(key);
	CHECK(auth && signing && unknown);
	CHECK(extension_add(
	    auth,
	    NID_key_usage,
	    "critical,digitalSignature,keyEncipherment"
	));
	CHECK(extension_add(auth, NID_ext_key_usage, "clientAuth"));
	CHECK(extension_add(
	    signing,
	    NID_key_usage,
	    "critical,digitalSignature,nonRepudiation"
	));
	CHECK(
	    extension_add(signing, NID_ext_key_usage, "emailProtection,1.2.3.99")
	);
	CHECK(policies_add(signing));
	CHECK(certificate_encode(auth, key, 0) == 0);
	CHECK(certificate_encode(signing, key, 1) == 0);
	CHECK(certificate_encode(unknown, key, 2) == 0);
	static unsigned char invalid[] = {0x30, 0x02, 0x05, 0};
	ders[3] = invalid;
	lens[3] = sizeof(invalid);
	CHECK(enumeration_check() == 0);
	CHECK(invalid_metadata_check(signing, key) == 0);
	CHECK(malformed_extension_check(key) == 0);
	for (size_t i = 0; i < 3; ++i) {
		OPENSSL_free(ders[i]);
	}
	X509_free(auth);
	X509_free(signing);
	X509_free(unknown);
	EVP_PKEY_free(key);
	return 0;
}
