/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <libssig/libssig.h>
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static const unsigned char content[] = {0, 0xff, 42, '\n'};

static X509* cert_create(EVP_PKEY* key, long serial, bool expired) {
	X509* cert = X509_new();
	if (!cert) {
		return NULL;
	}

	X509_NAME* name = X509_get_subject_name(cert);
	int        ok = X509_set_version(cert, 2) &&
	         ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) &&
	         X509_gmtime_adj(X509_getm_notBefore(cert), -3600) &&
	         X509_gmtime_adj(X509_getm_notAfter(cert), expired ? -60 : 3600) &&
	         X509_NAME_add_entry_by_txt(
	             name,
	             "CN",
	             MBSTRING_ASC,
	             (const unsigned char*)"Verification test",
	             -1,
	             -1,
	             0
	         ) &&
	         X509_set_issuer_name(cert, name) && X509_set_pubkey(cert, key) &&
	         X509_sign(cert, key, EVP_sha256());
	if (!ok) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static unsigned char* cms_encode(CMS_ContentInfo* cms, size_t* out_len) {
	unsigned char* data = NULL;
	int            len = i2d_CMS_ContentInfo(cms, &data);
	*out_len = len > 0 ? (size_t)len : 0;
	return data;
}

static int detached_check(CMS_ContentInfo* cms) {
	libssig_verify_params params = {
	    .content = content,
	    .content_len = sizeof(content)
	};
	unsigned char* data = cms_encode(cms, &params.data_len);
	CHECK(data);
	params.data = data;

	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_OK);
	CHECK(result.signature_valid && result.detached && result.count == 1);
	CHECK(!result.trust_checked && !result.trusted);
	CHECK(result.signers[0].cert_der && !result.signers[0].mime_type);
	libssig_verify_free(&result);
	libssig_verify_free(&result);
	CHECK(!result.count && !result.signers);

	params.content = NULL;
	params.content_len = 0;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_CONTENT_REQUIRED);
	params.content = (const unsigned char*)"altered";
	params.content_len = 7;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_VERIFY);
	CHECK(
	    !result.signature_valid &&
	    result.count ==
	        (size_t)sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(cms)) &&
	    result.signers[0].status == LIBSSIG_ERROR_VERIFY
	);
	libssig_verify_free(&result);
	params.content = content;
	params.content_len = sizeof(content);
	params.options = LIBSSIG_VERIFY_SYSTEM_TRUST;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_TRUST);
	CHECK(result.signature_valid && result.trust_checked && !result.trusted);
	CHECK(result.signers[0].trust_error != X509_V_OK);
	libssig_verify_free(&result);
	OPENSSL_free(data);
	return 0;
}

static int trust_check(CMS_ContentInfo* cms, X509* cert, bool expired) {
	char path[] = "/tmp/libssig-verify-XXXXXX";
	int  fd = mkstemp(path);
	CHECK(fd >= 0);
	FILE* file = fdopen(fd, "w");
	CHECK(file && PEM_write_X509(file, cert) && fclose(file) == 0);
	CHECK(setenv("SSL_CERT_FILE", path, 1) == 0);

	libssig_verify_params params = {
	    .content = content,
	    .content_len = sizeof(content),
	    .options = LIBSSIG_VERIFY_SYSTEM_TRUST
	};
	unsigned char* data = cms_encode(cms, &params.data_len);
	CHECK(data);
	params.data = data;
	libssig_verify_result result = {0};
	CHECK(
	    libssig_verify(&params, &result) ==
	    (expired ? LIBSSIG_ERROR_TRUST : LIBSSIG_OK)
	);
	CHECK(result.signature_valid && result.trust_checked);
	CHECK(result.trusted == !expired);
	CHECK(
	    result.signers[0].trust_error ==
	    (expired ? X509_V_ERR_CERT_HAS_EXPIRED : X509_V_OK)
	);
	libssig_verify_free(&result);
	OPENSSL_free(data);
	CHECK(unlink(path) == 0);
	CHECK(setenv("SSL_CERT_FILE", "/nonexistent-libssig-ca", 1) == 0);
	return 0;
}

static int attached_check(CMS_ContentInfo* cms, size_t count) {
	libssig_verify_params params = {0};
	unsigned char*        data = cms_encode(cms, &params.data_len);
	CHECK(data);
	params.data = data;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_OK);
	CHECK(result.signature_valid && !result.detached && result.count == count);
	libssig_verify_free(&result);
	params.content = content;
	params.content_len = sizeof(content);
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	OPENSSL_free(data);
	return 0;
}

static int container_errors_check(CMS_ContentInfo* cms) {
	libssig_verify_params params = {
	    .content = content,
	    .content_len = sizeof(content),
	};
	unsigned char* data = cms_encode(cms, &params.data_len);
	CHECK(data);
	unsigned char* trailing = malloc(params.data_len + 1);
	CHECK(trailing);
	memcpy(trailing, data, params.data_len);
	trailing[params.data_len] = 0;
	params.data = trailing;
	++params.data_len;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_FORMAT);
	--params.data_len;
	--params.data_len;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_FORMAT);
	free(trailing);
	OPENSSL_free(data);

	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	ASN1_OCTET_STRING* signature = CMS_SignerInfo_get0_signature(signer);
	unsigned char*     bytes = (unsigned char*)ASN1_STRING_get0_data(signature);
	/* Reject a bad signature while preserving its explicitly failed report. */
	bytes[0] ^= 1;
	data = cms_encode(cms, &params.data_len);
	CHECK(data);
	params.data = data;
	if (!CMS_is_detached(cms)) {
		params.content = NULL;
		params.content_len = 0;
	}
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_VERIFY);
	CHECK(
	    !result.signature_valid &&
	    result.count ==
	        (size_t)sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(cms)) &&
	    result.signers[0].checked &&
	    result.signers[0].status == LIBSSIG_ERROR_VERIFY
	);
	libssig_verify_free(&result);
	bytes[0] ^= 1;
	OPENSSL_free(data);
	return 0;
}

static int unsupported_digest_check(CMS_ContentInfo* cms) {
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	X509_ALGOR* digest = NULL;
	CMS_SignerInfo_get0_algs(signer, NULL, NULL, &digest, NULL);
	X509_ALGOR* saved = X509_ALGOR_dup(digest);
	CHECK(saved);
	CHECK(X509_ALGOR_set0(
	    digest,
	    OBJ_txt2obj("1.2.3.4.987654", 1),
	    V_ASN1_UNDEF,
	    NULL
	));
	libssig_verify_params params = {
	    .content = content,
	    .content_len = sizeof(content),
	};
	unsigned char* data = cms_encode(cms, &params.data_len);
	CHECK(data);
	params.data = data;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_UNSUPPORTED);
	CHECK(!result.signature_valid && !result.signers);
	CHECK(X509_ALGOR_copy(digest, saved));
	X509_ALGOR_free(saved);
	OPENSSL_free(data);
	return 0;
}

static int missing_certificate_check(EVP_PKEY* key, X509* cert) {
	BIO*             input = BIO_new_mem_buf(content, sizeof(content));
	CMS_ContentInfo* cms = CMS_sign(
	    cert,
	    key,
	    NULL,
	    input,
	    CMS_BINARY | CMS_DETACHED | CMS_NOCERTS
	);
	CHECK(cms);
	libssig_verify_params params = {
	    .content = content,
	    .content_len = sizeof(content),
	};
	unsigned char* data = cms_encode(cms, &params.data_len);
	CHECK(data);
	params.data = data;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_VERIFY);
	CHECK(
	    result.count == 1 && !result.signature_valid &&
	    result.signers[0].status == LIBSSIG_ERROR_VERIFY
	);
	libssig_verify_free(&result);
	OPENSSL_free(data);
	CMS_ContentInfo_free(cms);
	BIO_free(input);
	return 0;
}

static int invalid_check(void) {
	libssig_verify_result result = {0};
	libssig_verify_params params = {0};
	CHECK(libssig_verify(NULL, &result) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_verify(&params, NULL) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	params.data = content;
	params.data_len = sizeof(content);
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_FORMAT);
	params.options = 0x80000000u;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	params.options = 0;
	params.content_len = 1;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	libssig_verify_free(NULL);
	return 0;
}

int main(void) {
	/* Nix OpenSSL gives this variable precedence over SSL_CERT_FILE. */
	CHECK(unsetenv("NIX_SSL_CERT_FILE") == 0);
	CHECK(setenv("SSL_CERT_FILE", "/nonexistent-libssig-ca", 1) == 0);
	CHECK(setenv("SSL_CERT_DIR", "/nonexistent-libssig-ca-dir", 1) == 0);
	CHECK(invalid_check() == 0);
	EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	CHECK(key);
	X509* cert = cert_create(key, 1, false);
	X509* expired = cert_create(key, 2, true);
	CHECK(cert && expired);

	BIO* input = BIO_new_mem_buf(content, sizeof(content));
	CMS_ContentInfo*
	    cms = CMS_sign(cert, key, NULL, input, CMS_BINARY | CMS_DETACHED);
	CHECK(cms && detached_check(cms) == 0);
	CHECK(trust_check(cms, cert, false) == 0);
	CHECK(container_errors_check(cms) == 0);
	CHECK(unsupported_digest_check(cms) == 0);
	CHECK(missing_certificate_check(key, cert) == 0);
	CMS_ContentInfo_free(cms);
	BIO_free(input);

	input = BIO_new_mem_buf(content, sizeof(content));
	cms = CMS_sign(expired, key, NULL, input, CMS_BINARY | CMS_DETACHED);
	CHECK(cms && trust_check(cms, expired, true) == 0);
	CMS_ContentInfo_free(cms);
	BIO_free(input);

	input = BIO_new_mem_buf(content, sizeof(content));
	cms = CMS_sign(cert, key, NULL, input, CMS_BINARY);
	CHECK(cms && attached_check(cms, 1) == 0);
	CMS_ContentInfo_free(cms);
	BIO_free(input);

	input = BIO_new_mem_buf(content, sizeof(content));
	cms = CMS_sign(NULL, NULL, NULL, NULL, CMS_BINARY | CMS_PARTIAL);
	CHECK(cms && CMS_add1_signer(cms, cert, key, EVP_sha256(), 0));
	CHECK(CMS_add1_signer(cms, expired, key, EVP_sha384(), 0));
	CHECK(CMS_final(cms, input, NULL, CMS_BINARY));
	CHECK(attached_check(cms, 2) == 0);
	CHECK(container_errors_check(cms) == 0);
	CMS_ContentInfo_free(cms);
	BIO_free(input);

	/* Empty external content is present when the pointer is non-NULL. */
	input = BIO_new_mem_buf("", 0);
	cms = CMS_sign(cert, key, NULL, input, CMS_BINARY | CMS_DETACHED);
	CHECK(cms);
	libssig_verify_params params = {.content = (const unsigned char*)""};
	unsigned char*        data = cms_encode(cms, &params.data_len);
	CHECK(data);
	params.data = data;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_OK);
	libssig_verify_free(&result);
	OPENSSL_free(data);
	CMS_ContentInfo_free(cms);
	BIO_free(input);
	X509_free(expired);
	X509_free(cert);
	EVP_PKEY_free(key);
	return 0;
}
