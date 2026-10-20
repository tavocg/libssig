/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <libssig/libssig.h>
#include <limits.h>
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

typedef struct {
	unsigned char* data;
	size_t         len;
} buffer;

static bool extension_add(
    X509*       cert,
    X509*       issuer,
    int         nid,
    const char* value
) {
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
	X509_EXTENSION* extension = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	bool            ok = extension && X509_add_ext(cert, extension, -1);
	X509_EXTENSION_free(extension);
	return ok;
}

static X509* cert_create(
    EVP_PKEY*   key,
    const char* name,
    long        serial,
    X509*       issuer,
    EVP_PKEY*   issuer_key,
    bool        ca
) {
	X509* cert = X509_new();
	if (!cert) {
		return NULL;
	}

	bool ok = X509_set_version(cert, 2) &&
	          ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) &&
	          X509_gmtime_adj(X509_getm_notBefore(cert), -3600) &&
	          X509_gmtime_adj(X509_getm_notAfter(cert), 3600) &&
	          X509_NAME_add_entry_by_txt(
	              X509_get_subject_name(cert),
	              "CN",
	              MBSTRING_ASC,
	              (const unsigned char*)name,
	              -1,
	              -1,
	              0
	          ) &&
	          X509_set_issuer_name(
	              cert,
	              X509_get_subject_name(issuer ? issuer : cert)
	          ) &&
	          X509_set_pubkey(cert, key) &&
	          extension_add(
	              cert,
	              issuer ? issuer : cert,
	              NID_basic_constraints,
	              ca ? "critical,CA:TRUE" : "critical,CA:FALSE"
	          ) &&
	          extension_add(
	              cert,
	              issuer ? issuer : cert,
	              NID_key_usage,
	              ca ? "critical,keyCertSign,cRLSign"
	                 : "critical,digitalSignature"
	          ) &&
	          X509_sign(cert, issuer_key ? issuer_key : key, EVP_sha256());
	if (!ok) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static buffer cert_encode(X509* cert, bool pem) {
	buffer output = {0};
	BIO*   bio = BIO_new(BIO_s_mem());
	int    ok = bio &&
	         (pem ? PEM_write_bio_X509(bio, cert) : i2d_X509_bio(bio, cert));
	if (ok) {
		char* bytes = NULL;
		long  len = BIO_get_mem_data(bio, &bytes);
		if (len > 0) {
			output.data = malloc((size_t)len);
			if (output.data) {
				memcpy(output.data, bytes, (size_t)len);
				output.len = (size_t)len;
			}
		}
	}
	BIO_free(bio);
	return output;
}

static int verify_check(
    const libssig_verify_params* params,
    libssig_status               expected
) {
	libssig_verify_result result = {0};
	libssig_status        status = libssig_verify(params, &result);
	if (status != expected) {
		fprintf(stderr, "Expected status %d, got %d\n", expected, status);
	}
	CHECK(status == expected);
	if (expected == LIBSSIG_OK || expected == LIBSSIG_ERROR_TRUST) {
		CHECK(
		    result.signature_valid && result.count == 1 && result.trust_checked
		);
		CHECK(result.trusted == (expected == LIBSSIG_OK));
		CHECK((result.signers[0].trust_error == X509_V_OK) == result.trusted);
	} else {
		CHECK(!result.signature_valid && !result.signers && !result.count);
	}
	libssig_verify_free(&result);
	return 0;
}

static int invalid_bundles_check(
    libssig_verify_params base,
    buffer                root,
    buffer                intermediate
) {
	base.ca_data = root.data;
	base.ca_data_len = root.len;
	base.intermediates_data = intermediate.data;
	base.intermediates_data_len = intermediate.len;
	const char* invalid[] = {
	    "",
	    " \n\t",
	    "garbage",
	    "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
	};
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
		base.ca_data = (const unsigned char*)invalid[i];
		base.ca_data_len = strlen(invalid[i]);
		CHECK(
		    verify_check(
		        &base,
		        i ? LIBSSIG_ERROR_FORMAT : LIBSSIG_ERROR_ARGUMENT
		    ) == 0
		);
	}

	base.ca_data = NULL;
	base.ca_data_len = 1;
	CHECK(verify_check(&base, LIBSSIG_ERROR_ARGUMENT) == 0);
	base.ca_data = root.data;
	base.ca_data_len = (size_t)INT_MAX + 1;
	CHECK(verify_check(&base, LIBSSIG_ERROR_ARGUMENT) == 0);
	base.ca_data_len = root.len;
	base.intermediates_data_len = 0;
	CHECK(verify_check(&base, LIBSSIG_ERROR_ARGUMENT) == 0);
	base.intermediates_data = NULL;
	base.intermediates_data_len = 1;
	CHECK(verify_check(&base, LIBSSIG_ERROR_ARGUMENT) == 0);
	base.intermediates_data = (const unsigned char*)"invalid";
	base.intermediates_data_len = 7;
	CHECK(verify_check(&base, LIBSSIG_ERROR_FORMAT) == 0);
	base.ca_data = NULL;
	base.ca_data_len = 0;
	base.intermediates_data = intermediate.data;
	base.intermediates_data_len = intermediate.len;
	CHECK(verify_check(&base, LIBSSIG_ERROR_ARGUMENT) == 0);

	unsigned char* bundle = malloc(root.len * 2 + 1);
	CHECK(bundle);
	memcpy(bundle, root.data, root.len);
	memcpy(bundle + root.len, root.data, root.len);
	base.ca_data = bundle;
	base.ca_data_len = root.len * 2;
	CHECK(verify_check(&base, LIBSSIG_OK) == 0);
	base.ca_data_len = root.len + root.len / 2;
	CHECK(verify_check(&base, LIBSSIG_ERROR_FORMAT) == 0);
	bundle[root.len] = '!';
	base.ca_data_len = root.len + 1;
	CHECK(verify_check(&base, LIBSSIG_ERROR_FORMAT) == 0);
	free(bundle);
	return 0;
}

static int system_combination_check(
    libssig_verify_params params,
    buffer                root,
    buffer                other
) {
	char path[] = "/tmp/libssig-trust-XXXXXX";
	int  fd = mkstemp(path);
	CHECK(fd >= 0);
	FILE* file = fdopen(fd, "wb");
	CHECK(file && fwrite(root.data, 1, root.len, file) == root.len);
	CHECK(fclose(file) == 0);
	CHECK(setenv("SSL_CERT_FILE", path, 1) == 0);

	params.ca_data = other.data;
	params.ca_data_len = other.len;
	params.options = 0;
	CHECK(verify_check(&params, LIBSSIG_ERROR_TRUST) == 0);
	params.options = LIBSSIG_VERIFY_SYSTEM_TRUST;
	CHECK(verify_check(&params, LIBSSIG_OK) == 0);
	params.ca_data = NULL;
	params.ca_data_len = 0;
	CHECK(verify_check(&params, LIBSSIG_OK) == 0);

	file = fopen(path, "wb");
	CHECK(file && fwrite(other.data, 1, other.len, file) == other.len);
	CHECK(fclose(file) == 0);
	params.ca_data = root.data;
	params.ca_data_len = root.len;
	CHECK(verify_check(&params, LIBSSIG_OK) == 0);
	CHECK(unlink(path) == 0);
	CHECK(setenv("SSL_CERT_FILE", "/nonexistent-libssig-ca", 1) == 0);
	return 0;
}

static int fixtures_write(
    const char* directory,
    const char* name,
    buffer      bytes
) {
	if (!directory) {
		return 0;
	}

	char path[4096];
	int  len = snprintf(path, sizeof(path), "%s/%s", directory, name);
	CHECK(len > 0 && (size_t)len < sizeof(path));
	FILE* file = fopen(path, "wb");
	CHECK(file && fwrite(bytes.data, 1, bytes.len, file) == bytes.len);
	CHECK(fclose(file) == 0);
	return 0;
}

static int chain_check(
    CMS_ContentInfo* cms,
    buffer           root,
    buffer           intermediate,
    buffer           other,
    const char*      directory
) {
	unsigned char* data = NULL;
	int            len = i2d_CMS_ContentInfo(cms, &data);
	CHECK(len > 0);
	libssig_verify_params params = {
	    .data = data,
	    .data_len = (size_t)len,
	    .ca_data = root.data,
	    .ca_data_len = root.len,
	    .intermediates_data = intermediate.data,
	    .intermediates_data_len = intermediate.len,
	};
	CHECK(verify_check(&params, LIBSSIG_OK) == 0);
	CHECK(invalid_bundles_check(params, root, intermediate) == 0);
	CHECK(system_combination_check(params, root, other) == 0);
	params.intermediates_data = NULL;
	params.intermediates_data_len = 0;
	CHECK(verify_check(&params, LIBSSIG_ERROR_TRUST) == 0);
	params.ca_data = intermediate.data;
	params.ca_data_len = intermediate.len;
	CHECK(verify_check(&params, LIBSSIG_ERROR_TRUST) == 0);

	/* Putting the real root and intermediate in the untrusted list cannot
	 * make a different trust anchor accept this signature. */
	unsigned char* bundle = malloc(root.len + intermediate.len);
	CHECK(bundle);
	memcpy(bundle, root.data, root.len);
	memcpy(bundle + root.len, intermediate.data, intermediate.len);
	params.ca_data = other.data;
	params.ca_data_len = other.len;
	params.intermediates_data = bundle;
	params.intermediates_data_len = root.len + intermediate.len;
	CHECK(verify_check(&params, LIBSSIG_ERROR_TRUST) == 0);
	free(bundle);

	CHECK(
	    fixtures_write(directory, "signed.p7m", (buffer){data, (size_t)len}) ==
	    0
	);
	CHECK(fixtures_write(directory, "root.pem", root) == 0);
	CHECK(fixtures_write(directory, "intermediate.pem", intermediate) == 0);
	CHECK(fixtures_write(directory, "other.pem", other) == 0);
	OPENSSL_free(data);
	return 0;
}

int main(int argc, char** argv) {
	CHECK(argc <= 2);
	CHECK(setenv("SSL_CERT_FILE", "/nonexistent-libssig-ca", 1) == 0);
	CHECK(setenv("SSL_CERT_DIR", "/nonexistent-libssig-ca-dir", 1) == 0);
	EVP_PKEY* root_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	EVP_PKEY* inter_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	EVP_PKEY* leaf_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	EVP_PKEY* other_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	CHECK(root_key && inter_key && leaf_key && other_key);
	X509* root = cert_create(root_key, "Root", 1, NULL, NULL, true);
	X509* intermediate = cert_create(
	    inter_key,
	    "Intermediate",
	    2,
	    root,
	    root_key,
	    true
	);
	X509* leaf = cert_create(
	    leaf_key,
	    "Signer",
	    3,
	    intermediate,
	    inter_key,
	    false
	);
	X509* other = cert_create(other_key, "Unrelated root", 4, NULL, NULL, true);
	CHECK(root && intermediate && leaf && other);
	buffer root_pem = cert_encode(root, true);
	buffer inter_pem = cert_encode(intermediate, true);
	buffer other_pem = cert_encode(other, true);
	buffer root_der = cert_encode(root, false);
	buffer inter_der = cert_encode(intermediate, false);
	CHECK(
	    root_pem.data && inter_pem.data && other_pem.data && root_der.data &&
	    inter_der.data
	);

	BIO*             input = BIO_new_mem_buf("Document", 8);
	CMS_ContentInfo* cms = CMS_sign(leaf, leaf_key, NULL, input, CMS_BINARY);
	CHECK(cms);
	CHECK(
	    chain_check(
	        cms,
	        root_pem,
	        inter_pem,
	        other_pem,
	        argc == 2 ? argv[1] : NULL
	    ) == 0
	);
	unsigned char* data = NULL;
	int            len = i2d_CMS_ContentInfo(cms, &data);
	CHECK(len > 0);
	libssig_verify_params params = {
	    .data = data,
	    .data_len = (size_t)len,
	    .ca_data = root_der.data,
	    .ca_data_len = root_der.len,
	    .intermediates_data = inter_der.data,
	    .intermediates_data_len = inter_der.len,
	};
	CHECK(verify_check(&params, LIBSSIG_OK) == 0);
	unsigned char* trailing = malloc(root_der.len + 1);
	CHECK(trailing);
	memcpy(trailing, root_der.data, root_der.len);
	trailing[root_der.len] = 0;
	params.ca_data = trailing;
	params.ca_data_len = root_der.len + 1;
	CHECK(verify_check(&params, LIBSSIG_ERROR_FORMAT) == 0);
	free(trailing);
	params.ca_data = root_der.data;
	params.ca_data_len = root_der.len;
	OPENSSL_free(data);
	CHECK(CMS_add1_cert(cms, intermediate));
	data = NULL;
	len = i2d_CMS_ContentInfo(cms, &data);
	CHECK(len > 0);
	params.data = data;
	params.data_len = (size_t)len;
	params.intermediates_data = NULL;
	params.intermediates_data_len = 0;
	CHECK(verify_check(&params, LIBSSIG_OK) == 0);
	OPENSSL_free(data);
	CMS_ContentInfo_free(cms);
	BIO_free(input);
	free(root_pem.data);
	free(inter_pem.data);
	free(other_pem.data);
	free(root_der.data);
	free(inter_der.data);
	X509_free(root);
	X509_free(intermediate);
	X509_free(leaf);
	X509_free(other);
	EVP_PKEY_free(root_key);
	EVP_PKEY_free(inter_key);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(other_key);
	return 0;
}
