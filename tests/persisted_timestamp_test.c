/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			ERR_print_errors_fp(stderr);                                       \
			return 1;                                                          \
		}                                                                      \
	} while (0)

typedef struct {
	unsigned char* data;
	size_t         len;
} buffer;
static buffer      original, roots, signer_cert;
static const char* directory;

static buffer file_read(const char* name) {
	char path[4096];
	snprintf(path, sizeof(path), "%s/%s", directory, name);
	FILE*  file = fopen(path, "rb");
	buffer bytes = {0};
	if (!file) {
		return bytes;
	}
	if (fseek(file, 0, SEEK_END) == 0) {
		long len = ftell(file);
		if (len > 0 && fseek(file, 0, SEEK_SET) == 0) {
			bytes.data = malloc((size_t)len);
			if (bytes.data &&
			    fread(bytes.data, 1, (size_t)len, file) == (size_t)len) {
				bytes.len = (size_t)len;
			} else {
				free(bytes.data);
				bytes.data = NULL;
			}
		}
	}
	fclose(file);
	return bytes;
}

static CMS_ContentInfo* decode(buffer bytes) {
	const unsigned char* cursor = bytes.data;
	return d2i_CMS_ContentInfo(NULL, &cursor, (long)bytes.len);
}

static CMS_SignerInfo* signer_get(CMS_ContentInfo* cms) {
	return sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
}

static X509_ATTRIBUTE* timestamp_get(CMS_ContentInfo* cms) {
	CMS_SignerInfo* signer = signer_get(cms);
	int             i = CMS_unsigned_get_attr_by_NID(
        signer,
        NID_id_smime_aa_timeStampToken,
        -1
    );
	return CMS_unsigned_get_attr(signer, i);
}

static void timestamp_delete(CMS_ContentInfo* cms) {
	CMS_SignerInfo* signer = signer_get(cms);
	int             i = CMS_unsigned_get_attr_by_NID(
        signer,
        NID_id_smime_aa_timeStampToken,
        -1
    );
	X509_ATTRIBUTE_free(CMS_unsigned_delete_attr(signer, i));
}

static int verify_check(
    CMS_ContentInfo*      cms,
    libssig_verify_params params,
    libssig_status        expected,
    libssig_status        stamp_status,
    bool                  present,
    bool                  valid
) {
	unsigned char* encoded = NULL;
	int            len = i2d_CMS_ContentInfo(cms, &encoded);
	CHECK(len > 0);
	params.data = encoded;
	params.data_len = (size_t)len;
	libssig_verify_result result = {0};
	libssig_status        status = libssig_verify(&params, &result);
	if (status != expected) {
		fprintf(stderr, "Expected %d, got %d\n", expected, status);
	}
	CHECK(status == expected);
	CHECK(result.signature_valid && result.count == 1);
	libssig_verify_timestamp* stamp = &result.signers[0].timestamp;
	CHECK(stamp->present == present && stamp->valid == valid);
	CHECK(stamp->status == stamp_status);
	if (valid) {
		CHECK(strlen(stamp->time) == 20 && stamp->time[19] == 'Z');
		CHECK(stamp->cert_der && stamp->cert_der_len);
	} else {
		CHECK(!stamp->cert_der && !stamp->cert_der_len && !stamp->time[0]);
	}
	if (params.tsa_ca_data && valid) {
		CHECK(stamp->trust_checked);
		CHECK(stamp->trusted == (stamp_status == LIBSSIG_OK));
		CHECK((stamp->trust_error == 0) == stamp->trusted);
	} else {
		CHECK(!stamp->trust_checked && !stamp->trusted);
	}
	libssig_verify_free(&result);
	libssig_verify_free(&result);
	OPENSSL_free(encoded);
	return 0;
}

static int trust_check(void) {
	CMS_ContentInfo* cms = decode(original);
	CHECK(cms);
	libssig_verify_params params = {0};
	CHECK(verify_check(cms, params, LIBSSIG_OK, LIBSSIG_OK, true, true) == 0);
	params.ca_data = signer_cert.data;
	params.ca_data_len = signer_cert.len;
	CHECK(verify_check(cms, params, LIBSSIG_OK, LIBSSIG_OK, true, true) == 0);
	params.tsa_ca_data = roots.data;
	params.tsa_ca_data_len = roots.len;
	CHECK(verify_check(cms, params, LIBSSIG_OK, LIBSSIG_OK, true, true) == 0);
	params.ca_data = roots.data;
	params.ca_data_len = roots.len;
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TRUST,
	        LIBSSIG_OK,
	        true,
	        true
	    ) == 0
	);
	params.ca_data = NULL;
	params.ca_data_len = 0;
	params.tsa_ca_data = signer_cert.data;
	params.tsa_ca_data_len = signer_cert.len;
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TRUST,
	        LIBSSIG_ERROR_TRUST,
	        true,
	        true
	    ) == 0
	);
	CMS_ContentInfo_free(cms);
	return 0;
}

static int missing_check(void) {
	CMS_ContentInfo* cms = decode(original);
	CHECK(cms);
	timestamp_delete(cms);
	libssig_verify_params params = {0};
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_OK,
	        LIBSSIG_ERROR_NOT_FOUND,
	        false,
	        false
	    ) == 0
	);
	params.options = LIBSSIG_VERIFY_REQUIRE_TIMESTAMP;
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TIMESTAMP,
	        LIBSSIG_ERROR_NOT_FOUND,
	        false,
	        false
	    ) == 0
	);
	CMS_ContentInfo_free(cms);
	return 0;
}

static int malformed_check(void) {
	CMS_ContentInfo* cms = decode(original);
	CHECK(cms);
	X509_ATTRIBUTE* attr = timestamp_get(cms);
	CHECK(attr && CMS_unsigned_add1_attr(signer_get(cms), attr));
	libssig_verify_params params = {0};
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TIMESTAMP,
	        LIBSSIG_ERROR_FORMAT,
	        true,
	        false
	    ) == 0
	);
	CMS_ContentInfo_free(cms);

	cms = decode(original);
	CHECK(cms);
	attr = timestamp_get(cms);
	ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attr, 0);
	CHECK(X509_ATTRIBUTE_set1_data(
	    attr,
	    V_ASN1_SEQUENCE,
	    ASN1_STRING_get0_data(value->value.sequence),
	    ASN1_STRING_length(value->value.sequence)
	));
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TIMESTAMP,
	        LIBSSIG_ERROR_FORMAT,
	        true,
	        false
	    ) == 0
	);
	CMS_ContentInfo_free(cms);

	cms = decode(original);
	CHECK(cms);
	timestamp_delete(cms);
	CHECK(CMS_unsigned_add1_attr_by_NID(
	    signer_get(cms),
	    NID_id_smime_aa_timeStampToken,
	    V_ASN1_OCTET_STRING,
	    "invalid",
	    7
	));
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TIMESTAMP,
	        LIBSSIG_ERROR_FORMAT,
	        true,
	        false
	    ) == 0
	);
	CMS_ContentInfo_free(cms);

	cms = decode(original);
	CHECK(cms);
	timestamp_delete(cms);
	const unsigned char empty_sequence[] = {0x30, 0};
	CHECK(CMS_unsigned_add1_attr_by_NID(
	    signer_get(cms),
	    NID_id_smime_aa_timeStampToken,
	    V_ASN1_SEQUENCE,
	    empty_sequence,
	    sizeof(empty_sequence)
	));
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TIMESTAMP,
	        LIBSSIG_ERROR_FORMAT,
	        true,
	        false
	    ) == 0
	);
	CMS_ContentInfo_free(cms);
	return 0;
}

static int tampered_check(void) {
	CMS_ContentInfo* cms = decode(original);
	CHECK(cms);
	ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(timestamp_get(cms), 0);
	const unsigned char* cursor = ASN1_STRING_get0_data(value->value.sequence);
	CMS_ContentInfo*     token = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        ASN1_STRING_length(value->value.sequence)
    );
	CHECK(token);
	ASN1_OCTET_STRING* signature = CMS_SignerInfo_get0_signature(
	    signer_get(token)
	);
	unsigned char* bytes = (unsigned char*)ASN1_STRING_get0_data(signature);
	bytes[0] ^= 1;
	unsigned char* encoded = NULL;
	int            len = i2d_CMS_ContentInfo(token, &encoded);
	CHECK(len > 0);
	timestamp_delete(cms);
	CHECK(CMS_unsigned_add1_attr_by_NID(
	    signer_get(cms),
	    NID_id_smime_aa_timeStampToken,
	    V_ASN1_SEQUENCE,
	    encoded,
	    len
	));
	libssig_verify_params params = {0};
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TIMESTAMP,
	        LIBSSIG_ERROR_VERIFY,
	        true,
	        false
	    ) == 0
	);
	OPENSSL_free(encoded);
	CMS_ContentInfo_free(token);
	CMS_ContentInfo_free(cms);
	return 0;
}

static int transplanted_check(void) {
	buffer other = file_read("timestamped-other.p7m");
	CHECK(other.data);
	CMS_ContentInfo* cms = decode(original);
	CMS_ContentInfo* source = decode(other);
	CHECK(cms && source);
	timestamp_delete(cms);
	CHECK(CMS_unsigned_add1_attr(signer_get(cms), timestamp_get(source)));
	libssig_verify_params params = {0};
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TIMESTAMP,
	        LIBSSIG_ERROR_VERIFY,
	        true,
	        false
	    ) == 0
	);
	CMS_ContentInfo_free(source);
	CMS_ContentInfo_free(cms);
	free(other.data);
	return 0;
}

static int expired_check(void) {
	buffer bytes = file_read("timestamp-expired.p7m");
	CHECK(bytes.data);
	CMS_ContentInfo* cms = decode(bytes);
	CHECK(cms);
	libssig_verify_params params = {0};
	CHECK(verify_check(cms, params, LIBSSIG_OK, LIBSSIG_OK, true, true) == 0);
	params.tsa_ca_data = roots.data;
	params.tsa_ca_data_len = roots.len;
	CHECK(
	    verify_check(
	        cms,
	        params,
	        LIBSSIG_ERROR_TRUST,
	        LIBSSIG_ERROR_TRUST,
	        true,
	        true
	    ) == 0
	);
	CMS_ContentInfo_free(cms);
	free(bytes.data);
	return 0;
}

static int mixed_signers_check(void) {
	CMS_ContentInfo* cms = decode(original);
	EVP_PKEY*        key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	X509*            cert = X509_new();
	CHECK(cms && key && cert);
	CHECK(X509_set_version(cert, 2));
	CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), 42));
	CHECK(X509_gmtime_adj(X509_getm_notBefore(cert), -60));
	CHECK(X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
	CHECK(X509_NAME_add_entry_by_txt(
	    X509_get_subject_name(cert),
	    "CN",
	    MBSTRING_ASC,
	    (const unsigned char*)"Second signer",
	    -1,
	    -1,
	    0
	));
	CHECK(X509_set_issuer_name(cert, X509_get_subject_name(cert)));
	CHECK(X509_set_pubkey(cert, key) && X509_sign(cert, key, EVP_sha256()));
	CHECK(CMS_add1_signer(cms, cert, key, EVP_sha256(), CMS_REUSE_DIGEST));
	unsigned char* encoded = NULL;
	int            len = i2d_CMS_ContentInfo(cms, &encoded);
	CHECK(len > 0);
	libssig_verify_params params = {
	    .data = encoded,
	    .data_len = (size_t)len,
	    .tsa_ca_data = roots.data,
	    .tsa_ca_data_len = roots.len,
	};
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_OK);
	CHECK(result.signature_valid && result.count == 2);
	libssig_verify_free(&result);
	params.options = LIBSSIG_VERIFY_REQUIRE_TIMESTAMP;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_TIMESTAMP);
	CHECK(result.signature_valid && result.count == 2);
	size_t stamped = 0;
	for (size_t i = 0; i < result.count; ++i) {
		if (result.signers[i].timestamp.present) {
			CHECK(
			    result.signers[i].timestamp.valid &&
			    result.signers[i].timestamp.trusted
			);
			++stamped;
		} else {
			CHECK(
			    result.signers[i].timestamp.status == LIBSSIG_ERROR_NOT_FOUND
			);
		}
	}
	CHECK(stamped == 1);
	libssig_verify_free(&result);
	OPENSSL_free(encoded);
	X509_free(cert);
	EVP_PKEY_free(key);
	CMS_ContentInfo_free(cms);
	return 0;
}

static int invalid_params_check(void) {
	libssig_verify_params params = {
	    .data = original.data,
	    .data_len = original.len
	};
	libssig_verify_result result = {0};
	params.tsa_ca_data_len = 1;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	params.tsa_ca_data_len = 0;
	params.tsa_intermediates_data = roots.data;
	params.tsa_intermediates_data_len = roots.len;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	params.tsa_ca_data = (const unsigned char*)"invalid";
	params.tsa_ca_data_len = 7;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_FORMAT);
	CHECK(!result.signature_valid && !result.signers);
	return 0;
}

int main(int argc, char** argv) {
	CHECK(argc == 2);
	directory = argv[1];
	original = file_read("timestamped.p7m");
	roots = file_read("tsa-root.pem");
	signer_cert = file_read("cades-0-0.pem");
	CHECK(original.data && roots.data && signer_cert.data);
	CHECK(trust_check() == 0);
	CHECK(missing_check() == 0);
	CHECK(malformed_check() == 0);
	CHECK(tampered_check() == 0);
	CHECK(transplanted_check() == 0);
	CHECK(invalid_params_check() == 0);
	CHECK(expired_check() == 0);
	CHECK(mixed_signers_check() == 0);
	free(original.data);
	free(roots.data);
	free(signer_cert.data);
	return 0;
}
