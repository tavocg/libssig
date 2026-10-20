/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <libssig/libssig.h>
#include <limits.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
static EVP_PKEY *         issuer_key, *leaf_key, *responder_key, *other_key;
static X509 *             issuer, *leaf, *responder, *unauthorized, *other;
static buffer             issuer_pem, leaf_pem, responder_pem, other_pem;
static libssig_ocsp_query query;
static const char*        directory;

static bool extension_add(X509* cert, int nid, const char* value) {
	X509_EXTENSION* item = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	bool            ok = item && X509_add_ext(cert, item, -1);
	X509_EXTENSION_free(item);
	return ok;
}

static X509* certificate_create(
    EVP_PKEY*   key,
    long        serial,
    const char* name,
    bool        ca,
    const char* eku
) {
	X509* cert = X509_new();
	if (!cert) {
		return NULL;
	}
	bool ok = X509_set_version(cert, 2) &&
	          ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) &&
	          X509_gmtime_adj(X509_getm_notBefore(cert), -3600) &&
	          X509_gmtime_adj(X509_getm_notAfter(cert), 86400) &&
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
	              X509_get_subject_name(ca ? cert : issuer)
	          ) &&
	          X509_set_pubkey(cert, key) &&
	          extension_add(
	              cert,
	              NID_basic_constraints,
	              ca ? "critical,CA:TRUE" : "critical,CA:FALSE"
	          ) &&
	          extension_add(
	              cert,
	              NID_key_usage,
	              ca ? "critical,digitalSignature,keyCertSign,cRLSign"
	                 : "critical,digitalSignature"
	          ) &&
	          (!eku || extension_add(cert, NID_ext_key_usage, eku)) &&
	          (ca || extension_add(
	                     cert,
	                     NID_info_access,
	                     "OCSP;URI:http://ocsp.example/status,OCSP;URI:https://"
	                     "backup.example/status"
	                 )) &&
	          X509_sign(cert, ca ? key : issuer_key, EVP_sha256());
	if (!ok) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static buffer cert_encode(X509* cert) {
	buffer bytes = {0};
	BIO*   pem = BIO_new(BIO_s_mem());
	if (pem && PEM_write_bio_X509(pem, cert)) {
		char* data = NULL;
		long  len = BIO_get_mem_data(pem, &data);
		if (len > 0) {
			bytes.data = malloc((size_t)len);
			if (bytes.data) {
				memcpy(bytes.data, data, (size_t)len);
				bytes.len = (size_t)len;
			}
		}
	}
	BIO_free(pem);
	return bytes;
}

static buffer response_create(
    const libssig_ocsp_query* request_bytes,
    X509*                     signer,
    EVP_PKEY*                 key,
    int                       status,
    bool                      nonce,
    long                      current_offset,
    long                      next_offset,
    bool                      duplicate
) {
	const unsigned char* cursor = request_bytes->data;
	OCSP_REQUEST*        request = d2i_OCSP_REQUEST(
        NULL,
        &cursor,
        (long)request_bytes->len
    );
	OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
	ASN1_TIME*      current = X509_gmtime_adj(NULL, current_offset);
	ASN1_TIME*   next = next_offset ? X509_gmtime_adj(NULL, next_offset) : NULL;
	ASN1_TIME*   revoked = status == V_OCSP_CERTSTATUS_REVOKED
	                           ? X509_gmtime_adj(NULL, -120)
	                           : NULL;
	OCSP_CERTID* id = request ? OCSP_onereq_get0_id(
	                                OCSP_request_onereq_get0(request, 0)
	                            )
	                          : NULL;
	bool         ok = request && basic && current && id &&
	          OCSP_basic_add1_status(
	              basic,
	              id,
	              status,
	              OCSP_REVOKED_STATUS_KEYCOMPROMISE,
	              revoked,
	              current,
	              next
	          ) &&
	          (!duplicate || OCSP_basic_add1_status(
	                             basic,
	                             id,
	                             status,
	                             0,
	                             revoked,
	                             current,
	                             next
	                         )) &&
	          (!nonce || OCSP_copy_nonce(basic, request)) &&
	          OCSP_basic_sign(basic, signer, key, EVP_sha256(), NULL, 0);
	OCSP_RESPONSE* response = ok ? OCSP_response_create(
	                                   OCSP_RESPONSE_STATUS_SUCCESSFUL,
	                                   basic
	                               )
	                             : NULL;
	buffer         output = {0};
	int len = response ? i2d_OCSP_RESPONSE(response, &output.data) : -1;
	if (len > 0) {
		output.len = (size_t)len;
	}
	OCSP_RESPONSE_free(response);
	OCSP_BASICRESP_free(basic);
	OCSP_REQUEST_free(request);
	ASN1_TIME_free(current);
	ASN1_TIME_free(next);
	ASN1_TIME_free(revoked);
	return output;
}

static libssig_ocsp_verify_params params_create(buffer response) {
	return (libssig_ocsp_verify_params){
	    .cert_data = leaf_pem.data,
	    .cert_data_len = leaf_pem.len,
	    .issuer_data = issuer_pem.data,
	    .issuer_data_len = issuer_pem.len,
	    .request = query.data,
	    .request_len = query.len,
	    .response = response.data,
	    .response_len = response.len,
	    .ca_data = issuer_pem.data,
	    .ca_data_len = issuer_pem.len,
	};
}

static int verify_check(
    libssig_ocsp_verify_params params,
    libssig_status             expected,
    libssig_ocsp_status        state
) {
	libssig_ocsp_result result = {0};
	libssig_status      status = libssig_ocsp_verify(&params, &result);
	if (status != expected) {
		fprintf(stderr, "Expected %d got %d\n", expected, status);
	}
	CHECK(
	    status == expected && result.error == expected && result.status == state
	);
	CHECK(result.valid == (status == LIBSSIG_OK));
	if (result.valid) {
		CHECK(
		    strlen(result.produced_at) == 20 && strlen(result.this_update) == 20
		);
		CHECK(result.response_status == OCSP_RESPONSE_STATUS_SUCCESSFUL);
		if (state == LIBSSIG_OCSP_REVOKED) {
			CHECK(
			    result.reason == OCSP_REVOKED_STATUS_KEYCOMPROMISE &&
			    strlen(result.revocation_time) == 20
			);
		}
	} else {
		CHECK(
		    !result.produced_at[0] && !result.this_update[0] &&
		    !result.next_update[0] && !result.revocation_time[0]
		);
	}
	return 0;
}

static int fixtures_write(const char* name, buffer bytes) {
	if (!directory) {
		return 0;
	}
	char path[4096];
	int  len = snprintf(path, sizeof(path), "%s/%s", directory, name);
	CHECK(len > 0 && (size_t)len < sizeof(path));
	FILE* file = fopen(path, "wb");
	CHECK(
	    file && fwrite(bytes.data, 1, bytes.len, file) == bytes.len &&
	    fclose(file) == 0
	);
	return 0;
}

static int statuses_check(void) {
	int statuses[] = {
	    V_OCSP_CERTSTATUS_GOOD,
	    V_OCSP_CERTSTATUS_REVOKED,
	    V_OCSP_CERTSTATUS_UNKNOWN
	};
	libssig_ocsp_status states[] =
	    {LIBSSIG_OCSP_GOOD, LIBSSIG_OCSP_REVOKED, LIBSSIG_OCSP_UNKNOWN};
	for (size_t i = 0; i < 3; ++i) {
		buffer response = response_create(
		    &query,
		    responder,
		    responder_key,
		    statuses[i],
		    true,
		    -60,
		    3600,
		    false
		);
		CHECK(
		    response.data &&
		    verify_check(params_create(response), LIBSSIG_OK, states[i]) == 0
		);
		if (!i) {
			CHECK(fixtures_write("response.der", response) == 0);
		}
		OPENSSL_free(response.data);
	}
	buffer direct = response_create(
	    &query,
	    issuer,
	    issuer_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(
	    direct.data &&
	    verify_check(params_create(direct), LIBSSIG_OK, LIBSSIG_OCSP_GOOD) == 0
	);
	OPENSSL_free(direct.data);
	return 0;
}

static int nonce_check(void) {
	buffer response = response_create(
	    &query,
	    responder,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    false,
	    -60,
	    3600,
	    false
	);
	CHECK(response.data);
	libssig_ocsp_verify_params params = params_create(response);
	CHECK(verify_check(params, LIBSSIG_ERROR_VERIFY, LIBSSIG_OCSP_FAILED) == 0);
	params.options = LIBSSIG_OCSP_ALLOW_MISSING_NONCE;
	CHECK(verify_check(params, LIBSSIG_OK, LIBSSIG_OCSP_GOOD) == 0);
	OPENSSL_free(response.data);
	response = response_create(
	    &query,
	    responder,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(response.data);
	params = params_create(response);
	libssig_ocsp_request_params request =
	    {leaf_pem.data, leaf_pem.len, issuer_pem.data, issuer_pem.len};
	libssig_ocsp_query second = {0};
	CHECK(libssig_ocsp_request(&request, &second) == LIBSSIG_OK);
	params.request = second.data;
	params.request_len = second.len;
	CHECK(verify_check(params, LIBSSIG_ERROR_VERIFY, LIBSSIG_OCSP_FAILED) == 0);
	params.options = LIBSSIG_OCSP_ALLOW_MISSING_NONCE;
	CHECK(verify_check(params, LIBSSIG_ERROR_VERIFY, LIBSSIG_OCSP_FAILED) == 0);
	libssig_ocsp_request_free(&second);
	OPENSSL_free(response.data);
	return 0;
}

static int freshness_check(void) {
	const long offsets[][2] =
	    {{-7200, -3600}, {-172800, 3600}, {3600, 7200}, {-60, 0}};
	for (size_t i = 0; i < 4; ++i) {
		buffer response = response_create(
		    &query,
		    responder,
		    responder_key,
		    V_OCSP_CERTSTATUS_GOOD,
		    true,
		    offsets[i][0],
		    offsets[i][1],
		    false
		);
		CHECK(response.data);
		libssig_ocsp_verify_params params = params_create(response);
		CHECK(
		    verify_check(
		        params,
		        i == 3 ? LIBSSIG_OK : LIBSSIG_ERROR_VERIFY,
		        i == 3 ? LIBSSIG_OCSP_GOOD : LIBSSIG_OCSP_FAILED
		    ) == 0
		);
		if (i == 1) {
			params.max_age = 3 * 86400;
			CHECK(verify_check(params, LIBSSIG_OK, LIBSSIG_OCSP_GOOD) == 0);
		}
		OPENSSL_free(response.data);
	}
	return 0;
}

static int authentication_check(void) {
	buffer response = response_create(
	    &query,
	    unauthorized,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(
	    response.data && verify_check(
	                         params_create(response),
	                         LIBSSIG_ERROR_VERIFY,
	                         LIBSSIG_OCSP_FAILED
	                     ) == 0
	);
	OPENSSL_free(response.data);
	response = response_create(
	    &query,
	    other,
	    other_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(response.data);
	libssig_ocsp_verify_params params = params_create(response);
	buffer                     bundle = {
	                        .data = malloc(issuer_pem.len + other_pem.len),
	                        .len = issuer_pem.len + other_pem.len
    };
	CHECK(bundle.data);
	memcpy(bundle.data, issuer_pem.data, issuer_pem.len);
	memcpy(bundle.data + issuer_pem.len, other_pem.data, other_pem.len);
	params.ca_data = bundle.data;
	params.ca_data_len = bundle.len;
	CHECK(verify_check(params, LIBSSIG_ERROR_VERIFY, LIBSSIG_OCSP_FAILED) == 0);
	free(bundle.data);
	OPENSSL_free(response.data);

	response = response_create(
	    &query,
	    responder,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(response.data);
	params = params_create(response);
	params.ca_data = other_pem.data;
	params.ca_data_len = other_pem.len;
	CHECK(verify_check(params, LIBSSIG_ERROR_TRUST, LIBSSIG_OCSP_FAILED) == 0);
	const unsigned char* cursor = response.data;
	OCSP_RESPONSE*       decoded = d2i_OCSP_RESPONSE(
        NULL,
        &cursor,
        (long)response.len
    );
	OCSP_BASICRESP* basic = OCSP_response_get1_basic(decoded);
	CHECK(basic);
	ASN1_OCTET_STRING* signature = (ASN1_OCTET_STRING*)OCSP_resp_get0_signature(
	    basic
	);
	((unsigned char*)ASN1_STRING_get0_data(signature))[0] ^= 1;
	OCSP_RESPONSE* tampered = OCSP_response_create(
	    OCSP_RESPONSE_STATUS_SUCCESSFUL,
	    basic
	);
	CHECK(tampered);
	buffer altered = {0};
	int    len = i2d_OCSP_RESPONSE(tampered, &altered.data);
	CHECK(len > 0);
	altered.len = (size_t)len;
	CHECK(
	    verify_check(
	        params_create(altered),
	        LIBSSIG_ERROR_VERIFY,
	        LIBSSIG_OCSP_FAILED
	    ) == 0
	);
	OPENSSL_free(altered.data);
	OPENSSL_free(response.data);
	OCSP_RESPONSE_free(tampered);
	OCSP_BASICRESP_free(basic);
	OCSP_RESPONSE_free(decoded);
	return 0;
}

static int malformed_check(void) {
	buffer response = response_create(
	    &query,
	    responder,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    true
	);
	CHECK(
	    response.data && verify_check(
	                         params_create(response),
	                         LIBSSIG_ERROR_AMBIGUOUS,
	                         LIBSSIG_OCSP_FAILED
	                     ) == 0
	);
	OPENSSL_free(response.data);
	response = response_create(
	    &query,
	    responder,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(response.data);
	libssig_ocsp_verify_params params = params_create(response);
	params.response_len--;
	CHECK(verify_check(params, LIBSSIG_ERROR_FORMAT, LIBSSIG_OCSP_FAILED) == 0);
	params = params_create(response);
	params.request_len--;
	CHECK(verify_check(params, LIBSSIG_ERROR_FORMAT, LIBSSIG_OCSP_FAILED) == 0);
	params = params_create(response);
	params.ca_data = NULL;
	params.ca_data_len = 0;
	CHECK(
	    verify_check(params, LIBSSIG_ERROR_ARGUMENT, LIBSSIG_OCSP_FAILED) == 0
	);
	params = params_create(response);
	params.cert_data = responder_pem.data;
	params.cert_data_len = responder_pem.len;
	CHECK(verify_check(params, LIBSSIG_ERROR_VERIFY, LIBSSIG_OCSP_FAILED) == 0);
	OPENSSL_free(response.data);
	OCSP_RESPONSE* failed = OCSP_response_create(
	    OCSP_RESPONSE_STATUS_TRYLATER,
	    NULL
	);
	CHECK(failed);
	response = (buffer){0};
	int len = i2d_OCSP_RESPONSE(failed, &response.data);
	CHECK(len > 0);
	response.len = (size_t)len;
	CHECK(
	    verify_check(
	        params_create(response),
	        LIBSSIG_ERROR_OCSP,
	        LIBSSIG_OCSP_FAILED
	    ) == 0
	);
	OPENSSL_free(response.data);
	OCSP_RESPONSE_free(failed);
	return 0;
}

static int invalid_inputs_check(void) {
	libssig_ocsp_result result = {0};
	CHECK(libssig_ocsp_verify(NULL, &result) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(
	    result.error == LIBSSIG_ERROR_ARGUMENT &&
	    result.status == LIBSSIG_OCSP_FAILED
	);
	CHECK(libssig_ocsp_verify(NULL, NULL) == LIBSSIG_ERROR_ARGUMENT);
	libssig_ocsp_query unused = {0};
	CHECK(libssig_ocsp_request(NULL, &unused) == LIBSSIG_ERROR_ARGUMENT);
	libssig_ocsp_request_params request =
	    {leaf_pem.data, leaf_pem.len, other_pem.data, other_pem.len};
	CHECK(libssig_ocsp_request(&request, &unused) == LIBSSIG_ERROR_VERIFY);
	CHECK(!unused.data && !unused.urls.items && !unused.urls.count);
	request = (libssig_ocsp_request_params){issuer_pem.data,
	                                        issuer_pem.len,
	                                        issuer_pem.data,
	                                        issuer_pem.len};
	CHECK(libssig_ocsp_request(&request, &unused) == LIBSSIG_OK);
	CHECK(!unused.urls.count && unused.data && unused.len);
	libssig_ocsp_request_free(&unused);
	buffer response = response_create(
	    &query,
	    responder,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(response.data);
	libssig_ocsp_verify_params params = params_create(response);
	params.options = 0x80000000u;
	CHECK(
	    verify_check(params, LIBSSIG_ERROR_ARGUMENT, LIBSSIG_OCSP_FAILED) == 0
	);
	params = params_create(response);
	params.max_age = LONG_MAX;
	params.clock_skew = LONG_MAX;
	CHECK(verify_check(params, LIBSSIG_OK, LIBSSIG_OCSP_GOOD) == 0);
	OPENSSL_free(response.data);
	return 0;
}

static int system_trust_check(void) {
	char path[] = "/tmp/libssig-ocsp-ca-XXXXXX";
	int  fd = mkstemp(path);
	CHECK(fd >= 0);
	FILE* file = fdopen(fd, "wb");
	CHECK(
	    file &&
	    fwrite(issuer_pem.data, 1, issuer_pem.len, file) == issuer_pem.len &&
	    fclose(file) == 0
	);
	CHECK(setenv("SSL_CERT_FILE", path, 1) == 0);
	CHECK(setenv("SSL_CERT_DIR", "/nonexistent-libssig-ca-dir", 1) == 0);
	buffer response = response_create(
	    &query,
	    responder,
	    responder_key,
	    V_OCSP_CERTSTATUS_GOOD,
	    true,
	    -60,
	    3600,
	    false
	);
	CHECK(response.data);
	libssig_ocsp_verify_params params = params_create(response);
	params.ca_data = NULL;
	params.ca_data_len = 0;
	params.options = LIBSSIG_OCSP_SYSTEM_TRUST;
	CHECK(verify_check(params, LIBSSIG_OK, LIBSSIG_OCSP_GOOD) == 0);
	OPENSSL_free(response.data);
	CHECK(unlink(path) == 0);
	return 0;
}

static int integration_check(void) {
	BIO*             input = BIO_new_mem_buf("Document", 8);
	CMS_ContentInfo* cms = CMS_sign(leaf, leaf_key, NULL, input, CMS_BINARY);
	CHECK(cms);
	unsigned char* encoded = NULL;
	int            len = i2d_CMS_ContentInfo(cms, &encoded);
	CHECK(len > 0);
	libssig_ocsp_evidence evidence = {
	    .issuer_data = issuer_pem.data,
	    .issuer_data_len = issuer_pem.len,
	    .request = query.data,
	    .request_len = query.len,
	};
	libssig_verify_params params = {
	    .data = encoded,
	    .data_len = (size_t)len,
	    .ca_data = issuer_pem.data,
	    .ca_data_len = issuer_pem.len,
	    .ocsp = &evidence,
	    .ocsp_count = 1,
	    .options = LIBSSIG_VERIFY_REQUIRE_OCSP,
	};
	for (int i = 0; i < 3; ++i) {
		buffer response = response_create(
		    &query,
		    responder,
		    responder_key,
		    i,
		    true,
		    -60,
		    3600,
		    false
		);
		CHECK(response.data);
		evidence.response = response.data;
		evidence.response_len = response.len;
		libssig_verify_result result = {0};
		libssig_status expected = i == V_OCSP_CERTSTATUS_GOOD ? LIBSSIG_OK
		                          : i == V_OCSP_CERTSTATUS_REVOKED
		                              ? LIBSSIG_ERROR_REVOKED
		                              : LIBSSIG_ERROR_OCSP;
		CHECK(libssig_verify(&params, &result) == expected);
		CHECK(
		    result.signature_valid && result.trusted &&
		    result.signers[0].ocsp.valid
		);
		CHECK(
		    result.signers[0].ocsp.status == (i == 0   ? LIBSSIG_OCSP_GOOD
		                                      : i == 1 ? LIBSSIG_OCSP_REVOKED
		                                               : LIBSSIG_OCSP_UNKNOWN)
		);
		libssig_verify_free(&result);
		OPENSSL_free(response.data);
	}
	evidence.response = NULL;
	evidence.response_len = 0;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_OCSP);
	CHECK(
	    result.signature_valid &&
	    result.signers[0].ocsp.status == LIBSSIG_OCSP_FAILED
	);
	libssig_verify_free(&result);
	params.ocsp_count = 0;
	params.ocsp = NULL;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_OCSP);
	CHECK(
	    result.signature_valid &&
	    result.signers[0].ocsp.error == LIBSSIG_ERROR_NOT_FOUND
	);
	libssig_verify_free(&result);
	libssig_ocsp_evidence duplicate[] = {evidence, evidence};
	params.ocsp = duplicate;
	params.ocsp_count = 2;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(!result.signers && !result.signature_valid);
	params.ocsp = &evidence;
	params.ocsp_count = 1;
	evidence.signer_index = 99;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(!result.signers && !result.signature_valid);
	evidence.signer_index = 0;
	params.ocsp = NULL;
	params.ocsp_count = 0;
	params.options = LIBSSIG_VERIFY_REQUIRE_TSA_OCSP;
	params.tsa_ca_data = issuer_pem.data;
	params.tsa_ca_data_len = issuer_pem.len;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_OCSP);
	CHECK(result.signature_valid && !result.signers[0].timestamp.present);
	libssig_verify_free(&result);
	CHECK(fixtures_write("document.p7m", (buffer){encoded, (size_t)len}) == 0);
	OPENSSL_free(encoded);
	CMS_ContentInfo_free(cms);
	BIO_free(input);
	return 0;
}

int main(int argc, char** argv) {
	CHECK(argc <= 2);
	directory = argc == 2 ? argv[1] : NULL;
	issuer_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	leaf_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	responder_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	other_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	CHECK(issuer_key && leaf_key && responder_key && other_key);
	issuer = certificate_create(issuer_key, 1, "Issuer", true, NULL);
	CHECK(issuer);
	leaf = certificate_create(leaf_key, 2, "Signer", false, NULL);
	responder = certificate_create(
	    responder_key,
	    3,
	    "OCSP responder",
	    false,
	    "OCSPSigning"
	);
	unauthorized = certificate_create(
	    responder_key,
	    4,
	    "Unauthorized",
	    false,
	    "clientAuth"
	);
	other = certificate_create(other_key, 5, "Unrelated issuer", true, NULL);
	CHECK(leaf && responder && unauthorized && other);
	issuer_pem = cert_encode(issuer);
	leaf_pem = cert_encode(leaf);
	responder_pem = cert_encode(responder);
	other_pem = cert_encode(other);
	CHECK(
	    issuer_pem.data && leaf_pem.data && responder_pem.data && other_pem.data
	);
	libssig_ocsp_request_params params =
	    {leaf_pem.data, leaf_pem.len, issuer_pem.data, issuer_pem.len};
	CHECK(libssig_ocsp_request(&params, &query) == LIBSSIG_OK);
	CHECK(query.data && query.len && query.urls.count == 2);
	CHECK(!strcmp(query.urls.items[0], "http://ocsp.example/status"));
	CHECK(!strcmp(query.urls.items[1], "https://backup.example/status"));
	CHECK(statuses_check() == 0);
	CHECK(nonce_check() == 0);
	CHECK(freshness_check() == 0);
	CHECK(authentication_check() == 0);
	CHECK(malformed_check() == 0);
	CHECK(integration_check() == 0);
	CHECK(system_trust_check() == 0);
	CHECK(invalid_inputs_check() == 0);
	CHECK(fixtures_write("request.der", (buffer){query.data, query.len}) == 0);
	CHECK(fixtures_write("issuer.pem", issuer_pem) == 0);
	CHECK(fixtures_write("cert.pem", leaf_pem) == 0);
	CHECK(fixtures_write("other.pem", other_pem) == 0);
	libssig_ocsp_request_free(&query);
	libssig_ocsp_request_free(&query);
	libssig_ocsp_request_free(NULL);
	free(issuer_pem.data);
	free(leaf_pem.data);
	free(responder_pem.data);
	free(other_pem.data);
	X509_free(issuer);
	X509_free(leaf);
	X509_free(responder);
	X509_free(unauthorized);
	X509_free(other);
	EVP_PKEY_free(issuer_key);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(responder_key);
	EVP_PKEY_free(other_key);
	return 0;
}
