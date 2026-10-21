/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <libssig/libssig.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
static const char* directory;
static EVP_PKEY*   root_key;
static EVP_PKEY*   tsa_key;
static X509*       root;
static X509*       tsa;
static buffer      roots;

static buffer file_read(const char* name) {
	char path[4096];
	snprintf(path, sizeof(path), "%s/%s", directory, name);
	BIO*   input = BIO_new_file(path, "rb");
	BIO*   memory = BIO_new(BIO_s_mem());
	buffer bytes = {0};
	char   chunk[4096];
	int    len;
	while (input && memory &&
	       (len = BIO_read(input, chunk, sizeof(chunk))) > 0) {
		BIO_write(memory, chunk, len);
	}
	if (input && memory) {
		char* data = NULL;
		long  size = BIO_get_mem_data(memory, &data);
		if (size > 0) {
			bytes.data = malloc((size_t)size);
			if (bytes.data) {
				memcpy(bytes.data, data, (size_t)size);
				bytes.len = (size_t)size;
			}
		}
	}
	BIO_free(input);
	BIO_free(memory);
	return bytes;
}

static int file_write(const char* name, const unsigned char* data, size_t len) {
	char path[4096];
	int  count = snprintf(path, sizeof(path), "%s/%s", directory, name);
	CHECK(count > 0 && (size_t)count < sizeof(path));
	FILE* file = fopen(path, "wb");
	CHECK(file && fwrite(data, 1, len, file) == len && fclose(file) == 0);
	return 0;
}

static bool extension_add(X509* cert, int nid, const char* value) {
	X509_EXTENSION* extension = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	bool            ok = extension && X509_add_ext(cert, extension, -1);
	X509_EXTENSION_free(extension);
	return ok;
}

static X509* certificate_create(EVP_PKEY* key, bool authority) {
	X509* cert = X509_new();
	if (!cert) {
		return NULL;
	}
	bool ok = X509_set_version(cert, 2) &&
	          ASN1_INTEGER_set(
	              X509_get_serialNumber(cert),
	              authority ? 1 : 2
	          ) &&
	          X509_gmtime_adj(X509_getm_notBefore(cert), -3600) &&
	          X509_gmtime_adj(X509_getm_notAfter(cert), 86400) &&
	          X509_NAME_add_entry_by_txt(
	              X509_get_subject_name(cert),
	              "CN",
	              MBSTRING_ASC,
	              (const unsigned char*)(authority ? "Test TSA root"
	                                               : "Test TSA"),
	              -1,
	              -1,
	              0
	          ) &&
	          X509_set_issuer_name(
	              cert,
	              X509_get_subject_name(authority ? cert : root)
	          ) &&
	          X509_set_pubkey(cert, key) &&
	          extension_add(
	              cert,
	              NID_basic_constraints,
	              authority ? "critical,CA:TRUE" : "critical,CA:FALSE"
	          ) &&
	          extension_add(
	              cert,
	              NID_key_usage,
	              authority ? "critical,keyCertSign,cRLSign"
	                        : "critical,digitalSignature"
	          ) &&
	          (authority || extension_add(
	                            cert,
	                            NID_ext_key_usage,
	                            "critical,timeStamping"
	                        )) &&
	          X509_sign(cert, authority ? key : root_key, EVP_sha256());
	if (!ok) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static int future_time(TS_RESP_CTX* ctx, void* data, long* sec, long* usec) {
	(void)ctx;
	(void)data;
	*sec = (long)time(NULL) + 3600;
	*usec = 0;
	return 1;
}

static TS_RESP* response_create(const libssig_signature* request, bool future) {
	TS_RESP_CTX* ctx = TS_RESP_CTX_new();
	ASN1_OBJECT* policy = OBJ_txt2obj("1.2.3.4.1", 1);
	BIO*         query = BIO_new_mem_buf(request->data, (int)request->len);
	bool ok = ctx && policy && query && TS_RESP_CTX_set_signer_cert(ctx, tsa) &&
	          TS_RESP_CTX_set_signer_key(ctx, tsa_key) &&
	          TS_RESP_CTX_set_signer_digest(ctx, EVP_sha256()) &&
	          TS_RESP_CTX_set_ess_cert_id_digest(ctx, EVP_sha256()) &&
	          TS_RESP_CTX_set_def_policy(ctx, policy) &&
	          TS_RESP_CTX_add_md(ctx, EVP_sha256()) &&
	          TS_RESP_CTX_add_md(ctx, EVP_sha384()) &&
	          TS_RESP_CTX_add_md(ctx, EVP_sha512());
	if (ok && future) {
		TS_RESP_CTX_set_time_cb(ctx, future_time, NULL);
	}
	TS_RESP* response = ok ? TS_RESP_create_response(ctx, query) : NULL;
	BIO_free(query);
	ASN1_OBJECT_free(policy);
	TS_RESP_CTX_free(ctx);
	return response;
}

static buffer response_encode(TS_RESP* response) {
	buffer output = {0};
	int    len = i2d_TS_RESP(response, &output.data);
	if (len > 0) {
		output.len = (size_t)len;
	}
	return output;
}

static int apply_check(
    libssig_timestamp_params params,
    libssig_status           expected
) {
	libssig_signature output = {0};
	libssig_status    status = libssig_timestamp(&params, &output);
	if (status != expected) {
		fprintf(stderr, "Expected %d, got %d\n", expected, status);
	}
	CHECK(status == expected);
	CHECK(!output.data && !output.len && !output.ck_rv);
	libssig_signature_free(&output);
	return 0;
}

static int altered_response_check(
    libssig_timestamp_params params,
    bool                     wrong_usage
) {
	const unsigned char* cursor = params.response;
	TS_RESP* response = d2i_TS_RESP(NULL, &cursor, (long)params.response_len);
	CHECK(response);
	PKCS7* token = TS_RESP_get_token(response);
	if (wrong_usage) {
		X509* bad = X509_dup(tsa);
		CHECK(bad);
		int i = X509_get_ext_by_NID(bad, NID_ext_key_usage, -1);
		CHECK(i >= 0);
		X509_EXTENSION_free(X509_delete_ext(bad, i));
		CHECK(extension_add(bad, NID_ext_key_usage, "critical,clientAuth"));
		CHECK(X509_sign(bad, root_key, EVP_sha256()));
		X509* original = sk_X509_value(token->d.sign->cert, 0);
		CHECK(sk_X509_set(token->d.sign->cert, 0, bad));
		X509_free(original);
	} else {
		PKCS7_SIGNER_INFO* signer = sk_PKCS7_SIGNER_INFO_value(
		    PKCS7_get_signer_info(token),
		    0
		);
		CHECK(signer && signer->enc_digest->length);
		signer->enc_digest->data[0] ^= 1;
	}
	buffer altered = response_encode(response);
	CHECK(altered.data);
	params.response = altered.data;
	params.response_len = altered.len;
	CHECK(
	    apply_check(
	        params,
	        wrong_usage ? LIBSSIG_ERROR_TRUST : LIBSSIG_ERROR_VERIFY
	    ) == 0
	);
	OPENSSL_free(altered.data);
	TS_RESP_free(response);
	return 0;
}

static int policy_mismatch_check(libssig_timestamp_params params) {
	const unsigned char* cursor = params.request;
	TS_REQ*      request = d2i_TS_REQ(NULL, &cursor, (long)params.request_len);
	ASN1_OBJECT* policy = OBJ_txt2obj("1.2.3.4.999", 1);
	CHECK(request && policy && TS_REQ_set_policy_id(request, policy));
	unsigned char* encoded = NULL;
	int            len = i2d_TS_REQ(request, &encoded);
	CHECK(len > 0);
	params.request = encoded;
	params.request_len = (size_t)len;
	CHECK(apply_check(params, LIBSSIG_ERROR_VERIFY) == 0);
	OPENSSL_free(encoded);
	ASN1_OBJECT_free(policy);
	TS_REQ_free(request);
	return 0;
}

static int negative_check(
    libssig_timestamp_params         params,
    libssig_timestamp_request_params query
) {
	CHECK(altered_response_check(params, false) == 0);
	CHECK(altered_response_check(params, true) == 0);
	CHECK(policy_mismatch_check(params) == 0);
	buffer other = file_read("attached-cades-0-1.p7m");
	CHECK(other.data);
	libssig_timestamp_params different = params;
	different.data = other.data;
	different.data_len = other.len;
	CHECK(apply_check(different, LIBSSIG_ERROR_VERIFY) == 0);
	free(other.data);

	libssig_signature second = {0};
	CHECK(libssig_timestamp_request(&query, &second) == LIBSSIG_OK);
	CHECK(
	    second.len != params.request_len ||
	    memcmp(second.data, params.request, second.len)
	);
	libssig_timestamp_params mismatch = params;
	mismatch.request = second.data;
	mismatch.request_len = second.len;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_VERIFY) == 0);
	libssig_signature_free(&second);

	mismatch = params;
	mismatch.ca_data = NULL;
	mismatch.ca_data_len = 0;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_ARGUMENT) == 0);
	mismatch = params;
	mismatch.options = 0x80000000u;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_ARGUMENT) == 0);
	mismatch = params;
	mismatch.response_len--;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_FORMAT) == 0);
	mismatch = params;
	mismatch.request_len--;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_FORMAT) == 0);
	mismatch = params;
	mismatch.signer_index = 99;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_ARGUMENT) == 0);
	mismatch = params;
	buffer wrong = file_read("cades-0-0.pem");
	CHECK(wrong.data);
	mismatch.ca_data = wrong.data;
	mismatch.ca_data_len = wrong.len;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_TRUST) == 0);
	free(wrong.data);

	libssig_signature request = {
	    .data = (unsigned char*)params.request,
	    .len = params.request_len
	};
	TS_RESP* response = response_create(&request, true);
	CHECK(response);
	buffer future = response_encode(response);
	CHECK(future.data);
	mismatch = params;
	mismatch.response = future.data;
	mismatch.response_len = future.len;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_VERIFY) == 0);
	OPENSSL_free(future.data);
	TS_RESP_free(response);

	query.policy_oid = "1.2.3.4.999";
	CHECK(libssig_timestamp_request(&query, &second) == LIBSSIG_OK);
	response = response_create(&second, false);
	CHECK(response);
	buffer rejection = response_encode(response);
	CHECK(rejection.data);
	mismatch = params;
	mismatch.request = second.data;
	mismatch.request_len = second.len;
	mismatch.response = rejection.data;
	mismatch.response_len = rejection.len;
	CHECK(apply_check(mismatch, LIBSSIG_ERROR_TIMESTAMP) == 0);
	OPENSSL_free(rejection.data);
	TS_RESP_free(response);
	libssig_signature_free(&second);
	return 0;
}

static int token_check(
    const libssig_signature* output,
    TS_RESP*                 response,
    bool                     detached
) {
	const unsigned char* cursor = output->data;
	CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)output->len
    );
	CHECK(cms && CMS_is_detached(cms) == detached);
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	int i = CMS_unsigned_get_attr_by_NID(
	    signer,
	    NID_id_smime_aa_timeStampToken,
	    -1
	);
	CHECK(
	    i >= 0 && CMS_unsigned_get_attr_by_NID(
	                  signer,
	                  NID_id_smime_aa_timeStampToken,
	                  i
	              ) < 0
	);
	X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(signer, i);
	CHECK(X509_ATTRIBUTE_count(attr) == 1);
	ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attr, 0);
	CHECK(value && value->type == V_ASN1_SEQUENCE);
	unsigned char* token = NULL;
	int            len = i2d_PKCS7(TS_RESP_get_token(response), &token);
	CHECK(len == ASN1_STRING_length(value->value.sequence));
	CHECK(!memcmp(
	    token,
	    ASN1_STRING_get0_data(value->value.sequence),
	    (size_t)len
	));
	OPENSSL_free(token);
	CMS_ContentInfo_free(cms);
	libssig_verify_params verify = {
	    .data = output->data,
	    .data_len = output->len
	};
	const unsigned char content[] = {0, 0xff, 42};
	if (detached) {
		verify.content = content;
		verify.content_len = sizeof(content);
	}
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&verify, &result) == LIBSSIG_OK);
	CHECK(result.signature_valid);
	CHECK(
	    result.signers[0].timestamp.present && result.signers[0].timestamp.valid
	);
	CHECK(
	    !result.signers[0].timestamp.trust_checked &&
	    !result.signers[0].timestamp.trusted
	);
	CHECK(strlen(result.signers[0].timestamp.time) == 20);
	CHECK(result.signers[0].timestamp.cert_der_len > 0);
	libssig_verify_free(&result);
	verify.tsa_ca_data = roots.data;
	verify.tsa_ca_data_len = roots.len;
	verify.options = LIBSSIG_VERIFY_REQUIRE_TIMESTAMP;
	CHECK(libssig_verify(&verify, &result) == LIBSSIG_OK);
	CHECK(
	    result.signers[0].timestamp.trust_checked &&
	    result.signers[0].timestamp.trusted
	);
	CHECK(!result.trust_checked && !result.trusted);
	libssig_verify_free(&result);
	return 0;
}

static int expired_fixture_write(libssig_timestamp_params params) {
	X509* saved = tsa;
	tsa = X509_dup(saved);
	CHECK(tsa && X509_gmtime_adj(X509_getm_notAfter(tsa), -60));
	CHECK(X509_sign(tsa, root_key, EVP_sha256()));
	libssig_signature request = {
	    .data = (unsigned char*)params.request,
	    .len = params.request_len
	};
	TS_RESP* response = response_create(&request, false);
	CHECK(response && TS_RESP_get_token(response));
	X509_free(tsa);
	tsa = saved;
	const unsigned char* cursor = params.data;
	CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)params.data_len
    );
	CHECK(cms);
	unsigned char* token = NULL;
	int            len = i2d_PKCS7(TS_RESP_get_token(response), &token);
	CHECK(len > 0);
	CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(
	    CMS_get0_SignerInfos(cms),
	    0
	);
	CHECK(CMS_unsigned_add1_attr_by_NID(
	    signer,
	    NID_id_smime_aa_timeStampToken,
	    V_ASN1_SEQUENCE,
	    token,
	    len
	));
	OPENSSL_free(token);
	unsigned char* encoded = NULL;
	len = i2d_CMS_ContentInfo(cms, &encoded);
	CHECK(
	    len > 0 &&
	    file_write("timestamp-expired.p7m", encoded, (size_t)len) == 0
	);
	OPENSSL_free(encoded);
	TS_RESP_free(response);
	CMS_ContentInfo_free(cms);
	return 0;
}

static int tsa_ocsp_check(const libssig_signature* signature) {
	unsigned char* cert = NULL;
	int            cert_len = i2d_X509(tsa, &cert);
	CHECK(cert_len > 0);
	libssig_ocsp_request_params request = {
	    .cert_data = cert,
	    .cert_data_len = (size_t)cert_len,
	    .issuer_data = roots.data,
	    .issuer_data_len = roots.len,
	};
	libssig_ocsp_query query = {0};
	CHECK(libssig_ocsp_request(&request, &query) == LIBSSIG_OK);
	const unsigned char* cursor = query.data;
	OCSP_REQUEST* decoded = d2i_OCSP_REQUEST(NULL, &cursor, (long)query.len);
	CHECK(decoded);
	OCSP_CERTID* id = OCSP_onereq_get0_id(OCSP_request_onereq_get0(decoded, 0));
	ASN1_TIME*   current = X509_gmtime_adj(NULL, -60);
	ASN1_TIME*   next = X509_gmtime_adj(NULL, 3600);
	ASN1_TIME*   revoked = X509_gmtime_adj(NULL, -120);
	CHECK(current && next && revoked);
	libssig_ocsp_evidence evidence = {
	    .tsa = true,
	    .issuer_data = roots.data,
	    .issuer_data_len = roots.len,
	    .request = query.data,
	    .request_len = query.len,
	};
	libssig_verify_params params = {
	    .data = signature->data,
	    .data_len = signature->len,
	    .tsa_ca_data = roots.data,
	    .tsa_ca_data_len = roots.len,
	    .ocsp = &evidence,
	    .ocsp_count = 1,
	    .options = LIBSSIG_VERIFY_REQUIRE_TSA_OCSP,
	};
	for (int i = 0; i < 3; ++i) {
		OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
		CHECK(
		    basic && OCSP_basic_add1_status(
		                 basic,
		                 id,
		                 i,
		                 OCSP_REVOKED_STATUS_KEYCOMPROMISE,
		                 i == V_OCSP_CERTSTATUS_REVOKED ? revoked : NULL,
		                 current,
		                 next
		             )
		);
		CHECK(
		    OCSP_copy_nonce(basic, decoded) &&
		    OCSP_basic_sign(basic, root, root_key, EVP_sha256(), NULL, 0)
		);
		OCSP_RESPONSE* response = OCSP_response_create(
		    OCSP_RESPONSE_STATUS_SUCCESSFUL,
		    basic
		);
		CHECK(response);
		unsigned char* encoded = NULL;
		int            len = i2d_OCSP_RESPONSE(response, &encoded);
		CHECK(len > 0);
		evidence.response = encoded;
		evidence.response_len = (size_t)len;
		libssig_verify_result result = {0};
		libssig_status expected = i == V_OCSP_CERTSTATUS_GOOD ? LIBSSIG_OK
		                          : i == V_OCSP_CERTSTATUS_REVOKED
		                              ? LIBSSIG_ERROR_REVOKED
		                              : LIBSSIG_ERROR_OCSP;
		CHECK(libssig_verify(&params, &result) == expected);
		CHECK(
		    result.signature_valid && result.signers[0].timestamp.valid &&
		    result.signers[0].timestamp.trusted
		);
		CHECK(result.signers[0].timestamp.ocsp.valid);
		CHECK(
		    result.signers[0].timestamp.ocsp.status ==
		    (i == 0   ? LIBSSIG_OCSP_GOOD
		     : i == 1 ? LIBSSIG_OCSP_REVOKED
		              : LIBSSIG_OCSP_UNKNOWN)
		);
		libssig_verify_free(&result);
		OPENSSL_free(encoded);
		OCSP_RESPONSE_free(response);
		OCSP_BASICRESP_free(basic);
	}
	params.ocsp = NULL;
	params.ocsp_count = 0;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_OCSP);
	CHECK(
	    result.signature_valid &&
	    result.signers[0].timestamp.ocsp.error == LIBSSIG_ERROR_NOT_FOUND
	);
	libssig_verify_free(&result);
	ASN1_TIME_free(current);
	ASN1_TIME_free(next);
	ASN1_TIME_free(revoked);
	OCSP_REQUEST_free(decoded);
	libssig_ocsp_request_free(&query);
	OPENSSL_free(cert);
	return 0;
}

static int roundtrip_check(int algo, int hash, bool detached) {
	char name[80];
	snprintf(
	    name,
	    sizeof(name),
	    detached ? "cades-%d-%d.p7s" : "attached-cades-%d-%d.p7m",
	    algo,
	    hash
	);
	buffer original = file_read(name);
	CHECK(original.data);
	libssig_timestamp_request_params query = {
	    .data = original.data,
	    .data_len = original.len,
	    .hash = (libssig_hash)hash,
	    .policy_oid = hash == 1 ? NULL : "1.2.3.4.1",
	};
	libssig_signature request = {0};
	CHECK(libssig_timestamp_request(&query, &request) == LIBSSIG_OK);
	CHECK(request.data && request.len && !request.ck_rv);
	TS_RESP* response = response_create(&request, false);
	CHECK(response);
	buffer encoded = response_encode(response);
	CHECK(encoded.data);
	libssig_timestamp_params params = {
	    .data = original.data,
	    .data_len = original.len,
	    .request = request.data,
	    .request_len = request.len,
	    .response = encoded.data,
	    .response_len = encoded.len,
	    .ca_data = roots.data,
	    .ca_data_len = roots.len,
	};
	libssig_signature output = {0};
	CHECK(libssig_timestamp(&params, &output) == LIBSSIG_OK);
	CHECK(token_check(&output, response, detached) == 0);
	libssig_timestamp_request_params duplicate = {
	    .data = output.data,
	    .data_len = output.len
	};
	libssig_signature unused = {0};
	CHECK(
	    libssig_timestamp_request(&duplicate, &unused) ==
	    LIBSSIG_ERROR_AMBIGUOUS
	);
	params.data = output.data;
	params.data_len = output.len;
	CHECK(apply_check(params, LIBSSIG_ERROR_AMBIGUOUS) == 0);
	params.data = original.data;
	params.data_len = original.len;
	if (!algo && !hash && !detached) {
		CHECK(negative_check(params, query) == 0);
		CHECK(expired_fixture_write(params) == 0);
		CHECK(tsa_ocsp_check(&output) == 0);
		char path[4096];
		snprintf(path, sizeof(path), "%s/tsa-root.pem", directory);
		CHECK(setenv("SSL_CERT_FILE", path, 1) == 0);
		CHECK(setenv("SSL_CERT_DIR", "/nonexistent-libssig-tsa-dir", 1) == 0);
		libssig_timestamp_params system = params;
		system.ca_data = NULL;
		system.ca_data_len = 0;
		system.options = LIBSSIG_TIMESTAMP_SYSTEM_TRUST;
		libssig_signature trusted = {0};
		CHECK(libssig_timestamp(&system, &trusted) == LIBSSIG_OK);
		libssig_signature_free(&trusted);
		CHECK(file_write("timestamp.tsq", request.data, request.len) == 0);
		CHECK(file_write("timestamp.tsr", encoded.data, encoded.len) == 0);
		CHECK(file_write("timestamped.p7m", output.data, output.len) == 0);
	}
	if (!algo && hash == 1 && !detached) {
		CHECK(
		    file_write("timestamped-other.p7m", output.data, output.len) == 0
		);
	}
	libssig_signature_free(&output);
	libssig_signature_free(&request);
	TS_RESP_free(response);
	OPENSSL_free(encoded.data);
	free(original.data);
	return 0;
}

static int invalid_check(void) {
	libssig_signature                output = {0};
	libssig_timestamp_request_params query = {0};
	CHECK(libssig_timestamp_request(NULL, &output) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_timestamp_request(&query, NULL) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_timestamp_request(&query, &output) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_timestamp(NULL, &output) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_timestamp(NULL, NULL) == LIBSSIG_ERROR_ARGUMENT);
	buffer original = file_read("attached-cades-0-0.p7m");
	CHECK(original.data);
	query.data = original.data;
	query.data_len = original.len;
	query.hash = (libssig_hash)99;
	CHECK(
	    libssig_timestamp_request(&query, &output) == LIBSSIG_ERROR_UNSUPPORTED
	);
	query.hash = LIBSSIG_HASH_SHA256;
	query.policy_oid = "not-an-oid";
	CHECK(libssig_timestamp_request(&query, &output) == LIBSSIG_ERROR_ARGUMENT);
	free(original.data);
	return 0;
}

int main(int argc, char** argv) {
	/* Nix OpenSSL gives this variable precedence over SSL_CERT_FILE. */
	CHECK(unsetenv("NIX_SSL_CERT_FILE") == 0);
	CHECK(argc == 2);
	directory = argv[1];
	root_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	tsa_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	CHECK(root_key && tsa_key);
	root = certificate_create(root_key, true);
	CHECK(root);
	tsa = certificate_create(tsa_key, false);
	CHECK(tsa);
	BIO* pem = BIO_new(BIO_s_mem());
	CHECK(pem && PEM_write_bio_X509(pem, root));
	char* bytes = NULL;
	long  len = BIO_get_mem_data(pem, &bytes);
	CHECK(len > 0);
	roots.data = (unsigned char*)bytes;
	roots.len = (size_t)len;
	CHECK(file_write("tsa-root.pem", roots.data, roots.len) == 0);
	CHECK(invalid_check() == 0);
	for (int i = 0; i < 3; ++i) {
		for (int j = 0; j < 3; ++j) {
			CHECK(roundtrip_check(i, j, false) == 0);
			CHECK(roundtrip_check(i, j, true) == 0);
		}
	}
	BIO_free(pem);
	X509_free(tsa);
	X509_free(root);
	EVP_PKEY_free(tsa_key);
	EVP_PKEY_free(root_key);
	return 0;
}
