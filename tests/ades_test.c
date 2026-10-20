/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Reuse the local TSA fixture, including its negative tests, without network.
 */
#define main timestamp_fixture_main
#include "timestamp_test.c"
#undef main
#include <libssig/ades_internal.h>

static int  timestamp_calls;
static int  ocsp_calls;
static bool fail_archive;
static bool revoked_reply;

static libssig_status exchange(
    void*                user,
    libssig_fetch_kind   kind,
    const char*          url,
    const unsigned char* bytes,
    size_t               len,
    libssig_signature*   output
) {
	(void)user;
	(void)url;
	if (kind == LIBSSIG_FETCH_TIMESTAMP) {
		++timestamp_calls;
		if (fail_archive && timestamp_calls > 1) {
			return LIBSSIG_ERROR_TIMESTAMP;
		}
		libssig_signature query = {.data = (unsigned char*)bytes, .len = len};
		TS_RESP*          reply = response_create(&query, false);
		buffer encoded = reply ? response_encode(reply) : (buffer){0};
		output->data = encoded.data ? malloc(encoded.len) : NULL;
		if (output->data) {
			memcpy(output->data, encoded.data, encoded.len);
			output->len = encoded.len;
		}
		OPENSSL_free(encoded.data);
		TS_RESP_free(reply);
		return output->data ? LIBSSIG_OK : LIBSSIG_ERROR_CRYPTO;
	}
	if (kind == LIBSSIG_FETCH_CRL) {
		X509_CRL*  crl = X509_CRL_new();
		ASN1_TIME* current = X509_gmtime_adj(NULL, revoked_reply ? 3600 : -60);
		ASN1_TIME* next = X509_gmtime_adj(NULL, 7200);
		bool ok = crl && current && next && X509_CRL_set_version(crl, 1) &&
		          X509_CRL_set_issuer_name(crl, X509_get_subject_name(root)) &&
		          X509_CRL_set1_lastUpdate(crl, current) &&
		          X509_CRL_set1_nextUpdate(crl, next) &&
		          X509_CRL_sign(crl, root_key, EVP_sha256());
		unsigned char* encoded = NULL;
		int            size = ok ? i2d_X509_CRL(crl, &encoded) : 0;
		output->data = size > 0 ? malloc((size_t)size) : NULL;
		if (output->data) {
			memcpy(output->data, encoded, (size_t)size);
			output->len = (size_t)size;
		}
		OPENSSL_free(encoded);
		ASN1_TIME_free(current);
		ASN1_TIME_free(next);
		X509_CRL_free(crl);
		return output->data ? LIBSSIG_OK : LIBSSIG_ERROR_CRYPTO;
	}
	if (kind != LIBSSIG_FETCH_OCSP) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	++ocsp_calls;
	const unsigned char* cursor = bytes;
	OCSP_REQUEST*        query = d2i_OCSP_REQUEST(NULL, &cursor, (long)len);
	OCSP_BASICRESP*      basic = OCSP_BASICRESP_new();
	ASN1_TIME*           current = X509_gmtime_adj(NULL, -60);
	ASN1_TIME*           next = X509_gmtime_adj(NULL, 3600);
	ASN1_TIME*           revoked = X509_gmtime_adj(NULL, -120);
	bool ok = query && basic && OCSP_request_onereq_count(query) == 1 &&
	          OCSP_basic_add1_status(
	              basic,
	              OCSP_onereq_get0_id(OCSP_request_onereq_get0(query, 0)),
	              revoked_reply ? V_OCSP_CERTSTATUS_REVOKED
	                            : V_OCSP_CERTSTATUS_GOOD,
	              OCSP_REVOKED_STATUS_KEYCOMPROMISE,
	              revoked_reply ? revoked : NULL,
	              current,
	              next
	          ) &&
	          OCSP_copy_nonce(basic, query) &&
	          OCSP_basic_sign(basic, root, root_key, EVP_sha256(), NULL, 0);
	OCSP_RESPONSE* reply = ok ? OCSP_response_create(
	                                OCSP_RESPONSE_STATUS_SUCCESSFUL,
	                                basic
	                            )
	                          : NULL;
	unsigned char* encoded = NULL;
	int            size = reply ? i2d_OCSP_RESPONSE(reply, &encoded) : 0;
	output->data = size > 0 ? malloc((size_t)size) : NULL;
	if (output->data) {
		memcpy(output->data, encoded, (size_t)size);
		output->len = (size_t)size;
	}
	OPENSSL_free(encoded);
	OCSP_RESPONSE_free(reply);
	OCSP_BASICRESP_free(basic);
	OCSP_REQUEST_free(query);
	ASN1_TIME_free(current);
	ASN1_TIME_free(next);
	ASN1_TIME_free(revoked);
	return output->data ? LIBSSIG_OK : LIBSSIG_ERROR_CRYPTO;
}
int main(int argc, char** argv) {
	CHECK(argc == 2);
	directory = argv[1];
	root_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	tsa_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	CHECK(root_key && tsa_key);
	root = certificate_create(root_key, true);
	CHECK(root);
	tsa = certificate_create(tsa_key, false);
	CHECK(
	    tsa &&
	    extension_add(tsa, NID_info_access, "OCSP;URI:http://test/ocsp") &&
	    X509_sign(tsa, root_key, EVP_sha256())
	);
	BIO* pem = BIO_new(BIO_s_mem());
	CHECK(pem && PEM_write_bio_X509(pem, root));
	char*  root_bytes = NULL;
	long   root_len = BIO_get_mem_data(pem, &root_bytes);
	buffer original = file_read("attached-cades-0-0.p7m");
	buffer doc_root = file_read("cades-0-0.pem");
	CHECK(original.data && doc_root.data && root_len > 0);
	CHECK(
	    file_write(
	        "ades-tsa-root.pem",
	        (unsigned char*)root_bytes,
	        (size_t)root_len
	    ) == 0
	);
	libssig_verify_params trust = {
	    .ca_data = doc_root.data,
	    .ca_data_len = doc_root.len,
	    .tsa_ca_data = (unsigned char*)root_bytes,
	    .tsa_ca_data_len = (size_t)root_len
	};
	libssig_sign_services services =
	    {.exchange = exchange, .tsa_url = "http://test/tsa", .trust = &trust};
	libssig_extend_params params = {
	    .data = original.data,
	    .data_len = original.len,
	    .services = &services
	};
	libssig_level levels[] = {
	    LIBSSIG_LEVEL_B_B,
	    LIBSSIG_LEVEL_B_T,
	    LIBSSIG_LEVEL_B_LT,
	    LIBSSIG_LEVEL_B_LTA
	};
	for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); ++i) {
		timestamp_calls = ocsp_calls = 0;
		params.level = levels[i];
		libssig_signature output = {0};
		libssig_status    status = libssig_extend(&params, &output);
		if (status != LIBSSIG_OK) {
			fprintf(stderr, "Level %d: status=%d\n", params.level, status);
		}
		CHECK(status == LIBSSIG_OK && output.data);
		CHECK(timestamp_calls == (i == 0 ? 0 : i == 3 ? 2 : 1));
		CHECK((i < 2 && ocsp_calls == 0) || (i >= 2 && ocsp_calls > 0));
		libssig_verify_params verify = trust;
		verify.data = output.data;
		verify.data_len = output.len;
		libssig_verify_result result = {0};
		status = libssig_verify(&verify, &result);
		if (status != LIBSSIG_OK) {
			fprintf(
			    stderr,
			    "Verify level %d: status=%d\n",
			    params.level,
			    status
			);
		}
		CHECK(status == LIBSSIG_OK && result.signature_valid && result.trusted);
		CHECK(result.signers[0].timestamp.present == (i > 0));
		CHECK(result.signers[0].archive.present == (i == 3));
		if (i == 3) {
			CHECK(
			    result.signers[0].archive.valid &&
			    result.signers[0].archive.trusted
			);
		}
		libssig_verify_free(&result);
		if (i == 3) {
			const unsigned char* cursor = output.data;
			libssig_raw_cms*     raw = d2i_libssig_raw_cms(
                NULL,
                &cursor,
                (long)output.len
            );
			CHECK(raw && sk_ASN1_TYPE_num(raw->signed_data->revocations) > 0);
			ASN1_TYPE_free(sk_ASN1_TYPE_pop(raw->signed_data->revocations));
			unsigned char* tampered = NULL;
			int            len = i2d_libssig_raw_cms(raw, &tampered);
			CHECK(len > 0);
			verify.data = tampered;
			verify.data_len = (size_t)len;
			CHECK(libssig_verify(&verify, &result) == LIBSSIG_ERROR_TIMESTAMP);
			CHECK(
			    result.signature_valid && result.signers[0].archive.present &&
			    !result.signers[0].archive.valid
			);
			libssig_verify_free(&result);
			OPENSSL_free(tampered);
			libssig_raw_cms_free(raw);
		}
		char name[64];
		snprintf(name, sizeof(name), "ades-level-%zu.p7m", i);
		CHECK(file_write(name, output.data, output.len) == 0);
		libssig_signature_free(&output);
	}
	buffer pdf = file_read("pades-0-0.pdf");
	CHECK(pdf.data);
	for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); ++i) {
		timestamp_calls = ocsp_calls = 0;
		libssig_extend_params p = params;
		p.data = pdf.data;
		p.data_len = pdf.len;
		p.level = levels[i];
		libssig_signature output = {0};
		libssig_status    status = libssig_extend(&p, &output);
		if (status != LIBSSIG_OK) {
			fprintf(stderr, "PDF level %d: status=%d\n", p.level, status);
		}
		CHECK(status == LIBSSIG_OK && output.data);
		libssig_verify_params verify = trust;
		verify.data = output.data;
		verify.data_len = output.len;
		libssig_verify_result result = {0};
		status = libssig_verify(&verify, &result);
		if (status != LIBSSIG_OK) {
			fprintf(
			    stderr,
			    "PDF verify level %d: status=%d\n",
			    p.level,
			    status
			);
		}
		CHECK(status == LIBSSIG_OK && result.signature_valid && result.trusted);
		CHECK(result.signers[0].timestamp.present == (i > 0));
		CHECK(result.signers[0].archive.present == (i == 3));
		char name[64];
		snprintf(name, sizeof(name), "pades-level-%zu.pdf", i);
		CHECK(file_write(name, output.data, output.len) == 0);
		libssig_verify_free(&result);
		libssig_signature_free(&output);
	}
	free(pdf.data);
	for (int algo = 0; algo < 3; ++algo) {
		for (int hash = 0; hash < 3; ++hash) {
			char name[96];
			snprintf(name, sizeof(name), "cades-%d-%d.pem", algo, hash);
			buffer anchor = file_read(name);
			CHECK(anchor.data);
			trust.ca_data = anchor.data;
			trust.ca_data_len = anchor.len;
			for (int format = 0; format < 3; ++format) {
				snprintf(
				    name,
				    sizeof(name),
				    format == 0   ? "pades-%d-%d.pdf"
				    : format == 1 ? "attached-cades-%d-%d.p7m"
				                  : "cades-%d-%d.p7s",
				    algo,
				    hash
				);
				buffer source = file_read(name);
				buffer content = format == 2 ? file_read("input.bin")
				                             : (buffer){0};
				CHECK(source.data && (format != 2 || content.data));
				libssig_extend_params extend = {
				    .data = source.data,
				    .data_len = source.len,
				    .content = content.data,
				    .content_len = content.len,
				    .hash = (libssig_hash)hash,
				    .services = &services
				};
				libssig_signature output = {0};
				CHECK(libssig_extend(&extend, &output) == LIBSSIG_OK);
				libssig_verify_params verify = trust;
				verify.data = output.data;
				verify.data_len = output.len;
				verify.content = content.data;
				verify.content_len = content.len;
				libssig_verify_result result = {0};
				CHECK(libssig_verify(&verify, &result) == LIBSSIG_OK);
				CHECK(
				    result.signature_valid && result.trusted &&
				    result.signers[0].archive.valid
				);
				libssig_verify_free(&result);
				libssig_signature_free(&output);
				free(source.data);
				free(content.data);
			}
			free(anchor.data);
		}
	}
	trust.ca_data = doc_root.data;
	trust.ca_data_len = doc_root.len;
	fail_archive = true;
	timestamp_calls = 0;
	libssig_signature output = {0};
	CHECK(libssig_extend(&params, &output) != LIBSSIG_OK && !output.data);
	fail_archive = false;
	revoked_reply = true;
	CHECK(
	    libssig_extend(&params, &output) == LIBSSIG_ERROR_REVOKED &&
	    !output.data
	);
	revoked_reply = false;
	int access = X509_get_ext_by_NID(tsa, NID_info_access, -1);
	CHECK(access >= 0);
	X509_EXTENSION_free(X509_delete_ext(tsa, access));
	CHECK(
	    extension_add(tsa, NID_crl_distribution_points, "URI:http://test/crl")
	);
	CHECK(X509_sign(tsa, root_key, EVP_sha256()));
	CHECK(libssig_extend(&params, &output) == LIBSSIG_OK);
	libssig_signature_free(&output);
	revoked_reply = true;
	CHECK(libssig_extend(&params, &output) != LIBSSIG_OK && !output.data);
	free(original.data);
	free(doc_root.data);
	BIO_free(pem);
	X509_free(tsa);
	X509_free(root);
	EVP_PKEY_free(tsa_key);
	EVP_PKEY_free(root_key);
	return 0;
}
