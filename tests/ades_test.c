/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Reuse the local TSA fixture, including its negative tests, without network.
 */
#define main timestamp_fixture_main
#include "timestamp_test.c"
#undef main
#include <libssig/extend/internal.h>

static int  timestamp_calls;
static int  ocsp_calls;
static bool fail_archive;
static bool fail_validation;
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
	if (fail_validation && kind != LIBSSIG_FETCH_TIMESTAMP) {
		return LIBSSIG_ERROR_TIMESTAMP;
	}
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
static int lt_revoked_check(
    const libssig_signature* output,
    libssig_verify_params    verify
) {
	X509_CRL*     crl = X509_CRL_new();
	X509_REVOKED* entry = X509_REVOKED_new();
	ASN1_TIME*    current = X509_gmtime_adj(NULL, -60);
	ASN1_TIME*    next = X509_gmtime_adj(NULL, 3600);
	ASN1_TIME*    revoked = X509_gmtime_adj(NULL, -120);
	CHECK(
	    crl && entry && current && next && revoked &&
	    X509_CRL_set_version(crl, 1) &&
	    X509_CRL_set_issuer_name(crl, X509_get_subject_name(root)) &&
	    X509_CRL_set1_lastUpdate(crl, current) &&
	    X509_CRL_set1_nextUpdate(crl, next) &&
	    X509_REVOKED_set_serialNumber(entry, X509_get_serialNumber(tsa)) &&
	    X509_REVOKED_set_revocationDate(entry, revoked) &&
	    X509_CRL_add0_revoked(crl, entry) && X509_CRL_sort(crl) &&
	    X509_CRL_sign(crl, root_key, EVP_sha256())
	);
	unsigned char*       bytes = NULL;
	int                  len = i2d_X509_CRL(crl, &bytes);
	const unsigned char* cursor = bytes;
	ASN1_TYPE* value = len > 0 ? d2i_ASN1_TYPE(NULL, &cursor, len) : NULL;
	libssig_validation_data validation = {
	    .certs = sk_X509_new_null(),
	    .revocations = sk_ASN1_TYPE_new_null()
	};
	CHECK(
	    value && validation.certs && validation.revocations &&
	    sk_ASN1_TYPE_push(validation.revocations, value)
	);
	cursor = output->data;
	CMS_ContentInfo* cms = d2i_CMS_ContentInfo(
	    NULL,
	    &cursor,
	    (long)output->len
	);
	CHECK(cms && libssig_validation_embed(&cms, &validation) == LIBSSIG_OK);
	libssig_signature encoded = {0};
	CHECK(libssig_cms_encode(cms, &encoded) == LIBSSIG_OK);
	verify.data = encoded.data;
	verify.data_len = encoded.len;
	libssig_verify_result result = {0};
	CHECK(libssig_verify(&verify, &result) == LIBSSIG_ERROR_REVOKED);
	CHECK(
	    result.signature_valid &&
	    result.signers[0].level == LIBSSIG_LEVEL_B_LT &&
	    !result.signers[0].level_validated
	);
	libssig_verify_free(&result);
	libssig_signature_free(&encoded);
	libssig_validation_free(&validation);
	CMS_ContentInfo_free(cms);
	OPENSSL_free(bytes);
	ASN1_TIME_free(current);
	ASN1_TIME_free(next);
	ASN1_TIME_free(revoked);
	X509_CRL_free(crl);
	return 0;
}

#ifndef LIBSSIG_ADES_FIXTURE_MAIN
#define LIBSSIG_ADES_FIXTURE_MAIN main
#endif
int LIBSSIG_ADES_FIXTURE_MAIN(int argc, char** argv) {
	CHECK(unsetenv("NIX_SSL_CERT_FILE") == 0);
	CHECK(setenv("SSL_CERT_FILE", "/nonexistent-libssig-ades-root", 1) == 0);
	CHECK(setenv("SSL_CERT_DIR", "/nonexistent-libssig-ades-dir", 1) == 0);
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
	    .tsa_fallback_ca_data = (unsigned char*)root_bytes,
	    .tsa_fallback_ca_data_len = (size_t)root_len,
	    .options = LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
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
		CHECK(result.format == LIBSSIG_FORMAT_CADES);
		CHECK(
		    result.signers[0].level_detected &&
		    result.signers[0].level == levels[i] &&
		    result.signers[0].level_validated
		);
		CHECK(result.signers[0].timestamp.present == (i > 0));
		CHECK(result.signers[0].archive.present == (i == 3));
		if (i == 3) {
			CHECK(
			    result.signers[0].archive.valid &&
			    result.signers[0].archive.trusted
			);
		}
		libssig_verify_free(&result);
		if (i == 2) {
			CHECK(lt_revoked_check(&output, verify) == 0);
		}
		verify.options |= LIBSSIG_VERIFY_HISTORICAL;
		status = libssig_verify(&verify, &result);
		CHECK(status == (i == 3 ? LIBSSIG_OK : LIBSSIG_ERROR_EVIDENCE));
		CHECK(
		    result.signers[0].history ==
		    (i == 3 ? LIBSSIG_HISTORY_VALID : LIBSSIG_HISTORY_INCOMPLETE)
		);
		libssig_verify_free(&result);
		verify.options &= ~LIBSSIG_VERIFY_HISTORICAL;
		if (i == 3) {
			const unsigned char* cursor = output.data;
			libssig_raw_cms*     raw = d2i_libssig_raw_cms(
                NULL,
                &cursor,
                (long)output.len
            );
			CHECK(raw && sk_ASN1_TYPE_num(raw->signed_data->revocations) > 0);
			ASN1_TYPE* source = sk_ASN1_TYPE_value(
			    raw->signed_data->revocations,
			    0
			);
			ASN1_TYPE* added = ASN1_TYPE_new();
			CHECK(
			    added &&
			    ASN1_TYPE_set1(added, source->type, source->value.ptr) &&
			    sk_ASN1_TYPE_push(raw->signed_data->revocations, added)
			);
			unsigned char* unprotected = NULL;
			int            extra_len = i2d_libssig_raw_cms(raw, &unprotected);
			CHECK(extra_len > 0);
			verify.data = unprotected;
			verify.data_len = (size_t)extra_len;
			verify.options |= LIBSSIG_VERIFY_HISTORICAL;
			CHECK(libssig_verify(&verify, &result) == LIBSSIG_ERROR_TIMESTAMP);
			CHECK(
			    result.signature_valid &&
			    result.signers[0].history == LIBSSIG_HISTORY_INCOMPLETE
			);
			libssig_verify_free(&result);
			OPENSSL_free(unprotected);
			ASN1_TYPE_free(sk_ASN1_TYPE_pop(raw->signed_data->revocations));
			verify.options &= ~LIBSSIG_VERIFY_HISTORICAL;

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

		if (i == 3) {
			libssig_extend_params renew = params;
			renew.data = output.data;
			renew.data_len = output.len;
			libssig_signature renewed = {0};
			libssig_status    renewed_status = libssig_extend(&renew, &renewed);
			if (renewed_status != LIBSSIG_OK) {
				fprintf(stderr, "CAdES renewal status=%d\n", renewed_status);
			}
			CHECK(renewed_status == LIBSSIG_OK);
			libssig_verify_params checked = trust;
			checked.data = renewed.data;
			checked.data_len = renewed.len;
			libssig_verify_result renewed_result = {0};
			CHECK(libssig_verify(&checked, &renewed_result) == LIBSSIG_OK);
			CHECK(renewed_result.signers[0].level_validated);
			CHECK(
			    file_write("ades-renewed.p7m", renewed.data, renewed.len) == 0
			);
			libssig_verify_free(&renewed_result);
			libssig_signature_free(&renewed);
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
		CHECK(result.format == LIBSSIG_FORMAT_PADES);
		CHECK(
		    result.signers[0].level_detected &&
		    result.signers[0].level == levels[i] &&
		    result.signers[0].level_validated
		);
		CHECK(result.signers[0].timestamp.present == (i > 0));
		CHECK(result.signers[0].archive.present == (i == 3));
		libssig_verify_free(&result);
		verify.options |= LIBSSIG_VERIFY_HISTORICAL;
		status = libssig_verify(&verify, &result);
		if (status != (i == 3 ? LIBSSIG_OK : LIBSSIG_ERROR_EVIDENCE)) {
			fprintf(stderr, "PDF historical level %zu: %d\n", i, status);
		}
		CHECK(status == (i == 3 ? LIBSSIG_OK : LIBSSIG_ERROR_EVIDENCE));
		CHECK(
		    result.signers[0].history ==
		    (i == 3 ? LIBSSIG_HISTORY_VALID : LIBSSIG_HISTORY_INCOMPLETE)
		);
		if (i == 3) {
			libssig_verify_free(&result);
			libssig_signature current_crl = {0};
			CHECK(
			    exchange(
			        NULL,
			        LIBSSIG_FETCH_CRL,
			        "http://test/crl",
			        NULL,
			        0,
			        &current_crl
			    ) == LIBSSIG_OK
			);
			libssig_revocation_evidence evidence = {
			    .data = current_crl.data,
			    .len = current_crl.len
			};
			verify.current_revocations = &evidence;
			verify.current_revocation_count = 1;
			CHECK(libssig_verify(&verify, &result) == LIBSSIG_OK);
			libssig_verify_free(&result);
			static const unsigned char malformed[] = {0x30, 0};
			evidence.data = malformed;
			evidence.len = sizeof(malformed);
			CHECK(libssig_verify(&verify, &result) == LIBSSIG_ERROR_EVIDENCE);
			CHECK(result.signature_valid);
			libssig_verify_free(&result);
			libssig_signature_free(&current_crl);
			verify.current_revocations = NULL;
			verify.current_revocation_count = 0;
			static const char suffix[] = "\n% unsigned revision\n";
			unsigned char*    unsigned_revision = malloc(
                output.len + sizeof(suffix) - 1
            );
			CHECK(unsigned_revision);
			memcpy(unsigned_revision, output.data, output.len);
			memcpy(unsigned_revision + output.len, suffix, sizeof(suffix) - 1);
			verify.data = unsigned_revision;
			verify.data_len = output.len + sizeof(suffix) - 1;
			CHECK(libssig_verify(&verify, &result) == LIBSSIG_ERROR_EVIDENCE);
			CHECK(
			    result.signature_valid &&
			    result.signers[0].history == LIBSSIG_HISTORY_INCOMPLETE
			);
			free(unsigned_revision);
		}

		if (i == 3) {
			libssig_extend_params renew = p;
			renew.data = output.data;
			renew.data_len = output.len;
			libssig_signature renewed = {0};
			libssig_status    renewed_status = libssig_extend(&renew, &renewed);
			if (renewed_status != LIBSSIG_OK) {
				fprintf(stderr, "PAdES renewal status=%d\n", renewed_status);
			}
			CHECK(renewed_status == LIBSSIG_OK);
			CHECK(
			    renewed.len > output.len &&
			    !memcmp(renewed.data, output.data, output.len)
			);
			libssig_verify_params checked = trust;
			checked.data = renewed.data;
			checked.data_len = renewed.len;
			libssig_verify_result renewed_result = {0};
			CHECK(libssig_verify(&checked, &renewed_result) == LIBSSIG_OK);
			CHECK(renewed_result.signers[0].level_validated);
			CHECK(
			    file_write("pades-renewed.pdf", renewed.data, renewed.len) == 0
			);
			libssig_verify_free(&renewed_result);
			libssig_signature_free(&renewed);
		}
		char name[64];
		snprintf(name, sizeof(name), "pades-level-%zu.pdf", i);
		CHECK(file_write(name, output.data, output.len) == 0);
		libssig_verify_free(&result);
		libssig_signature_free(&output);
	}
	/* Validation fails before a PDF revision is opened: cleanup must be safe.
	 */
	libssig_extend_params failed = params;
	failed.data = pdf.data;
	failed.data_len = pdf.len;
	failed.level = LIBSSIG_LEVEL_B_LTA;
	libssig_signature failed_output = {0};
	fail_validation = true;
	CHECK(libssig_extend(&failed, &failed_output) != LIBSSIG_OK);
	CHECK(!failed_output.data && !failed_output.len);
	libssig_signature_free(&failed_output);
	fail_validation = false;
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
