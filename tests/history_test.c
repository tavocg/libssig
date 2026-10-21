/* SPDX-License-Identifier: GPL-3.0-or-later */
#define main timestamp_fixture_main
#include "timestamp_test.c"
#undef main
#include <libssig/extend/internal.h>

static time_t signed_at;
static int signing_time(TS_RESP_CTX* ctx, void* user, long* sec, long* usec) {
	(void)ctx;
	(void)user;
	*sec = (long)(user ? *(time_t*)user : signed_at);
	*usec = 0;
	return 1;
}

static bool     aged_archive;
static TS_RESP* response_at(const libssig_signature* request, time_t at) {
	TS_RESP_CTX* ctx = TS_RESP_CTX_new();
	ASN1_OBJECT* policy = OBJ_txt2obj("1.2.3.4.1", 1);
	BIO*         input = BIO_new_mem_buf(request->data, (int)request->len);
	bool ok = ctx && policy && input && TS_RESP_CTX_set_signer_cert(ctx, tsa) &&
	          TS_RESP_CTX_set_signer_key(ctx, tsa_key) &&
	          TS_RESP_CTX_set_signer_digest(ctx, EVP_sha256()) &&
	          TS_RESP_CTX_set_ess_cert_id_digest(ctx, EVP_sha256()) &&
	          TS_RESP_CTX_set_def_policy(ctx, policy) &&
	          TS_RESP_CTX_add_md(ctx, EVP_sha256());
	if (ok) {
		TS_RESP_CTX_set_time_cb(ctx, signing_time, &at);
	}
	TS_RESP* reply = ok ? TS_RESP_create_response(ctx, input) : NULL;
	TS_RESP_CTX_free(ctx);
	ASN1_OBJECT_free(policy);
	BIO_free(input);
	return reply;
}

static int old_stamp(CMS_ContentInfo* cms) {
	CMS_SignerInfo* s = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
	ASN1_OCTET_STRING* signature = CMS_SignerInfo_get0_signature(s);
	unsigned char      hash[32];
	unsigned int       len = 0;
	CHECK(EVP_Digest(
	    ASN1_STRING_get0_data(signature),
	    ASN1_STRING_length(signature),
	    hash,
	    &len,
	    EVP_sha256(),
	    NULL
	));
	libssig_signature request = {0};
	CHECK(
	    libssig_ades_query(hash, len, LIBSSIG_HASH_SHA256, &request) ==
	    LIBSSIG_OK
	);
	TS_RESP*       reply = response_at(&request, signed_at);
	PKCS7*         token = reply ? TS_RESP_get_token(reply) : NULL;
	unsigned char* data = NULL;
	int            size = token ? i2d_PKCS7(token, &data) : 0;
	CHECK(
	    size > 0 && CMS_unsigned_add1_attr_by_NID(
	                    s,
	                    NID_id_smime_aa_timeStampToken,
	                    V_ASN1_SEQUENCE,
	                    data,
	                    size
	                )
	);
	OPENSSL_free(data);
	TS_RESP_free(reply);
	libssig_signature_free(&request);
	return 0;
}

static libssig_status archive_exchange(
    void*                user,
    libssig_fetch_kind   kind,
    const char*          url,
    const unsigned char* data,
    size_t               len,
    libssig_signature*   output
) {
	(void)user;
	(void)url;
	if (kind != LIBSSIG_FETCH_TIMESTAMP) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_signature request = {.data = (unsigned char*)data, .len = len};
	TS_RESP* reply = aged_archive ? response_at(&request, signed_at + 600)
	                              : response_create(&request, false);
	buffer   encoded = reply ? response_encode(reply) : (buffer){0};
	output->data = encoded.len ? malloc(encoded.len) : NULL;
	if (output->data) {
		memcpy(output->data, encoded.data, encoded.len);
		output->len = encoded.len;
	}
	OPENSSL_free(encoded.data);
	TS_RESP_free(reply);
	return output->data ? LIBSSIG_OK : LIBSSIG_ERROR_CRYPTO;
}

static int revocations_add(
    CMS_ContentInfo** cms,
    X509*             leaf,
    long              revoked_offset,
    bool              include,
    bool              stale,
    int               reason
) {
	X509_CRL*  crl = X509_CRL_new();
	ASN1_TIME* current = X509_gmtime_adj(
	    NULL,
	    aged_archive ? -2 * 86400 + 60 : -60
	);
	ASN1_TIME* next = X509_gmtime_adj(
	    NULL,
	    aged_archive ? -2 * 86400 + 3600
	    : stale      ? -1
	                 : 3600
	);
	CHECK(
	    crl && current && next && X509_CRL_set_version(crl, 1) &&
	    X509_CRL_set_issuer_name(crl, X509_get_subject_name(root)) &&
	    X509_CRL_set1_lastUpdate(crl, current) &&
	    X509_CRL_set1_nextUpdate(crl, next)
	);
	if (revoked_offset) {
		X509_REVOKED*    entry = X509_REVOKED_new();
		ASN1_TIME*       when = X509_gmtime_adj(NULL, revoked_offset);
		ASN1_ENUMERATED* code = ASN1_ENUMERATED_new();
		CHECK(
		    entry && when && code && ASN1_ENUMERATED_set(code, reason) &&
		    X509_REVOKED_set_serialNumber(entry, X509_get_serialNumber(leaf)) &&
		    X509_REVOKED_set_revocationDate(entry, when) &&
		    X509_REVOKED_add1_ext_i2d(entry, NID_crl_reason, code, 0, 0) &&
		    X509_CRL_add0_revoked(crl, entry)
		);
		ASN1_ENUMERATED_free(code);
		ASN1_TIME_free(when);
	}
	CHECK(X509_CRL_sort(crl) && X509_CRL_sign(crl, root_key, EVP_sha256()));
	unsigned char*       data = NULL;
	int                  len = i2d_X509_CRL(crl, &data);
	const unsigned char* cursor = data;
	ASN1_TYPE* value = len > 0 ? d2i_ASN1_TYPE(NULL, &cursor, len) : NULL;
	libssig_validation_data validation = {
	    .certs = sk_X509_new_null(),
	    .revocations = sk_ASN1_TYPE_new_null()
	};
	CHECK(value && validation.certs && validation.revocations);
	if (include) {
		CHECK(sk_ASN1_TYPE_push(validation.revocations, value));
	} else {
		ASN1_TYPE_free(value);
	}
	CHECK(libssig_validation_embed(cms, &validation) == LIBSSIG_OK);
	libssig_validation_free(&validation);
	OPENSSL_free(data);
	ASN1_TIME_free(current);
	ASN1_TIME_free(next);
	X509_CRL_free(crl);
	return 0;
}

static int history_case(
    X509*                        leaf,
    EVP_PKEY*                    key,
    const libssig_verify_params* trust,
    X509*                        old_tsa,
    long                         revoked_offset,
    bool                         include,
    bool                         stale,
    int                          reason,
    libssig_status               expected
) {
	BIO* content = BIO_new_mem_buf("historical content", 18);
	CMS_ContentInfo*
	    cms = CMS_sign(leaf, key, NULL, content, CMS_BINARY | CMS_CADES);
	CHECK(
	    cms && CMS_add1_cert(cms, root) && CMS_add1_cert(cms, tsa) &&
	    CMS_add1_cert(cms, old_tsa)
	);
	X509* current_tsa = tsa;
	tsa = old_tsa;
	CHECK(old_stamp(cms) == 0);
	tsa = current_tsa;
	CHECK(
	    revocations_add(&cms, leaf, revoked_offset, include, stale, reason) == 0
	);
	libssig_sign_services services = {
	    .exchange = archive_exchange,
	    .tsa_url = "http://local/tsa",
	    .trust = trust
	};
	libssig_extend_params extend = {
	    .services = &services,
	    .hash = LIBSSIG_HASH_SHA256
	};
	CHECK(libssig_cades_v131_archive_apply(&cms, &extend) == LIBSSIG_OK);
	libssig_signature encoded = {0};
	CHECK(libssig_cms_encode(cms, &encoded) == LIBSSIG_OK);
	libssig_verify_params params = *trust;
	params.data = encoded.data;
	params.data_len = encoded.len;
	libssig_verify_result result = {0};
	params.options = LIBSSIG_VERIFY_CURRENT_TIME;
	CHECK(libssig_verify(&params, &result) == LIBSSIG_ERROR_TRUST);
	CHECK(!result.signers[0].level_validated);
	CHECK(result.signature_valid);
	libssig_verify_free(&result);
	params.options = 0;
	libssig_status status = libssig_verify(&params, &result);
	if (status != expected) {
		fprintf(
		    stderr,
		    "Historical expected %d, got %d (revoked=%ld include=%d "
		    "stale=%d)\n",
		    expected,
		    status,
		    revoked_offset,
		    include,
		    stale
		);
	}
	CHECK(status == expected && result.signature_valid);
	CHECK(
	    result.format == LIBSSIG_FORMAT_CADES &&
	    result.signers[0].level_detected &&
	    result.signers[0].level == LIBSSIG_LEVEL_B_LTA
	);
	CHECK(result.signers[0].level_validated == (expected == LIBSSIG_OK));
	CHECK(
	    result.signers[0].history ==
	    (expected == LIBSSIG_OK              ? LIBSSIG_HISTORY_VALID
	     : expected == LIBSSIG_ERROR_REVOKED ? LIBSSIG_HISTORY_REVOKED
	                                         : LIBSSIG_HISTORY_INCOMPLETE)
	);
	CHECK(result.signers[0].validation_time[0]);
	libssig_verify_free(&result);
	if (aged_archive) {
		X509_CRL*  crl = X509_CRL_new();
		ASN1_TIME* current = X509_gmtime_adj(NULL, -60);
		ASN1_TIME* next = X509_gmtime_adj(NULL, 3600);
		CHECK(
		    crl && current && next && X509_CRL_set_version(crl, 1) &&
		    X509_CRL_set_issuer_name(crl, X509_get_subject_name(root)) &&
		    X509_CRL_set1_lastUpdate(crl, current) &&
		    X509_CRL_set1_nextUpdate(crl, next) &&
		    X509_CRL_sign(crl, root_key, EVP_sha256())
		);
		unsigned char*              data = NULL;
		int                         len = i2d_X509_CRL(crl, &data);
		libssig_revocation_evidence evidence = {
		    .data = data,
		    .len = (size_t)len
		};
		params.current_revocations = &evidence;
		params.current_revocation_count = 1;
		CHECK(
		    libssig_verify(&params, &result) ==
		    (include ? LIBSSIG_OK : LIBSSIG_ERROR_EVIDENCE)
		);
		CHECK(
		    result.signers[0].history ==
		    (include ? LIBSSIG_HISTORY_VALID : LIBSSIG_HISTORY_INCOMPLETE)
		);
		libssig_verify_free(&result);
		OPENSSL_free(data);
		ASN1_TIME_free(current);
		ASN1_TIME_free(next);
		X509_CRL_free(crl);
	}
	libssig_signature_free(&encoded);
	CMS_ContentInfo_free(cms);
	BIO_free(content);
	return 0;
}

int main(void) {
	root_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	tsa_key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	CHECK(root_key && tsa_key);
	root = certificate_create(root_key, true);
	CHECK(
	    root && X509_gmtime_adj(X509_getm_notBefore(root), -4 * 86400) &&
	    X509_sign(root, root_key, EVP_sha256())
	);
	tsa = certificate_create(tsa_key, false);
	CHECK(
	    tsa && X509_gmtime_adj(X509_getm_notBefore(tsa), -3 * 86400) &&
	    X509_sign(tsa, root_key, EVP_sha256())
	);
	X509* old_tsa = certificate_create(tsa_key, false);
	CHECK(
	    tsa && old_tsa && ASN1_INTEGER_set(X509_get_serialNumber(old_tsa), 3) &&
	    X509_gmtime_adj(X509_getm_notBefore(old_tsa), -3 * 86400) &&
	    X509_gmtime_adj(X509_getm_notAfter(old_tsa), -86400) &&
	    X509_sign(old_tsa, root_key, EVP_sha256())
	);
	EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	X509*     leaf = certificate_create(key, false);
	CHECK(leaf && ASN1_INTEGER_set(X509_get_serialNumber(leaf), 4));
	int pos = X509_get_ext_by_NID(leaf, NID_ext_key_usage, -1);
	CHECK(pos >= 0);
	X509_EXTENSION_free(X509_delete_ext(leaf, pos));
	CHECK(
	    X509_gmtime_adj(X509_getm_notBefore(leaf), -3 * 86400) &&
	    X509_gmtime_adj(X509_getm_notAfter(leaf), -86400) &&
	    X509_sign(leaf, root_key, EVP_sha256())
	);
	BIO* pem = BIO_new(BIO_s_mem());
	CHECK(pem && PEM_write_bio_X509(pem, root));
	char*                 data = NULL;
	long                  len = BIO_get_mem_data(pem, &data);
	libssig_verify_params trust = {
	    .ca_data = (unsigned char*)data,
	    .ca_data_len = (size_t)len,
	    .tsa_ca_data = (unsigned char*)data,
	    .tsa_ca_data_len = (size_t)len
	};
	signed_at = time(NULL) - 2 * 86400;
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        0,
	        true,
	        false,
	        0,
	        LIBSSIG_OK
	    ) == 0
	);
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        -3600,
	        true,
	        false,
	        CRL_REASON_AFFILIATION_CHANGED,
	        LIBSSIG_OK
	    ) == 0
	);
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        -3 * 86400,
	        true,
	        false,
	        CRL_REASON_AFFILIATION_CHANGED,
	        LIBSSIG_ERROR_REVOKED
	    ) == 0
	);
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        -3600,
	        true,
	        false,
	        CRL_REASON_KEY_COMPROMISE,
	        LIBSSIG_ERROR_REVOKED
	    ) == 0
	);
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        0,
	        false,
	        false,
	        0,
	        LIBSSIG_ERROR_EVIDENCE
	    ) == 0
	);
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        0,
	        true,
	        true,
	        0,
	        LIBSSIG_ERROR_EVIDENCE
	    ) == 0
	);
	aged_archive = true;
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        0,
	        true,
	        false,
	        0,
	        LIBSSIG_ERROR_EVIDENCE
	    ) == 0
	);
	CHECK(
	    history_case(
	        leaf,
	        key,
	        &trust,
	        old_tsa,
	        0,
	        false,
	        false,
	        0,
	        LIBSSIG_ERROR_EVIDENCE
	    ) == 0
	);
	BIO_free(pem);
	X509_free(leaf);
	X509_free(old_tsa);
	X509_free(tsa);
	X509_free(root);
	EVP_PKEY_free(key);
	EVP_PKEY_free(tsa_key);
	EVP_PKEY_free(root_key);
	return 0;
}
