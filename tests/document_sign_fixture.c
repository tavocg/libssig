/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Reuse the tested PKCS#11 lifecycle fixture; signing still goes through
 * libssig_sign. */
#define main document_sign_fixture_original_main
#include "sign_test.c"
#undef main

static CK_RV document_raw_sign(
    CK_SESSION_HANDLE handle,
    CK_BYTE_PTR       bytes,
    CK_ULONG          len,
    CK_BYTE_PTR       output,
    CK_ULONG_PTR      out_len
) {
	(void)handle;
	size_t half = (size_t)(EVP_PKEY_get_bits(rsa) + 7) / 8;
	size_t needed = algorithm == LIBSSIG_ALGO_ECDSA
	                    ? 2 * half
	                    : (size_t)EVP_PKEY_get_size(rsa);
	if (!output) {
		*out_len = (CK_ULONG)needed;
		return CKR_OK;
	}
	if (*out_len < needed) {
		return CKR_BUFFER_TOO_SMALL;
	}
	EVP_MD_CTX*   ctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX* key_ctx = NULL;
	unsigned char signature[1024];
	size_t        size = sizeof(signature);
	bool ok = ctx && EVP_DigestSignInit(ctx, &key_ctx, digest, NULL, rsa) > 0 &&
	          padding_set(key_ctx) &&
	          EVP_DigestSign(ctx, signature, &size, bytes, (size_t)len) > 0;
	if (ok && algorithm == LIBSSIG_ALGO_ECDSA) {
		const unsigned char* cursor = signature;
		ECDSA_SIG*           sig = d2i_ECDSA_SIG(NULL, &cursor, (long)size);
		const BIGNUM *       r = NULL, *s = NULL;
		if (sig) {
			ECDSA_SIG_get0(sig, &r, &s);
		}
		ok = sig && BN_bn2binpad(r, output, (int)half) == (int)half &&
		     BN_bn2binpad(s, output + half, (int)half) == (int)half;
		ECDSA_SIG_free(sig);
	} else if (ok) {
		memcpy(output, signature, size);
	}
	EVP_MD_CTX_free(ctx);
	*out_len = (CK_ULONG)needed;
	return ok ? CKR_OK : CKR_GENERAL_ERROR;
}
libssig_status document_fixture_sign(
    EVP_PKEY*           key,
    X509*               cert,
    libssig_sign_params params,
    libssig_signature*  output
) {
	static const CK_MECHANISM_TYPE mechanisms[3][3] = {
	    {CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS},
	    {CKM_SHA256_RSA_PKCS_PSS,
	     CKM_SHA384_RSA_PKCS_PSS,
	     CKM_SHA512_RSA_PKCS_PSS},
	    {CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512}
	};
	const EVP_MD* digests[] = {EVP_sha256(), EVP_sha384(), EVP_sha512()};
	const CK_MECHANISM_TYPE    hashes[] = {CKM_SHA256, CKM_SHA384, CKM_SHA512};
	const CK_RSA_PKCS_MGF_TYPE mgfs[] =
	    {CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512};
	rsa = key;
	public_key = key;
	key_type = params.algo == LIBSSIG_ALGO_ECDSA ? CKK_EC : CKK_RSA;
	algorithm = params.algo;
	digest = digests[params.hash];
	expected_mechanism = mechanisms[params.algo][params.hash];
	expected_hash = hashes[params.hash];
	expected_mgf = mgfs[params.hash];
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
	module.C_Sign = document_raw_sign;
	CK_FUNCTION_LIST*           modules[] = {&module, NULL};
	struct libssig_context_impl impl = {.modules = modules};
	libssig_context             ctx = {.impl = &impl};
	libssig_token               token = {.uri = "pkcs11:token=test"};
	unsigned char*              der = NULL;
	int                         len = i2d_X509(cert, &der);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	libssig_certificate certificate = {
	    .id = (unsigned char*)id,
	    .id_len = sizeof(id),
	    .der = der,
	    .der_len = (size_t)len
	};
	params.cert = &certificate;
	params.token = &token;
	params.pin = (const unsigned char*)"1234";
	params.pin_len = 4;
	libssig_status status = libssig_sign(&ctx, &params, output);
	OPENSSL_free(der);
	return status;
}
