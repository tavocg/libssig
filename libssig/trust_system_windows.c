/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifdef _WIN32
#include <libssig/trust_system.h>
#include <stdint.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
/* OpenSSL precedes wincrypt's conflicting X509_NAME macro; windows.h must
 * precede wincrypt.h for the Windows type declarations. */
// clang-format off
#include <windows.h>
#include <wincrypt.h>
// clang-format on
#undef X509_NAME

libssig_status libssig_trust_native_certificates(STACK_OF(X509) * certs) {
	static const wchar_t* names[] = {L"ROOT", L"CA"};
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
		HCERTSTORE store = CertOpenStore(
		    CERT_STORE_PROV_SYSTEM_W,
		    0,
		    0,
		    CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
		        CERT_STORE_READONLY_FLAG,
		    names[i]
		);
		if (!store) {
			return LIBSSIG_ERROR_TRUST;
		}
		PCCERT_CONTEXT cert = NULL;
		libssig_status status = LIBSSIG_OK;
		while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
			status = libssig_trust_native_append(
			    certs,
			    cert->pbCertEncoded,
			    cert->cbCertEncoded
			);
			if (status != LIBSSIG_OK) {
				CertFreeCertificateContext(cert);
				break;
			}
		}
		if (status == LIBSSIG_OK &&
		    GetLastError() != (DWORD)CRYPT_E_NOT_FOUND) {
			status = LIBSSIG_ERROR_TRUST;
		}
		CertCloseStore(store, 0);
		if (status != LIBSSIG_OK) {
			return status;
		}
	}
	return LIBSSIG_OK;
}
static PCCERT_CONTEXT certificate_add(HCERTSTORE store, X509* cert) {
	unsigned char* der = NULL;
	int            len = i2d_X509(cert, &der);
	PCCERT_CONTEXT result = NULL;
	if (len > 0) {
		CertAddEncodedCertificateToStore(
		    store,
		    X509_ASN_ENCODING,
		    der,
		    (DWORD)len,
		    CERT_STORE_ADD_USE_EXISTING,
		    &result
		);
	}
	OPENSSL_free(der);
	return result;
}
bool libssig_trust_native_verify(X509_STORE_CTX* ctx) {
	STACK_OF(X509)* certs = X509_STORE_CTX_get0_chain(ctx);
	int        count = sk_X509_num(certs);
	HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
	if (!store || count < 1) {
		if (store) {
			CertCloseStore(store, 0);
		}
		return false;
	}
	PCCERT_CONTEXT leaf = NULL;
	bool           ok = true;
	for (int i = 0; ok && i < count; ++i) {
		PCCERT_CONTEXT cert = certificate_add(store, sk_X509_value(certs, i));
		if (!cert) {
			ok = false;
		} else if (!i) {
			leaf = cert;
		} else {
			CertFreeCertificateContext(cert);
		}
	}
	/* No Authenticode or S/MIME policy is implied by a document signature. */
	CERT_CHAIN_PARA params = {0};
	params.cbSize = sizeof(params);
	params.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	char* timestamp = szOID_KP_TIME_STAMP_SIGNING;
	if (X509_VERIFY_PARAM_get_purpose(X509_STORE_CTX_get0_param(ctx)) ==
	    X509_PURPOSE_TIMESTAMP_SIGN) {
		params.RequestedUsage.Usage.cUsageIdentifier = 1;
		params.RequestedUsage.Usage.rgpszUsageIdentifier = &timestamp;
	}
	time_t         at = libssig_trust_native_time(ctx);
	const int64_t  epoch = INT64_C(11644473600);
	ULARGE_INTEGER ticks;
	int64_t        seconds = (int64_t)at;
	if (seconds < -epoch ||
	    seconds > (int64_t)(UINT64_MAX / UINT64_C(10000000)) - epoch) {
		ok = false;
	}
	ticks.QuadPart = ok ? (uint64_t)(seconds + epoch) * UINT64_C(10000000) : 0;
	FILETIME when = {
	    .dwLowDateTime = ticks.LowPart,
	    .dwHighDateTime = ticks.HighPart
	};
	PCCERT_CHAIN_CONTEXT chain = NULL;
	if (ok) {
		ok = CertGetCertificateChain(
		         NULL,
		         leaf,
		         &when,
		         store,
		         &params,
		         CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA |
		             CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
		         NULL,
		         &chain
		     ) != 0;
	}
	CERT_CHAIN_POLICY_PARA policy = {0};
	policy.cbSize = sizeof(policy);
	CERT_CHAIN_POLICY_STATUS status = {0};
	status.cbSize = sizeof(status);
	if (ok) {
		ok = chain->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR &&
		     CertVerifyCertificateChainPolicy(
		         CERT_CHAIN_POLICY_BASE,
		         chain,
		         &policy,
		         &status
		     ) &&
		     !status.dwError;
	}
	if (ok) {
		ok = chain->cChain == 1 && chain->rgpChain[0]->cElement == (DWORD)count;
	}
	for (int i = 0; ok && i < count; ++i) {
		PCCERT_CONTEXT cert = chain->rgpChain[0]->rgpElement[i]->pCertContext;
		ok = libssig_trust_native_matches(
		    sk_X509_value(certs, i),
		    cert->pbCertEncoded,
		    cert->cbCertEncoded
		);
	}
	if (chain) {
		CertFreeCertificateChain(chain);
	}
	if (leaf) {
		CertFreeCertificateContext(leaf);
	}
	CertCloseStore(store, 0);
	return ok;
}
#else
typedef int libssig_trust_windows_not_selected;
#endif
