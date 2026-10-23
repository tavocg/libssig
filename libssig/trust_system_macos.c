/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libssig/trust_system.h>

static libssig_status certificates_append(
    STACK_OF(X509) * certs,
    CFArrayRef array
) {
	for (CFIndex i = 0; array && i < CFArrayGetCount(array); ++i) {
		SecCertificateRef cert = (SecCertificateRef)
		    CFArrayGetValueAtIndex(array, i);
		CFDataRef      der = SecCertificateCopyData(cert);
		libssig_status status = der ? libssig_trust_native_append(
		                                  certs,
		                                  CFDataGetBytePtr(der),
		                                  (size_t)CFDataGetLength(der)
		                              )
		                            : LIBSSIG_ERROR_CRYPTO;
		if (der) {
			CFRelease(der);
		}
		if (status != LIBSSIG_OK) {
			return status;
		}
	}
	return LIBSSIG_OK;
}
libssig_status libssig_trust_native_certificates(STACK_OF(X509) * certs) {
	CFArrayRef     array = NULL;
	OSStatus       result = SecTrustCopyAnchorCertificates(&array);
	libssig_status status = result == errSecSuccess
	                            ? certificates_append(certs, array)
	                            : LIBSSIG_ERROR_TRUST;
	if (array) {
		CFRelease(array);
	}
	/* Certificates with user/admin settings may be trusted or explicitly
	 * denied; SecTrust, rather than enumeration, decides whether they are
	 * anchors. */
	SecTrustSettingsDomain domains[] = {
	    kSecTrustSettingsDomainUser,
	    kSecTrustSettingsDomainAdmin
	};
	for (size_t i = 0;
	     status == LIBSSIG_OK && i < sizeof(domains) / sizeof(domains[0]);
	     ++i) {
		array = NULL;
		result = SecTrustSettingsCopyCertificates(domains[i], &array);
		if (result == errSecSuccess) {
			status = certificates_append(certs, array);
		} else if (result != errSecNoTrustSettings) {
			status = LIBSSIG_ERROR_TRUST;
		}
		if (array) {
			CFRelease(array);
		}
	}
	if (status != LIBSSIG_OK) {
		return status;
	}
	/* Public certificates in the default keychain search list supply issuers.
	 * Locked keychains are optional; no authentication UI is permitted.
	 */
	/* The C API's no-UI option remains supported. Its replacement requires
	 * an Objective-C LAContext; retain the public C-only option for 10.14+. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	const void* keys[] =
	    {kSecClass, kSecMatchLimit, kSecReturnRef, kSecUseAuthenticationUI};
	const void* values[] = {
	    kSecClassCertificate,
	    kSecMatchLimitAll,
	    kCFBooleanTrue,
	    kSecUseAuthenticationUIFail
	};
#pragma clang diagnostic pop
	CFDictionaryRef query = CFDictionaryCreate(
	    NULL,
	    keys,
	    values,
	    4,
	    &kCFTypeDictionaryKeyCallBacks,
	    &kCFTypeDictionaryValueCallBacks
	);
	CFTypeRef found = NULL;
	result = query ? SecItemCopyMatching(query, &found) : errSecAllocate;
	if (result == errSecSuccess && found &&
	    CFGetTypeID(found) == CFArrayGetTypeID()) {
		status = certificates_append(certs, (CFArrayRef)found);
	} else if (result != errSecItemNotFound &&
	           result != errSecInteractionNotAllowed) {
		status = LIBSSIG_ERROR_TRUST;
	}
	if (found) {
		CFRelease(found);
	}
	if (query) {
		CFRelease(query);
	}
	return status;
}
static SecCertificateRef certificate_create(X509* cert) {
	unsigned char*    der = NULL;
	int               len = i2d_X509(cert, &der);
	CFDataRef         data = len > 0 ? CFDataCreate(NULL, der, len) : NULL;
	SecCertificateRef result = data ? SecCertificateCreateWithData(NULL, data)
	                                : NULL;
	if (data) {
		CFRelease(data);
	}
	OPENSSL_free(der);
	return result;
}
/* The legacy accessors also work on macOS 10.14/10.15/11; they only read the
 * evaluated chain. No deprecated trust evaluation function is used. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static bool chain_matches(SecTrustRef trust, const STACK_OF(X509) * chain) {
	if (SecTrustGetCertificateCount(trust) != sk_X509_num(chain)) {
		return false;
	}
	for (int i = 0; i < sk_X509_num(chain); ++i) {
		CFDataRef der = SecCertificateCopyData(
		    SecTrustGetCertificateAtIndex(trust, i)
		);
		bool ok = der && libssig_trust_native_matches(
		                     sk_X509_value(chain, i),
		                     CFDataGetBytePtr(der),
		                     (size_t)CFDataGetLength(der)
		                 );
		if (der) {
			CFRelease(der);
		}
		if (!ok) {
			return false;
		}
	}
	return true;
}
#pragma clang diagnostic pop
bool libssig_trust_native_verify(X509_STORE_CTX* ctx) {
	STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(ctx);
	CFMutableArrayRef certs = CFArrayCreateMutable(
	    NULL,
	    0,
	    &kCFTypeArrayCallBacks
	);
	if (!certs) {
		return false;
	}
	bool ok = true;
	for (int i = 0; ok && i < sk_X509_num(chain); ++i) {
		SecCertificateRef cert = certificate_create(sk_X509_value(chain, i));
		if (!cert) {
			ok = false;
		} else {
			CFArrayAppendValue(certs, cert);
			CFRelease(cert);
		}
	}
	int purpose = X509_VERIFY_PARAM_get_purpose(X509_STORE_CTX_get0_param(ctx));
	SecPolicyRef policy = purpose == X509_PURPOSE_TIMESTAMP_SIGN
	                          ? SecPolicyCreateWithProperties(
	                                kSecPolicyAppleTimeStamping,
	                                NULL
	                            )
	                          : SecPolicyCreateBasicX509();
	SecTrustRef  trust = NULL;
	if (ok) {
		ok = policy && SecTrustCreateWithCertificates(certs, policy, &trust) ==
		                   errSecSuccess;
	}
	time_t    at = libssig_trust_native_time(ctx);
	CFDateRef date = CFDateCreate(
	    NULL,
	    (CFAbsoluteTime)at - kCFAbsoluteTimeIntervalSince1970
	);
	if (ok) {
		ok = date && SecTrustSetVerifyDate(trust, date) == errSecSuccess &&
		     SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess;
	}
	if (ok) {
		if (__builtin_available(macOS 10.14, *)) {
			ok = SecTrustEvaluateWithError(trust, NULL) &&
			     chain_matches(trust, chain);
		} else {
			ok = false;
		}
	}
	if (date) {
		CFRelease(date);
	}
	if (trust) {
		CFRelease(trust);
	}
	if (policy) {
		CFRelease(policy);
	}
	CFRelease(certs);
	return ok;
}
#else
typedef int libssig_trust_macos_not_selected;
#endif
