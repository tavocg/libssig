/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static CK_FLAGS     flags = CKF_LOGIN_REQUIRED;
static CK_RV        info_rv = CKR_OK;
static CK_RV        login_rv = CKR_OK;
static unsigned int calls;
static bool         protected_path;

static CK_RV info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR out) {
	(void)slot;
	memset(out, 0, sizeof(*out));
	out->flags = flags;
	return info_rv;
}

static CK_RV login(
    CK_SESSION_HANDLE handle,
    CK_USER_TYPE      user,
    CK_UTF8CHAR_PTR   pin,
    CK_ULONG          length
) {
	++calls;
	if (handle != 42 || user != CKU_USER) {
		return CKR_ARGUMENTS_BAD;
	}
	if (protected_path) {
		if (pin || length) {
			return CKR_ARGUMENTS_BAD;
		}
	} else if (!pin || length != 4 || memcmp(pin, "1234", 4)) {
		return CKR_ARGUMENTS_BAD;
	}
	return login_rv;
}

int main(void) {
	CK_FUNCTION_LIST module = {0};
	module.C_GetTokenInfo = info;
	module.C_Login = login;
	pkcs11_session      s = {.module = &module, .handle = 42, .open = true};
	const unsigned char pin[] = "1234";
	CK_RV               rv = CKR_OK;
	CHECK(pkcs11_session_login(&s, pin, 4, &rv) == LIBSSIG_OK);
	CHECK(rv == CKR_OK && calls == 1 && !memcmp(pin, "1234", 4));
	login_rv = CKR_USER_ALREADY_LOGGED_IN;
	CHECK(pkcs11_session_login(&s, pin, 4, &rv) == LIBSSIG_OK);
	CHECK(rv == CKR_USER_ALREADY_LOGGED_IN && calls == 2);
	login_rv = CKR_PIN_INCORRECT;
	CHECK(pkcs11_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_PIN_INCORRECT && calls == 3);
	login_rv = CKR_PIN_LOCKED;
	CHECK(pkcs11_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_PIN_LOCKED && calls == 4);
	CHECK(pkcs11_session_login(&s, NULL, 0, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(pkcs11_session_login(&s, NULL, 4, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(calls == 4);
	flags = 0;
	CHECK(pkcs11_session_login(&s, NULL, 0, &rv) == LIBSSIG_OK && calls == 4);
	flags = CKF_LOGIN_REQUIRED | CKF_PROTECTED_AUTHENTICATION_PATH;
	protected_path = true;
	login_rv = CKR_OK;
	CHECK(pkcs11_session_login(&s, NULL, 0, &rv) == LIBSSIG_OK && calls == 5);
	info_rv = CKR_TOKEN_NOT_PRESENT;
	CHECK(pkcs11_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_TOKEN_NOT_PRESENT && calls == 5);
	s.open = false;
	CHECK(pkcs11_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(pkcs11_session_login(NULL, pin, 4, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(pkcs11_session_login(&s, pin, 4, NULL) == LIBSSIG_ERROR_ARGUMENT);
	return 0;
}
