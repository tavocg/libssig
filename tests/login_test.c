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

static CK_FLAGS     token_flags = CKF_LOGIN_REQUIRED;
static CK_RV        info_rv = CKR_OK;
static CK_RV        login_rv = CKR_OK;
static unsigned int login_count;
static bool         protected_path;

static CK_RV mock_token_info_get(
    CK_SLOT_ID        slot,
    CK_TOKEN_INFO_PTR out_token_info
) {
	(void)slot;
	memset(out_token_info, 0, sizeof(*out_token_info));
	out_token_info->flags = token_flags;
	return info_rv;
}

static CK_RV mock_session_login(
    CK_SESSION_HANDLE handle,
    CK_USER_TYPE      user,
    CK_UTF8CHAR_PTR   pin,
    CK_ULONG          pin_len
) {
	++login_count;
	if (handle != 42 || user != CKU_USER) {
		return CKR_ARGUMENTS_BAD;
	}

	if (protected_path) {
		if (pin || pin_len) {
			return CKR_ARGUMENTS_BAD;
		}
	} else if (!pin || pin_len != 4 || memcmp(pin, "1234", 4)) {
		return CKR_ARGUMENTS_BAD;
	}
	return login_rv;
}

int main(void) {
	CK_FUNCTION_LIST module = {0};
	module.C_GetTokenInfo = mock_token_info_get;
	module.C_Login = mock_session_login;
	libssig_session     s = {.module = &module, .handle = 42, .open = true};
	const unsigned char pin[] = "1234";
	CK_RV               rv = CKR_OK;
	CHECK(libssig_session_login(&s, pin, 4, &rv) == LIBSSIG_OK);
	CHECK(rv == CKR_OK && login_count == 1 && !memcmp(pin, "1234", 4));

	login_rv = CKR_USER_ALREADY_LOGGED_IN;
	CHECK(libssig_session_login(&s, pin, 4, &rv) == LIBSSIG_OK);
	CHECK(rv == CKR_USER_ALREADY_LOGGED_IN && login_count == 2);

	login_rv = CKR_PIN_INCORRECT;
	CHECK(libssig_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_PIN_INCORRECT && login_count == 3);

	login_rv = CKR_PIN_LOCKED;
	CHECK(libssig_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_PIN_LOCKED && login_count == 4);
	CHECK(libssig_session_login(&s, NULL, 0, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_session_login(&s, NULL, 4, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(login_count == 4);
	token_flags = 0;
	CHECK(
	    libssig_session_login(&s, NULL, 0, &rv) == LIBSSIG_OK &&
	    login_count == 4
	);
	token_flags = CKF_LOGIN_REQUIRED | CKF_PROTECTED_AUTHENTICATION_PATH;
	protected_path = true;
	login_rv = CKR_OK;
	CHECK(
	    libssig_session_login(&s, NULL, 0, &rv) == LIBSSIG_OK &&
	    login_count == 5
	);

	info_rv = CKR_TOKEN_NOT_PRESENT;
	CHECK(libssig_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_TOKEN_NOT_PRESENT && login_count == 5);
	s.open = false;
	CHECK(libssig_session_login(&s, pin, 4, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_session_login(NULL, pin, 4, &rv) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_session_login(&s, pin, 4, NULL) == LIBSSIG_ERROR_ARGUMENT);
	return 0;
}
