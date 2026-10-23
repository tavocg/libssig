# SPDX-License-Identifier: GPL-3.0-or-later
include(CheckCSourceCompiles)

function(libssig_openssl_compat target)
    # Inspect the header ABI without linking Homebrew libraries against a
    # potentially older deployment target during this compile-only check.
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
    set(CMAKE_REQUIRED_FLAGS "-Werror=incompatible-pointer-types")
    check_c_source_compiles("
        #include <openssl/x509_vfy.h>
        static int issuer(X509 **out, X509_STORE_CTX *ctx, const X509 *cert) {
            (void)out; (void)ctx; (void)cert; return 0;
        }
        int main(void) {
            X509_STORE_CTX_get_issuer_fn callback = issuer;
            return callback == 0;
        }" LIBSSIG_OPENSSL_CONST_ISSUER)
    if(LIBSSIG_OPENSSL_CONST_ISSUER)
        target_compile_definitions(${target} PRIVATE LIBSSIG_OPENSSL_CONST_ISSUER)
    endif()
endfunction()
