# SPDX-License-Identifier: GPL-3.0-or-later
include(CheckCSourceCompiles)

function(libssig_openssl_compat target)
    set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto)
    set(CMAKE_REQUIRED_FLAGS "-Werror")
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
