/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>

int main(void) {
  int major = -1;
  libssig_version(&major, NULL, NULL);
  /* Pull signing, verification and PKCS#11 dependencies into static links
   * without accessing a real token or any user configuration. */
  libssig_context_close(NULL);
  if (libssig_sign(NULL, NULL, NULL) != LIBSSIG_ERROR_ARGUMENT ||
      libssig_verify(NULL, NULL) != LIBSSIG_ERROR_ARGUMENT) {
    return 1;
  }
  return major != LIBSSIG_VERSION_MAJOR;
}
