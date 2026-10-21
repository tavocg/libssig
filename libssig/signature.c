/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/types.h>
#include <stdlib.h>

void libssig_signature_free(libssig_signature* signature) {
	if (!signature) {
		return;
	}

	free(signature->data);
	*signature = (libssig_signature){0};
}
