/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <stdio.h>

int main(void) {
	/* Exercise every combination of optional output pointers. */
	for (unsigned int i = 0; i < 8; ++i) {
		int major = -1, minor = -1, patch = -1;
		libssig_version(
		    i & 1 ? &major : NULL,
		    i & 2 ? &minor : NULL,
		    i & 4 ? &patch : NULL
		);
		if (major != (i & 1 ? LIBSSIG_VERSION_MAJOR : -1) ||
		    minor != (i & 2 ? LIBSSIG_VERSION_MINOR : -1) ||
		    patch != (i & 4 ? LIBSSIG_VERSION_PATCH : -1)) {
			fprintf(
			    stderr,
			    "Unexpected library version outputs (mask %u)\n",
			    i
			);
			return 1;
		}
	}
	return 0;
}
