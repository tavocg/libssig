#include <libssig/libssig.h>

void libssig_version(int* major, int* minor, int* patch) {
	if (major) {
		*major = LIBSSIG_VERSION_MAJOR;
	}

	if (minor) {
		*minor = LIBSSIG_VERSION_MINOR;
	}

	if (patch) {
		*patch = LIBSSIG_VERSION_PATCH;
	}
}
