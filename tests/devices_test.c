/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <p11-kit/p11-kit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(value)                                                           \
	do {                                                                       \
		if (!(value)) {                                                        \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value);        \
			abort();                                                           \
		}                                                                      \
	} while (0)
static void phase(const char* path, char value) {
	FILE* file = fopen(path, "w");
	CHECK(file);
	CHECK(fputc(value, file) != EOF);
	CHECK(fclose(file) == 0);
}
int main(int argc, char** argv) {
	CHECK(argc == 4);
	phase(argv[2], '0');
	FILE* log = fopen(argv[3], "w");
	CHECK(log);
	fclose(log);
	libssig_context     context = {0};
	const char*         paths[] = {argv[1], argv[1]};
	libssig_string_list modules = {.items = paths, .count = 2};
	CHECK(libssig_context_open_modules(&context, &modules) == LIBSSIG_OK);
	libssig_device_list devices = {0};
	CHECK(libssig_devices(NULL, &devices, 0) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_devices(&context, &devices, 2) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_devices(&context, &devices, 0) == LIBSSIG_OK);
	CHECK(devices.count == 1 && devices.items[0].slot_count == 3);
	libssig_device_slot* slot = &devices.items[0].slots[0];
	CHECK(
	    slot->token_valid && slot->token_present && slot->status == LIBSSIG_OK
	);
	CHECK(strcmp(slot->description, "USB fixture <&>") == 0);
	CHECK(slot->certificates.count == 2 && slot->key_count == 4);
	CHECK(slot->certificates.items[0].public_key_bits == 2048);
	CHECK(
	    slot->certificates.items[1].metadata_status ==
	    LIBSSIG_CERTIFICATE_METADATA_INVALID
	);
	CHECK(slot->certificates.items[1].public_key_bits == 0);
	CHECK(slot->keys[0].bits == 3072 && slot->keys[1].bits == 256);
	CHECK(
	    slot->keys[2].object_class == CKO_PRIVATE_KEY &&
	    slot->keys[2].bits == 2048 && slot->keys[2].size_from_certificate
	);
	CHECK(
	    slot->keys[3].object_class == CKO_SECRET_KEY &&
	    slot->keys[3].bits == 256
	);
	CHECK(!devices.items[0].slots[1].token_present);
	CHECK(devices.items[0].slots[2].status == LIBSSIG_ERROR_PKCS11);
	CHECK(devices.items[0].slots[2].ck_rv == CKR_DEVICE_ERROR);
	CHECK(libssig_devices(&context, &devices, 0) == LIBSSIG_ERROR_ARGUMENT);
	char events[512] = {0};
	log = fopen(argv[3], "r");
	CHECK(log);
	CHECK(fread(events, 1, sizeof(events) - 1, log) > 0);
	fclose(log);
	CHECK(!strstr(events, "software-session"));
	libssig_devices_free(&devices);
	CHECK(!devices.items && !devices.count);
	CHECK(
	    libssig_devices(&context, &devices, LIBSSIG_DEVICES_ALL) == LIBSSIG_OK
	);
	CHECK(
	    devices.items[0].slot_count == 4 &&
	    devices.items[0].slots[3].certificates.count == 2
	);
	libssig_devices_free(&devices);
	libssig_device_state state = {0};
	bool                 changed = false;
	CHECK(
	    libssig_devices_changed(&context, &state, &changed, 0) == LIBSSIG_OK &&
	    changed
	);
	CHECK(
	    libssig_devices_changed(&context, &state, &changed, 0) == LIBSSIG_OK &&
	    !changed
	);
	phase(argv[2], '2');
	CHECK(
	    libssig_devices_changed(&context, &state, &changed, 0) == LIBSSIG_OK &&
	    changed
	);
	CHECK(libssig_devices(&context, &devices, 0) == LIBSSIG_OK);
	CHECK(strcmp(devices.items[0].slots[0].token.serial, "card-two") == 0);
	libssig_devices_free(&devices);
	phase(argv[2], '1');
	CHECK(
	    libssig_devices_changed(&context, &state, &changed, 0) == LIBSSIG_OK &&
	    changed
	);
	CHECK(libssig_devices(&context, &devices, 0) == LIBSSIG_OK);
	CHECK(
	    !devices.items[0].slots[0].token_present &&
	    !devices.items[0].slots[0].certificates.count
	);
	libssig_devices_free(&devices);
	phase(argv[2], '3');
	CHECK(
	    libssig_devices_changed(&context, &state, &changed, 0) == LIBSSIG_OK &&
	    changed
	);
	CHECK(
	    libssig_devices(&context, &devices, 0) == LIBSSIG_OK &&
	    !devices.items[0].slot_count
	);
	libssig_devices_free(&devices);
	phase(argv[2], '0');
	CHECK(
	    libssig_devices_changed(&context, &state, &changed, 0) == LIBSSIG_OK &&
	    changed
	);
	CHECK(libssig_devices(&context, &devices, 0) == LIBSSIG_OK);
	libssig_context_close(&context);
	CHECK(strcmp(devices.items[0].slots[0].token.serial, "card-one") == 0);
	libssig_devices_free(&devices);
	libssig_devices_free(&devices);
	libssig_devices_free(NULL);
	remove(argv[2]);
	remove(argv[3]);
	return 0;
}
