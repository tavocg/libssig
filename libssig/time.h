/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TIME_H
#define LIBSSIG_TIME_H

#include <libssig/types.h>
#include <openssl/asn1.h>
#include <time.h>

bool libssig_time_read(const ASN1_TIME* value, time_t* out_time);
bool libssig_verify_time_parse(const char value[21], time_t* out_time);

#endif
