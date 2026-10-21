/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/document.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

bool libssig_bytes_append(
    libssig_signature* bytes,
    const void*        data,
    size_t             len
) {
	if ((len && !data) || len > LIBSSIG_DOCUMENT_LIMIT ||
	    bytes->len > LIBSSIG_DOCUMENT_LIMIT - len) {
		return false;
	}
	if (!len) {
		return true;
	}
	unsigned char* grown = realloc(bytes->data, bytes->len + len + 1);
	if (!grown) {
		return false;
	}
	bytes->data = grown;
	memcpy(grown + bytes->len, data, len);
	bytes->len += len;
	grown[bytes->len] = 0;
	return true;
}
char* libssig_base64(const void* data, size_t len, bool url) {
	if (len > LIBSSIG_DOCUMENT_LIMIT || (len && !data)) {
		return NULL;
	}
	size_t size = 4 * ((len + 2) / 3);
	char*  text = malloc(size + 1);
	if (!text) {
		return NULL;
	}
	EVP_EncodeBlock(
	    (unsigned char*)text,
	    len ? data : (const unsigned char*)"",
	    (int)len
	);
	if (url) {
		for (size_t i = 0; i < size; ++i) {
			if (text[i] == '+') {
				text[i] = '-';
			} else if (text[i] == '/') {
				text[i] = '_';
			}
		}
		while (size && text[size - 1] == '=') {
			text[--size] = 0;
		}
	}
	return text;
}
bool libssig_base64_read(
    const char*        text,
    size_t             len,
    bool               url,
    libssig_signature* bytes
) {
	if (!text || len > LIBSSIG_DOCUMENT_LIMIT || (url && len % 4 == 1) ||
	    (!url && len % 4)) {
		return false;
	}
	size_t         padded = (len + 3) / 4 * 4;
	unsigned char* buffer = malloc(padded + 1);
	unsigned char* decoded = malloc(padded / 4 * 3 + 1);
	if (!buffer || !decoded) {
		free(buffer);
		free(decoded);
		return false;
	}
	bool valid = true;
	for (size_t i = 0; i < len; ++i) {
		unsigned char c = (unsigned char)text[i];
		bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		             (c >= '0' && c <= '9');
		if (!alpha && c != (url ? '-' : '+') && c != (url ? '_' : '/') &&
		    (url || c != '=' || i + 2 < len)) {
			valid = false;
		}
		buffer[i] = c == '-' && url ? '+' : c == '_' && url ? '/' : c;
	}
	for (size_t i = len; i < padded; ++i) {
		buffer[i] = '=';
	}
	buffer[padded] = 0;
	int    count = valid ? EVP_DecodeBlock(decoded, buffer, (int)padded) : -1;
	size_t padding = padded - len;
	if (!url) {
		if (len && text[len - 1] == '=') {
			++padding;
		}
		if (len > 1 && text[len - 2] == '=') {
			++padding;
		}
	}
	valid = count >= 0 && (size_t)count >= padding;
	size_t size = valid ? (size_t)count - padding : 0;
	char*  canonical = valid ? libssig_base64(decoded, size, url) : NULL;
	valid = canonical && strlen(canonical) == len &&
	        !memcmp(canonical, text, len);
	if (valid) {
		bytes->data = decoded;
		bytes->len = size;
		decoded = NULL;
	}
	free(canonical);
	free(buffer);
	free(decoded);
	return valid;
}
bool libssig_document_digest(
    const void*    data,
    size_t         len,
    libssig_hash   hash,
    unsigned char* digest,
    unsigned int*  out_len
) {
	const EVP_MD* md = libssig_timestamp_digest(hash);
	return md && EVP_Digest(data, len, digest, out_len, md, NULL) == 1;
}
libssig_format libssig_document_format(const unsigned char* data, size_t len) {
	size_t i = 0;
	while (i < len && (data[i] == ' ' || data[i] == '\n' || data[i] == '\r' ||
	                   data[i] == '\t')) {
		++i;
	}
	if (i < len && data[i] == '{') {
		return LIBSSIG_FORMAT_JADES;
	}
	if (i < len && data[i] == '<') {
		return LIBSSIG_FORMAT_XADES;
	}
	if (len >= 5 && !memcmp(data, "%PDF-", 5)) {
		return LIBSSIG_FORMAT_PADES;
	}
	return LIBSSIG_FORMAT_CADES;
}
