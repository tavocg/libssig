/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/pdf.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static qpdf_oh inherited(qpdf_data pdf, qpdf_oh page, const char* key) {
	for (int depth = 0; depth < 64 && qpdf_oh_is_dictionary(pdf, page);
	     ++depth) {
		qpdf_oh value = qpdf_oh_get_key(pdf, page, key);
		if (!qpdf_oh_is_null(pdf, value)) {
			return value;
		}
		page = qpdf_oh_get_key(pdf, page, "/Parent");
	}
	return qpdf_oh_new_null(pdf);
}
static bool box(qpdf_data pdf, qpdf_oh value, double out[4]) {
	if (!qpdf_oh_is_array(pdf, value) ||
	    qpdf_oh_get_array_n_items(pdf, value) != 4) {
		return false;
	}
	for (int i = 0; i < 4; ++i) {
		qpdf_oh number = qpdf_oh_get_array_item(pdf, value, i);
		if (!qpdf_oh_is_number(pdf, number)) {
			return false;
		}
		out[i] = qpdf_oh_get_numeric_value(pdf, number);
		if (!isfinite(out[i]) || fabs(out[i]) > 1e7) {
			return false;
		}
	}
	return out[2] > out[0] && out[3] > out[1];
}
static void number(qpdf_data pdf, double value, char out[64]) {
	snprintf(
	    out,
	    64,
	    "%s",
	    qpdf_oh_unparse(pdf, qpdf_oh_new_real_from_double(pdf, value, 6))
	);
}
static bool layout(
    qpdf_data                     pdf,
    qpdf_oh                       page,
    const libssig_pdf_appearance* a,
    double                        rect[4],
    double                        matrix[6]
) {
	double media[4], crop[4];
	if (!box(pdf, inherited(pdf, page, "/MediaBox"), media)) {
		return false;
	}
	qpdf_oh value = inherited(pdf, page, "/CropBox");
	if (qpdf_oh_is_null(pdf, value)) {
		memcpy(crop, media, sizeof(crop));
	} else if (!box(pdf, value, crop)) {
		return false;
	}
	if (crop[0] < media[0]) {
		crop[0] = media[0];
	}
	if (crop[1] < media[1]) {
		crop[1] = media[1];
	}
	if (crop[2] > media[2]) {
		crop[2] = media[2];
	}
	if (crop[3] > media[3]) {
		crop[3] = media[3];
	}
	if (crop[2] <= crop[0] || crop[3] <= crop[1]) {
		return false;
	}
	value = inherited(pdf, page, "/Rotate");
	long long rotation = 0;
	if (!qpdf_oh_is_null(pdf, value)) {
		if (!qpdf_oh_is_integer(pdf, value)) {
			return false;
		}
		rotation = qpdf_oh_get_int_value(pdf, value);
		if (rotation % 90) {
			return false;
		}
		rotation = (rotation % 360 + 360) % 360;
	}
	double unit = 1;
	value = qpdf_oh_get_key(pdf, page, "/UserUnit");
	if (!qpdf_oh_is_null(pdf, value)) {
		if (!qpdf_oh_is_number(pdf, value)) {
			return false;
		}
		unit = qpdf_oh_get_numeric_value(pdf, value);
		if (!isfinite(unit) || unit <= 0 || unit > 75000) {
			return false;
		}
	}
	double pw = crop[2] - crop[0], ph = crop[3] - crop[1];
	double x = a->x / unit, y = a->y / unit;
	double w = a->width / unit, h = a->height / unit;
	double vw = rotation % 180 ? ph : pw, vh = rotation % 180 ? pw : ph;
	if (x + w > vw + 1e-7 || y + h > vh + 1e-7) {
		return false;
	}
	if (rotation == 90) {
		double r[] =
		    {crop[0] + y, crop[1] + x, crop[0] + y + h, crop[1] + x + w};
		double m[] = {0, w, -h, 0, h, 0};
		memcpy(rect, r, sizeof(r));
		memcpy(matrix, m, sizeof(m));
	} else if (rotation == 180) {
		double r[] =
		    {crop[2] - x - w, crop[1] + y, crop[2] - x, crop[1] + y + h};
		double m[] = {-w, 0, 0, -h, w, h};
		memcpy(rect, r, sizeof(r));
		memcpy(matrix, m, sizeof(m));
	} else if (rotation == 270) {
		double r[] =
		    {crop[2] - y - h, crop[3] - x - w, crop[2] - y, crop[3] - x};
		double m[] = {0, -w, h, 0, 0, w};
		memcpy(rect, r, sizeof(r));
		memcpy(matrix, m, sizeof(m));
	} else {
		double r[] =
		    {crop[0] + x, crop[3] - y - h, crop[0] + x + w, crop[3] - y};
		double m[] = {w, 0, 0, h, 0, 0};
		memcpy(rect, r, sizeof(r));
		memcpy(matrix, m, sizeof(m));
	}
	return true;
}
static int image_stream(
    libssig_pdf_revision* r,
    const unsigned char*  bytes,
    size_t                len,
    size_t                width,
    size_t                height,
    int                   mask
) {
	uLongf         capacity = compressBound((uLong)len);
	unsigned char* compressed = malloc(capacity);
	if (!compressed) {
		return 0;
	}
	int result = 0;
	if (compress2(
	        compressed,
	        &capacity,
	        bytes,
	        (uLong)len,
	        Z_BEST_COMPRESSION
	    ) == Z_OK) {
		char dictionary[256], smask[48] = "";
		if (mask > 0) {
			snprintf(smask, sizeof(smask), "/SMask %d 0 R", mask);
		}
		snprintf(
		    dictionary,
		    sizeof(dictionary),
		    "/Type /XObject /Subtype /Image /Width %zu /Height %zu "
		    "/BitsPerComponent 8 /ColorSpace /%s /Filter /FlateDecode %s",
		    width,
		    height,
		    mask < 0 ? "DeviceGray" : "DeviceRGB",
		    smask
		);
		result = libssig_pdf_stream_dict(r, dictionary, compressed, capacity);
	}
	free(compressed);
	return result;
}
static int image(libssig_pdf_revision* r, const libssig_pdf_appearance* a) {
	size_t         count = a->pixel_width * a->pixel_height;
	unsigned char* rgb = malloc(count * 3);
	unsigned char* alpha = malloc(count);
	if (!rgb || !alpha) {
		free(rgb);
		free(alpha);
		return 0;
	}
	bool transparent = false;
	for (size_t y = 0; y < a->pixel_height; ++y) {
		for (size_t x = 0; x < a->pixel_width; ++x) {
			const unsigned char* p = a->pixels + y * a->row_stride + x * 4;
			size_t               i = y * a->pixel_width + x;
			memcpy(rgb + i * 3, p, 3);
			alpha[i] = p[3];
			transparent |= p[3] != 255;
		}
	}
	int mask = transparent ? image_stream(
	                             r,
	                             alpha,
	                             count,
	                             a->pixel_width,
	                             a->pixel_height,
	                             -1
	                         )
	                       : 0;
	int result = transparent && !mask ? 0
	                                  : image_stream(
	                                        r,
	                                        rgb,
	                                        count * 3,
	                                        a->pixel_width,
	                                        a->pixel_height,
	                                        mask
	                                    );
	free(alpha);
	free(rgb);
	return result;
}
libssig_status libssig_pdf_appearance_apply(
    libssig_pdf_revision*         r,
    const libssig_pdf_appearance* a
) {
	if (!a || !a->page_number || !a->pixels || !a->pixel_width ||
	    !a->pixel_height || a->pixel_width > 4096 || a->pixel_height > 4096 ||
	    a->row_stride < a->pixel_width * 4 ||
	    a->row_stride > SIZE_MAX / a->pixel_height || !isfinite(a->x) ||
	    !isfinite(a->y) || !isfinite(a->width) || !isfinite(a->height) ||
	    a->x < 0 || a->y < 0 || a->width <= 0 || a->height <= 0) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	int pages = qpdf_get_num_pages(r->pdf);
	if (pages < 1 || a->page_number > (unsigned int)pages) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	qpdf_oh page = qpdf_get_page_n(r->pdf, a->page_number - 1);
	double  rect[4], matrix[6];
	if (!layout(r->pdf, page, a, rect, matrix)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	int image_id = image(r, a);
	if (!image_id) {
		return LIBSSIG_ERROR_MEMORY;
	}
	char v[10][64];
	for (int i = 0; i < 6; ++i) {
		number(r->pdf, matrix[i], v[i]);
	}
	char content[512];
	int  len = snprintf(
        content,
        sizeof(content),
        "q %s %s %s %s %s %s cm /Image Do Q\n",
        v[0],
        v[1],
        v[2],
        v[3],
        v[4],
        v[5]
    );
	number(r->pdf, rect[2] - rect[0], v[0]);
	number(r->pdf, rect[3] - rect[1], v[1]);
	char dictionary[384];
	snprintf(
	    dictionary,
	    sizeof(dictionary),
	    "/Type /XObject /Subtype /Form /FormType 1 "
	    "/BBox [0 0 %s %s] /Resources << /XObject << /Image %d 0 R >> >>",
	    v[0],
	    v[1],
	    image_id
	);
	int appearance_id = libssig_pdf_stream_dict(
	    r,
	    dictionary,
	    (unsigned char*)content,
	    (size_t)len
	);
	if (!appearance_id) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	for (int i = 0; i < 4; ++i) {
		number(r->pdf, rect[i], v[i]);
	}
	char field[512];
	snprintf(
	    field,
	    sizeof(field),
	    "<< /Type /Annot /Subtype /Widget /F 4 /FT /Sig "
	    "/T (libssig-%d) /V %d 0 R /Rect [%s %s %s %s] /AP << /N %d 0 R >> /P "
	    "%d %d R >>",
	    r->signature_id,
	    r->signature_id,
	    v[0],
	    v[1],
	    v[2],
	    v[3],
	    appearance_id,
	    qpdf_oh_get_object_id(r->pdf, page),
	    qpdf_oh_get_generation(r->pdf, page)
	);
	if (!libssig_pdf_update(
	        r,
	        qpdf_get_object_by_id(r->pdf, r->field_id, 0),
	        field
	    )) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	qpdf_oh annotations = qpdf_oh_get_key(r->pdf, page, "/Annots");
	if (!qpdf_oh_is_null(r->pdf, annotations) &&
	    !qpdf_oh_is_array(r->pdf, annotations)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	qpdf_oh copy = qpdf_oh_new_array(r->pdf);
	int     n = qpdf_oh_is_null(r->pdf, annotations)
	                ? 0
	                : qpdf_oh_get_array_n_items(r->pdf, annotations);
	for (int i = 0; i < n; ++i) {
		qpdf_oh_append_item(
		    r->pdf,
		    copy,
		    qpdf_oh_get_array_item(r->pdf, annotations, i)
		);
	}
	qpdf_oh_append_item(
	    r->pdf,
	    copy,
	    qpdf_get_object_by_id(r->pdf, r->field_id, 0)
	);
	qpdf_oh_replace_key(r->pdf, page, "/Annots", copy);
	if (!libssig_pdf_update(r, page, qpdf_oh_unparse_resolved(r->pdf, page))) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	return qpdf_has_error(r->pdf) ? LIBSSIG_ERROR_FORMAT : LIBSSIG_OK;
}
