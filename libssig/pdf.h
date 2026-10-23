/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_PDF_H
#define LIBSSIG_PDF_H

#include <libssig/ades.h>
#include <libssig/tsa.h>
#include <qpdf/qpdf-c.h>

typedef struct {
	qpdf_data pdf;
	qpdf_oh   root;
	BIO*      bytes;
	size_t    previous;
	int       first, next;
	size_t    offsets[2048];
	size_t    range_offset, content_start, content_end;
	int       field_id, signature_id;
	struct {
		int    id, generation;
		size_t offset;
	} updates[16];
	size_t update_count;
} libssig_pdf_revision;
libssig_status libssig_pdf_open(
    const unsigned char*  data,
    size_t                len,
    libssig_pdf_revision* revision
);
void libssig_pdf_close(libssig_pdf_revision* revision);
int  libssig_pdf_object(libssig_pdf_revision* revision, const char* value);
int  libssig_pdf_stream(
     libssig_pdf_revision* revision,
     const unsigned char*  data,
     size_t                len
 );
int libssig_pdf_stream_dict(
    libssig_pdf_revision* revision,
    const char*           dictionary,
    const unsigned char*  data,
    size_t                len
);
bool libssig_pdf_update(
    libssig_pdf_revision* revision,
    qpdf_oh               object,
    const char*           value
);
libssig_status libssig_pdf_appearance_apply(
    libssig_pdf_revision*         revision,
    const libssig_pdf_appearance* appearance
);
libssig_status libssig_pdf_slot(
    libssig_pdf_revision* revision,
    bool                  timestamp,
    bool                  visible
);
libssig_status libssig_pdf_finish(
    libssig_pdf_revision* revision,
    libssig_signature*    output
);
libssig_status libssig_pdf_content(
    libssig_pdf_revision* revision,
    libssig_signature*    output
);
libssig_status libssig_pdf_insert(
    libssig_pdf_revision*    revision,
    const libssig_signature* token,
    libssig_signature*       output
);
libssig_status libssig_pades_v121_finish(
    const libssig_sign_params* params,
    CMS_ContentInfo*           cms,
    libssig_signature*         output
);
libssig_status libssig_pdf_dss(
    libssig_pdf_revision*          revision,
    const libssig_validation_data* data
);
typedef struct {
	libssig_signature cms, content;
	size_t            end, hole_start, hole_end;
	bool              timestamp;
} libssig_pdf_signature;

libssig_status libssig_pdf_signature_read(
    qpdf_data                    pdf,
    qpdf_oh                      dict,
    const libssig_verify_params* params,
    libssig_pdf_signature*       signature
);

libssig_status libssig_pdf_archive(
    const libssig_sign_params* params,
    libssig_signature*         output
);
#endif
