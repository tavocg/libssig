# SPDX-License-Identifier: GPL-3.0-or-later
# Use the C API without libqpdf.pc's C++-only compiler flags.
find_path(QPDF_INCLUDE_DIR NAMES qpdf/qpdf-c.h)
find_library(QPDF_LIBRARY NAMES qpdf)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibssigQPDF
    REQUIRED_VARS QPDF_INCLUDE_DIR QPDF_LIBRARY)
if(LibssigQPDF_FOUND AND NOT TARGET LibssigQPDF::LibssigQPDF)
    add_library(LibssigQPDF::LibssigQPDF UNKNOWN IMPORTED)
    set_target_properties(LibssigQPDF::LibssigQPDF PROPERTIES
        IMPORTED_LOCATION "${QPDF_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${QPDF_INCLUDE_DIR}")
endif()
mark_as_advanced(QPDF_INCLUDE_DIR QPDF_LIBRARY)
