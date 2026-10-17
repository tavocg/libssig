// Package ssig provides Go bindings for libssig.
package ssig

/*
#cgo CFLAGS: -I${SRCDIR}/../..
#cgo LDFLAGS: -lssig
#include <libssig/libssig.h>
*/
import "C"

// Version returns the major, minor, and patch version of the loaded library.
func Version() (major, minor, patch int) {
	var cMajor, cMinor, cPatch C.int
	C.libssig_version(&cMajor, &cMinor, &cPatch)
	return int(cMajor), int(cMinor), int(cPatch)
}
