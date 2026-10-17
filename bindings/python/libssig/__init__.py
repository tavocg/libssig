"""Bindings for the native libssig library (installed separately)."""

import ctypes
import ctypes.util
import os
from functools import lru_cache

__all__ = ["version"]


@lru_cache(maxsize=1)
def _library():
    path = os.environ.get("LIBSSIG_LIBRARY") or ctypes.util.find_library("ssig")
    if not path:
        raise OSError(
            "libssig was not found; install the native library or set "
            "LIBSSIG_LIBRARY to its shared library path"
        )
    library = ctypes.CDLL(path)
    library.libssig_version.argtypes = [ctypes.POINTER(ctypes.c_int)] * 3
    library.libssig_version.restype = None
    return library


def version() -> tuple[int, int, int]:
    """Return the major, minor, and patch version of the loaded library."""
    major, minor, patch = ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
    _library().libssig_version(
        ctypes.byref(major), ctypes.byref(minor), ctypes.byref(patch)
    )
    return major.value, minor.value, patch.value
