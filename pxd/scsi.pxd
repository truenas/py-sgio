# cython: language_level=3, c_string_type=unicode, c_string_encoding=default


cdef extern from "scsi/scsi.h":
    cdef enum:
        # opcodes
        INQUIRY
        PERSISTENT_RESERVE_IN
        PERSISTENT_RESERVE_OUT
