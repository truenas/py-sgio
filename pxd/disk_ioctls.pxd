# cython: language_level=3, c_string_type=unicode, c_string_encoding=default


cdef extern from "linux/fs.h":
    cdef enum:
        BLKRRPART
        BLKFLSBUF
