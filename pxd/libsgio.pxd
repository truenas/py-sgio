# cython: language_level=3, c_string_type=unicode, c_string_encoding=default


cdef extern from "scsi/sg.h":
    cdef enum:
        SG_IO
        SG_GET_VERSION_NUM

    cdef enum:
        SG_DXFER_NONE
        SG_DXFER_TO_DEV
        SG_DXFER_FROM_DEV
        SG_DXFER_TO_FROM_DEV

    cdef enum:
        SG_INFO_OK_MASK
        SG_INFO_OK

    ctypedef struct sg_io_hdr_t:
        int interface_id
        int dxfer_direction
        unsigned char cmd_len
        unsigned char mx_sb_len
        unsigned short int iovec_count
        unsigned int dxfer_len
        unsigned char * dxferp
        unsigned char * cmdp
        unsigned char * sbp
        unsigned int timeout
        unsigned int flags
        int pack_id
        void * usr_ptr
        unsigned char status
        unsigned char masked_status
        unsigned char msg_status
        unsigned char sb_len_wr
        unsigned short int host_status
        unsigned short int driver_status
        int resid
        unsigned int duration
        unsigned int info
