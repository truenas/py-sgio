# cython: language_level=3, c_string_type=unicode, c_string_encoding=default
from enum import IntEnum
from os import strerror

from pxd cimport libsgio, scsi

from posix.ioctl cimport ioctl
from posix.fcntl cimport open, O_RDONLY
from posix.unistd cimport close
from libc.stdlib cimport calloc, free
from libc.string cimport memset
from libc.errno cimport errno


class SCSIErrorException(Exception):
    def __init__(self, message, sense_data, *args):
        self.message = message
        self.sense_data = sense_data
        super(SCSIErrorException, self).__init__(message, sense_data, *args)


class SCSI_OPCODES(IntEnum):
    # as defined in SAM-6 spec at t10.org
    GOOD = 0x0
    CHECK_CONDITION = 0x02
    CONDITION_MET = 0x04
    BUSY = 0x08
    OBSOLETE1 = 0x10
    OBSOLETE2 = 0x14
    RESERVATION_CONFLICT = 0x18
    OBSOLETE3 = 0x22
    TASK_SET_FULL = 0x28
    ACA_ACTIVE = 0x30
    TASK_ABORTED = 0x40
    UNKNOWN = 0xff  # our own code


cdef class SCSIDevice(object):

    cdef const char* device
    cdef int dev_fd
    cdef libsgio.sg_io_hdr_t io

    def __cinit__(self, device):

        self.device = device
        self.dev_fd = -1

        # open the device
        with nogil:
            self.dev_fd = open(self.device, O_RDONLY)
            if self.dev_fd == -1:
                raise OSError(errno, strerror(errno), self.device)

    def __dealloc__(self):
        with nogil:
            if self.dev_fd >= 0:
                close(self.dev_fd)

    cdef int issue_io(self, unsigned char *cdb, unsigned char cdb_size,
            int xfer_dir, unsigned char *data, unsigned int *data_size,
            unsigned char *sense, unsigned int *sense_len) except -1:

        with nogil:
            memset(&self.io, 0, sizeof(libsgio.sg_io_hdr_t))

        self.io.interface_id = b'S'
        self.io.cmdp = cdb
        self.io.cmd_len = cdb_size
        self.io.sbp = sense
        self.io.mx_sb_len = sense_len[0]
        self.io.dxfer_direction = xfer_dir
        self.io.dxferp = data
        self.io.dxfer_len = data_size[0]
        self.io.timeout = 5000  # milliseconds (5 seconds)

        # set the sense_len back to 0 since it will get set
        # to > 0 if the issued ioctl cmd returned sense
        # data (errors)
        sense_len[0] = 0

        with nogil:
            res = ioctl(self.dev_fd, libsgio.SG_IO, &self.io)
            if res < 0:
                raise OSError(res, strerror(res))

        cdef int check_sense_data = 0
        if (self.io.info & libsgio.SG_INFO_OK_MASK) != libsgio.SG_INFO_OK:
            check_sense_data = 1
            if self.io.sb_len_wr > 0:
                # set sense_len if error occurred
                sense_len[0] = self.io.sb_len_wr

        return check_sense_data

    cdef format_sense_data(self, unsigned char *sense, unsigned int sense_len):
        return {
            'device_status': self.io.status,
            'driver_status': self.io.driver_status,
            'transport_status': self.io.host_status,
            'response_len': self.io.sb_len_wr,
            'duration': self.io.duration,
            'din_resid': self.io.resid,
            'raw_sense_buffer': [sense[i] for i in range(sense_len)],
        }

    def raise_error(self, sense_data):
        error_name = SCSI_OPCODES.UNKNOWN.name
        for error in filter(lambda x: x.value == sense_data['device_status'], SCSI_OPCODES):
            error_name = error.name

        raise SCSIErrorException(error_name, sense_data)

    def read_keys(self):
        """Read the registered keys on the disk"""
        cdef unsigned char[10] cdb = [scsi.PERSISTENT_RESERVE_IN, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 0x00ff
        cdef unsigned char[0x00ff] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef unsigned int sa = 0
        cdef int res
        cdef int i
        cdef unsigned long prgen
        cdef unsigned long add_len

        cdb[1] = sa
        cdb[7] = (data_size >> 8) & 0xff
        cdb[8] = data_size & 0xff

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_FROM_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

        # prgeneration
        prgen = data[0]
        prgen = prgen << 8
        prgen = prgen | data[1]
        prgen = prgen << 8
        prgen = prgen | data[2]
        prgen = prgen << 8
        prgen = prgen | data[3]

        # the keys
        add_len = data[4]
        add_len = add_len << 8
        add_len = add_len | data[5]
        add_len = add_len << 8
        add_len = add_len | data[6]
        add_len = add_len << 8
        add_len = add_len | data[7]

        # number of keys on disk
        entries = int(add_len / 8)

        keys = []
        for i in range(0, <int>add_len, 8):
            key = []
            for j in range(8, 16):
                key.append(data[i + j])
            keys.append(int(bytes(key).hex(), 16))

        return {
            'generation': prgen,
            'entries': entries,
            'keys': keys,
        }

    def read_reservation(self):
        """Read the persistent reservation key on the disk"""
        cdef unsigned char[10] cdb = [scsi.PERSISTENT_RESERVE_IN, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 0x00ff
        cdef unsigned char[0x00ff] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef unsigned int sa = 1
        cdef int res
        cdef unsigned long prgen
        cdef unsigned long add_len

        cdb[1] = sa
        cdb[7] = (data_size >> 8) & 0xff
        cdb[8] = data_size & 0xff

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_FROM_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

        # prgeneration
        prgen = data[0]
        prgen = prgen << 8
        prgen = prgen | data[1]
        prgen = prgen << 8
        prgen = prgen | data[2]
        prgen = prgen << 8
        prgen = prgen | data[3]
        
        # the reservation key
        add_len = data[4]
        add_len = add_len << 8
        add_len = add_len | data[5]
        add_len = add_len << 8
        add_len = add_len | data[6]
        add_len = add_len << 8
        add_len = add_len | data[7]

        # number of resv keys on disk
        entries = int(add_len / 16)

        scope = type = resv_key = None
        if add_len == 16:
            resv_key = []
            for i in range(8, 16):
                resv_key.append(data[i])
            resv_key = int(bytes(resv_key).hex(), 16)

        if resv_key:
            scope = data[21] >> 4
            type = data[21] & 0x0f

        return {
            'generation': prgen,
            'entries': entries,
            'reservation': resv_key,
            'scope': scope,
            'type': type,
        }
    
    def update_key(self, cur_key, new_key):
        """
        If `cur_key` currently holds the reservation then the reservation key will be
        updated to the `new_key`
        """
        cdef unsigned char[10] cdb = [scsi.PERSISTENT_RESERVE_OUT, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 24
        cdef unsigned char[24] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef unsigned int sa = 0
        cdef int res

        cdb[1] = sa
        cdb[2] = (0 << 4) | 1  # scope = 0, type = 1
        cdb[7] = (data_size >> 8) & 0xff
        cdb[8] = data_size & 0xff

        with nogil:
            memset(data, 0, data_size)

        # cur_key
        pos = 56
        for i in range(0, 8):
            if pos == 0:
                data[i] = cur_key & 0xff
            else:
                data[i] = (cur_key >> pos) & 0xff
            pos -= 8

        # new_key
        pos = 56
        for i in range(8, 16):
            if pos == 0:
                data[i] = new_key & 0xff
            else:
                data[i] = (new_key >> pos) & 0xff
            pos -= 8

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_TO_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

    def register_new_key(self, key):
        """Register a new key to the disk."""
        cdef unsigned char[10] cdb = [scsi.PERSISTENT_RESERVE_OUT, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 24
        cdef unsigned char[24] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef unsigned int sa = 0
        cdef int res

        cdb[1] = sa
        cdb[2] = (0 << 4) | 1  # scope = 0, type = 1
        cdb[7] = (data_size >> 8) & 0xff
        cdb[8] = data_size & 0xff

        with nogil:
            memset(data, 0, data_size)

        # key
        pos = 56
        for i in range(8, 16):
            if pos == 0:
                data[i] = key & 0xff
            else:
                data[i] = (key >> pos) & 0xff
            pos -= 8

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_TO_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

    def register_ignore_key(self, key):
        """
        Regsiters a `key` to a disk ignoring any keys that already exist that are owned by this host.
        """
        cdef unsigned char[10] cdb = [scsi.PERSISTENT_RESERVE_OUT, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 24
        cdef unsigned char[24] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef unsigned int sa = 6
        cdef int res

        cdb[1] = sa
        cdb[2] = (0 << 4) | 1  # scope = 0, type = 1
        cdb[7] = (data_size >> 8) & 0xff
        cdb[8] = data_size & 0xff

        with nogil:
            memset(data, 0, data_size)

        # key to be registered
        pos = 56
        for i in range(8, 16):
            if pos == 0:
                data[i] = key & 0xff
            else:
                data[i] = (key >> pos) & 0xff
            pos -= 8

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_TO_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

    def reserve_key(self, key):
        """Reserves the disk (WR_EXCLUSIVE) using `key`."""
        cdef unsigned char[10] cdb = [scsi.PERSISTENT_RESERVE_OUT, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 24
        cdef unsigned char[24] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef unsigned int sa = 1
        cdef int res

        cdb[1] = sa
        cdb[2] = (0 << 4) | 1  # scope = 0, type = 1
        cdb[7] = (data_size >> 8) & 0xff
        cdb[8] = data_size & 0xff

        with nogil:
            memset(data, 0, data_size)

        # reservation key
        pos = 56
        for i in range(0, 8):
            if pos == 0:
                data[i] = key & 0xff
            else:
                data[i] = (key >> pos) & 0xff
            pos -= 8

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_TO_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

    def preempt_key(self, cur_key, new_key):
        """
        Preempts an existing `cur_key` that is reserving the disk and places a new reservation on the
        disk via `new_key`
        """
        cdef unsigned char[10] cdb = [scsi.PERSISTENT_RESERVE_OUT, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 24
        cdef unsigned char[24] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef unsigned int sa = 4
        cdef int res

        cdb[1] = sa
        cdb[2] = (0 << 4) | 1  # scope = 0, type = 1
        cdb[7] = (data_size >> 8) & 0xff
        cdb[8] = data_size & 0xff

        with nogil:
            memset(data, 0, data_size)

        # new_key
        pos = 56
        for i in range(0, 8):
            if pos == 0:
                data[i] = new_key & 0xff
            else:
                data[i] = (new_key >> pos) & 0xff
            pos -= 8

        # cur_key
        pos = 56
        for i in range(8, 16):
            if pos == 0:
                data[i] = cur_key & 0xff
            else:
                data[i] = (cur_key >> pos) & 0xff
            pos -= 8

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_TO_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

    def serial(self):
        """Request serial number"""
        cdef unsigned char[6] cdb = [scsi.INQUIRY, 0x01, 0x80, 0, 0, 0]
        cdef unsigned int data_size = 0x00ff
        cdef unsigned char[0x00ff] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef int pagelen

        cdb[3] = (data_size >> 8) & 0xff
        cdb[4] = data_size & 0xff

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_FROM_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

        # page length
        pagelen = data[3]

        serial = []
        for i in range(4, pagelen + 4):
            serial.append(data[i])

        serial = bytearray(serial)

        return serial.decode().strip().replace('\x00', '')

    def rotation_rate(self):
        """Request rotational rate"""
        cdef unsigned char[8] cdb = [scsi.INQUIRY, 0x01, 0xb1, 0, 0, 0, 0, 0]
        cdef unsigned int data_size = 0x00ff
        cdef unsigned char[0x00ff] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense

        cdb[3] = (data_size >> 8) & 0xff
        cdb[4] = data_size & 0xff

        check_sense_data = self.issue_io(
            cdb,
            sizeof(cdb),
            libsgio.SG_DXFER_FROM_DEV,
            data,
            &data_size,
            sense,
            &sense_len,
        )

        # handle errors
        if any((check_sense_data, sense_len)):
            self.raise_error(self.format_sense_data(sense, sense_len))

        return int(f'0x{data[4]:02x}{data[5]:02x}', 16)
