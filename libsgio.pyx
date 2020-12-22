# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

from pxd cimport libsgio

from posix.ioctl cimport ioctl
from posix.fcntl cimport open, O_RDONLY
from posix.unistd cimport close
from libc.stdlib cimport calloc, free
from libc.string cimport memset


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
                raise OSError('Failed to open device')

        with nogil:
            memset(&self.io, 0, sizeof(libsgio.sg_io_hdr_t))

    def __dealloc__(self):

        with nogil:
            if self.dev_fd >= 0:
                close(self.dev_fd)

    cdef int issue_io(self, unsigned char *cdb, unsigned char cdb_size,
            int xfer_dir, unsigned char *data, unsigned int *data_size,
            unsigned char *sense, unsigned int *sense_len):

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
            if res != 0:
                raise RuntimeError()

        # set sense_len if error occurred
        if (self.io.info & libsgio.SG_INFO_OK_MASK) != libsgio.SG_INFO_OK:
            if self.io.sb_len_wr > 0:
                sense_len[0]=self.io.sb_len_wr
                error_data = 1

    cdef format_sense_data(self, unsigned char *sense, unsigned int sense_len):

        sensetable = {
            1: 'no sense',
            2: 'recovered error',
            3: 'not ready',
            4: 'medium error',
            5: 'hardware error',
            6: 'illegal request',
            7: 'unit attention',
            8: 'data protect',
            9: 'blank check',
            10: 'vendor specific',
            11: 'copy aborted',
            12: 'aborted command',
            13: 'unknown',
            14: 'unknown',
            15: 'unknown',
            16: 'unknown',
        }

        sense_info = {}

        sense_info['status'] = '0x' + f'{self.io.status:02x}'
        sense_info['masked_status'] = '0x' + f'{self.io.masked_status:02x}'
        sense_info['host_status'] = '0x' + f'{self.io.host_status:02x}'
        sense_info['driver_status'] = '0x' + f'{self.io.driver_status:02x}'

        add_cmd = []
        if sense[0] == 0x70:
            sense_info['filemark'] = int((sense[2] & 0x80) != 0)
            sense_info['eom'] = int((sense[2] & 0x40) != 0)
            sense_info['ili'] = int((sense[2] & 0x20) != 0)
            sense_info['sense_key'] = '0x' + f'{(sense[2] & 0x0f):02x}'
            sense_info['error_msg'] = sensetable[(sense[2] & 0x0f)]

            for i in range(8, 12):
                add_cmd.append('0x' + f'{sense[i]:02x}')
            sense_info['cmd_info'] = add_cmd

            asc = ascq = None
            asc = '0x' + f'{sense[12]:02x}'
            ascq = '0x' + f'{sense[13]:02x}'
            sense_info['additional_sense_code'] = asc
            sense_info['additional_sense_code_qualifier'] = ascq
            sense_info['field_replaceable_unit_code'] = '0x' + f'{sense[14]:02x}'

            sense_info['invalid_cmd_op_code'] = False
            if asc == 0x20 and ascq == 0x00:
                sense_info['invalid_cmd_op_code'] = True

        sense_info['raw_data'] = []
        for i in range(0, sense_len + 1):
            if isinstance(sense[i], str):
                sense_info['raw_data'].append('0x' + sense[i])
            elif isinstance(sense[i], int):
                sense_info['raw_data'].append('0x' + f'{sense[i]:02x}')

        return sense_info

    def read_keys(self):
        """
        Read the registered keys on the disk
        """

        cdef unsigned char[10] cdb = [
            0x5e, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
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

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_FROM_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

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
        """
        Read the persistent reservation key on the disk
        """

        cdef unsigned char[10] cdb = [
            0x5e, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
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

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_FROM_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

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
        Update an existing `cur_key` with the
        `new_key`
        """

        cdef unsigned char[10] cdb = [
            0x5f, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
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

        # cur_key
        pos = 56
        for i in range(0, 7):
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

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_TO_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

    def register_new_key(self, key):
        """
        Register a new key to the disk.
        """

        cdef unsigned char[10] cdb = [
            0x5f, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
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

        # where an existing key would be put
        # if an existing one was registered
        # by this host so fill with 0's
        # since this method implies that
        # there are no current keys
        # registered by this host
        for i in range(0, 8):
            data[i] = 0

        # key
        pos = 56
        for i in range(8, 16):
            if pos == 0:
                data[i] = key & 0xff
            else:
                data[i] = (key >> pos) & 0xff
            pos -= 8

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_TO_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

    def register_ignore_key(self, key):
        """
        Regsiters a `key` to a disk ignoring
        any keys that already exist that are owned
        by this host.
        """

        cdef unsigned char[10] cdb = [
            0x5f, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
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

        # where the existing key would be
        # but since we're ignoring the
        # current key (if any) fill with 0's
        for i in range(0, 7):
            data[i] = 0

        # key to be registered
        pos = 56
        for i in range(8, 16):
            if pos == 0:
                data[i] = key & 0xff
            else:
                data[i] = (key >> pos) & 0xff
            pos -= 8

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_TO_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

    def reserve_key(self, key):
        """
        Reserves the disk (WR_EXCLUSIVE) using `key`.
        """

        cdef unsigned char[10] cdb = [
            0x5f, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
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

        # where a new key would be put
        # if an existing one was reserved
        # by this host so fill with 0's
        # since this method implies that
        # there are no current reservations
        # by this host
        for i in range(8, 16):
            data[i] = 0

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_TO_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

    def preempt_key(self, cur_key, new_key):
        """
        Preempts an existing `cur_key` that is reserving
        the disk and places a new reservation on the
        disk via `new_key`
        """

        cdef unsigned char[10] cdb = [
            0x5f, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
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

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_TO_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

    def serial(self):
        """
        Request serial number
        """

        cdef unsigned char[6] cdb = [
            0x12, 0x01, 0x80, 0, 0, 0,
        ]
        cdef unsigned int data_size = 0x00ff
        cdef unsigned char[0x00ff] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense
        cdef int pagelen

        cdb[3] = (data_size >> 8) & 0xff
        cdb[4] = data_size & 0xff

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_FROM_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

        # page length
        pagelen = data[3]

        serial = []
        for i in range(4, pagelen + 4):
            serial.append(data[i])

        serial = bytearray(serial)

        return serial.decode().strip().replace('\x00', '')

    def rotation_rate(self):
        """
        Request rotational rate
        """

        cdef unsigned char[8] cdb = [
            0x12, 0x01, 0xb1, 0, 0, 0, 0, 0
        ]
        cdef unsigned int data_size = 0x00ff
        cdef unsigned char[0x00ff] data
        cdef unsigned int sense_len = 32
        cdef unsigned char[32] sense

        cdb[3] = (data_size >> 8) & 0xff
        cdb[4] = data_size & 0xff

        try:
            self.issue_io(
                cdb,
                sizeof(cdb),
                libsgio.SG_DXFER_FROM_DEV,
                data,
                &data_size,
                sense,
                &sense_len,
            )
        except RuntimeError:
            # no reason to continue
            raise

        # handle errors
        if sense_len != 0:
            raise OSError(self.format_sense_data(sense, sense_len))

        rotation = '0x' + f'{data[4]:02x}' + f'{data[5]:02x}'

        return int(rotation, 16)
