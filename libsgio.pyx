# cython: language_level=3, c_string_type=unicode, c_string_encoding=default
from enum import IntEnum
from os import strerror

from pxd cimport libsgio, scsi, ses

from posix.ioctl cimport ioctl
from posix.fcntl cimport open, O_RDONLY
from posix.unistd cimport close
from libc.stdlib cimport calloc, free
from libc.string cimport memset, memcpy, memcmp, strlen
from libc.errno cimport errno
from libc.stdio cimport snprintf
from libc.stdint cimport uint8_t, uint32_t

import re


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


class SES_ETC(IntEnum):
    UNSPECIFIED_ETC = 0x0
    DEVICE_ETC = 0x1
    POWER_SUPPLY_ETC = 0x2
    COOLING_ETC = 0x3
    TEMPERATURE_ETC = 0x4
    DOOR_ETC = 0x5
    AUD_ALARM_ETC = 0x6
    ENC_SCELECTR_ETC = 0x7
    SCC_CELECTR_ETC = 0x8
    NV_CACHE_ETC = 0x9
    INV_OP_REASON_ETC = 0xa
    UI_POWER_SUPPLY_ETC = 0xb
    DISPLAY_ETC = 0xc
    KEY_PAD_ETC = 0xd
    ENCLOSURE_ETC = 0xe
    SCSI_PORT_TRAN_ETC = 0xf
    LANGUAGE_ETC = 0x10
    COMM_PORT_ETC = 0x11
    VOLT_SENSOR_ETC = 0x12
    CURR_SENSOR_ETC = 0x13
    SCSI_TPORT_ETC = 0x14
    SCSI_IPORT_ETC = 0x15
    SIMPLE_SUBENC_ETC = 0x16
    ARRAY_DEV_ETC = 0x17
    SAS_EXPANDER_ETC = 0x18
    SAS_CONNECTOR_ETC = 0x19


cdef class EnclosureDevice(object):

    cdef const char* device
    cdef int dev_fd
    cdef ses.sg_pt_base * ptvp
    cdef ses.type_desc_hdr_t desc_hdrs[1024]
    cdef int desc_hdrs_count
    cdef unsigned char * rsp_buff
    cdef unsigned char * free_rsp_buff
    cdef unsigned char * tmp_buff
    cdef unsigned char * free_tmp_buff
    cdef unsigned int MX_ALLOC_LEN
    cdef unsigned int CONFIGURATION_DPC
    cdef unsigned int ENC_STATUS_DPC
    cdef unsigned int ELEM_DESC_DPC
    cdef char r_buff[8192]
    cdef char * start
    cdef char * end
    cdef dict element_type_dict

    def __cinit__(self, device):
        self.device = device
        self.dev_fd = -1
        self.desc_hdrs_count = 0
        self.ptvp = NULL
        self.rsp_buff = NULL
        self.tmp_buff = NULL
        self.free_rsp_buff = NULL
        self.MX_ALLOC_LEN = ((64 * 1024) - 4)
        self.CONFIGURATION_DPC = 0x1
        self.ENC_STATUS_DPC = 0x2
        self.ELEM_DESC_DPC = 0x7
        self.element_type_dict = {
            SES_ETC.UNSPECIFIED_ETC : ["un", "Unspecified"],
            SES_ETC.DEVICE_ETC : ["dev", "Device slot"],
            SES_ETC.POWER_SUPPLY_ETC : ["ps", "Power supply"],
            SES_ETC.COOLING_ETC : ["coo", "Cooling"],
            SES_ETC.TEMPERATURE_ETC : ["ts", "Temperature sensor"],
            SES_ETC.DOOR_ETC : ["do", "Door"],
            SES_ETC.AUD_ALARM_ETC : ["aa", "Audible alarm"],
            SES_ETC.ENC_SCELECTR_ETC : ["esc", "Enclosure services controller electronics"],
            SES_ETC.SCC_CELECTR_ETC : ["sce", "SCC controller electronics"],
            SES_ETC.NV_CACHE_ETC : ["nc", "Nonvolatile cache"],
            SES_ETC.INV_OP_REASON_ETC : ["ior", "Invalid operation reason"],
            SES_ETC.UI_POWER_SUPPLY_ETC : ["ups", "Uninterruptible power supply"],
            SES_ETC.DISPLAY_ETC : ["dis", "Display"],
            SES_ETC.KEY_PAD_ETC : ["kpe", "SCSI port/transceiver"],
            SES_ETC.ENCLOSURE_ETC : ["enc", "Enclosure"],
            SES_ETC.SCSI_PORT_TRAN_ETC : ["sp", "SCSI port/transceiver"],
            SES_ETC.LANGUAGE_ETC : ["lan", "Language"],
            SES_ETC.COMM_PORT_ETC : ["cp", "Communication port"],
            SES_ETC.VOLT_SENSOR_ETC : ["vs", "Voltage sensor"],
            SES_ETC.CURR_SENSOR_ETC : ["cs", "Current sensor"],
            SES_ETC.SCSI_TPORT_ETC : ["stp", "SCSI target port"],
            SES_ETC.SCSI_IPORT_ETC : ["sip", "SCSI initiator port"],
            SES_ETC.SIMPLE_SUBENC_ETC : ["ss", "Simple subenclosure"],
            SES_ETC.ARRAY_DEV_ETC : ["arr", "Array device slot"],
            SES_ETC.SAS_EXPANDER_ETC : ["sse", "SAS expander"],
            SES_ETC.SAS_CONNECTOR_ETC : ["ssc", "SAS connector"]
        }

        with nogil:
            self.dev_fd = ses.sg_cmds_open_device(self.device, True, 0)
            if self.dev_fd < 0:
                raise OSError(errno, strerror(errno), self.device)

            self.rsp_buff = ses.sg_memalign(self.MX_ALLOC_LEN, 0, &self.free_rsp_buff, False)
            if self.rsp_buff == NULL:
                raise OSError(-12, strerror(-12), self.device) # ENOMEM
            memset(self.rsp_buff, 0, self.MX_ALLOC_LEN)

            self.tmp_buff = ses.sg_memalign(self.MX_ALLOC_LEN, 0, &self.free_tmp_buff, False)
            if self.tmp_buff == NULL:
                raise OSError(-12, strerror(-12), self.device) # ENOMEM
            memset(self.tmp_buff, 0, self.MX_ALLOC_LEN)

            self.ptvp = ses.construct_scsi_pt_obj_with_fd(self.dev_fd, 0)
            if self.ptvp == NULL:
                raise OSError(-12, strerror(-12), self.device) # ENOMEM
            ses.clear_scsi_pt_obj(self.ptvp)
            self.clear_r_buff()

    def __dealloc__(self):
        with nogil:
            if self.dev_fd >= 0:
                ses.sg_cmds_close_device(self.dev_fd)
            if self.rsp_buff != NULL:
                free(self.free_rsp_buff)
            if self.tmp_buff != NULL:
                free(self.free_tmp_buff)
            if self.ptvp != NULL:
                ses.destruct_scsi_pt_obj(self.ptvp)

    cdef void clear_r_buff(self) nogil:
        memset(self.r_buff, 0, 4096)
        self.start = self.r_buff
        self.end = self.r_buff + sizeof(self.r_buff)

    cdef void clear_resp_buffs(self) nogil:
        if self.rsp_buff != NULL:
            memset(self.rsp_buff, 0, self.MX_ALLOC_LEN)
        if self.tmp_buff != NULL:
            memset(self.tmp_buff, 0, self.MX_ALLOC_LEN)

    cdef void clear_ptvp(self) nogil:
        if self.ptvp != NULL:
            ses.clear_scsi_pt_obj(self.ptvp)

    cdef void clear_objs(self) nogil:
        self.clear_resp_buffs()
        self.clear_ptvp()

    cdef char * etype_str(self, int elem_code, char * buff, int buff_len) nogil:
        cdef int len
        with gil:
            if elem_code in self.element_type_dict:
                return self.element_type_dict[elem_code][1]

        if elem_code < 0x80:
            snprintf(buff, buff_len - 1, "[0x%x]", elem_code)
        else:
            snprintf(buff, buff_len - 1, "vendor specific [0x%x]", elem_code)

        return buff

    cdef int get_diagnostic_page(self, int page_code, unsigned char * buff, int * rsp_len) nogil:
        cdef int ret = -1
        cdef int resid
        cdef int buff_size = self.MX_ALLOC_LEN

        ret = ses.sg_ll_receive_diag_pt(self.ptvp, True, page_code, buff, buff_size, 0, &resid, False, 0)
        if 0 == ret:
            rsp_len[0] = ses.sg_get_unaligned_be16(buff + 2) + 4
            if rsp_len[0] > buff_size:
                if buff_size > 8:
                    self.start += snprintf(self.start, self.end - self.start, "Warning: Response buffer was too small.\n")
                if resid > 0:
                    buff_size -= resid
            elif resid > 0:
                buff_size -= resid
            if rsp_len[0] > buff_size:
                    rsp_len[0] = buff_size
            if rsp_len[0] < 0:
                self.start += snprintf(self.start, self.end - self.start, "Warning: resid=%d too large, implies -ve reply length: %d\n", resid, rsp_len[0])
                rsp_len[0] = 0
            if rsp_len[0] > 1 and page_code != buff[0]:
                if 0x9 == buff[0] and 1 & buff[1]:
                    self.start += snprintf(self.start, self.end - self.start, "Enclosure busy, try again later\n")
                elif 0x8 == buff[0]:
                    self.start += snprintf(self.start, self.end - self.start, "Enclosure only supports Short Enclosure Status: 0x%x\n", buff[1])
                else:
                    self.start += snprintf(self.start, self.end - self.start, "Invalid response, wanted page code: 0x%x but got 0x%x\n", page_code, buff[0])
                return -2

        return ret

    cdef int build_tdhs(self, uint32_t *generation, ses.enclosure_info * primary_ip) nogil:
        cdef int ret, num_subs, sum_type_dheaders, el
        cdef int len = -1
        cdef uint8_t * bp
        cdef uint8_t * last_bp

        ret = self.get_diagnostic_page(self.CONFIGURATION_DPC, self.tmp_buff, &len)
        if ret:
            self.start += snprintf(self.start, self.end - self.start, "Could not read config page.\n")
            return -1
        if len < 4:
            if 0 == ret:
                self.desc_hdrs_count += 1
            return -1

        num_subs = self.tmp_buff[1] + 1;
        sum_type_dheaders = el = 0
        last_bp = self.tmp_buff + len - 1;
        bp = self.tmp_buff + 8
        generation[0] = ses.sg_get_unaligned_be32(self.tmp_buff + 4)

        for k in range (num_subs):
            if bp + 3 > last_bp:
                self.start += snprintf(self.start, self.end - self.start, "Config too short.\n")
                return -1
            el = bp[3] + 4
            sum_type_dheaders += bp[2]
            if el < 40:
                self.start += snprintf(self.start, self.end - self.start, "Short enc descriptor len=%d ??\n", el)
                bp += el
                continue
            if 0 == k:
                primary_ip.have_info += 1
                primary_ip.rel_esp_id = (bp[0] & 0x70) >> 4
                primary_ip.num_esp = (bp[0] & 0x7)
                memcpy(primary_ip.enc_log_id, bp + 4, 8)
                memcpy(primary_ip.enc_vendor_id, bp + 12, 8)
                memcpy(primary_ip.product_id, bp + 20, 16)
                memcpy(primary_ip.product_rev_level, bp + 36, 4)
            bp += el

        for k in range (sum_type_dheaders):
            if bp + 3 > last_bp:
                self.start += snprintf(self.start, self.end - self.start, "Config too short.\n")
                return -1
            if k >= 1024:
                self.start += snprintf(self.start, self.end - self.start, "Too many elements.\n")
                return -1
            self.desc_hdrs[k].etype = bp[0];
            self.desc_hdrs[k].num_elements = bp[1];
            self.desc_hdrs[k].se_id = bp[2];
            self.desc_hdrs[k].txt_len = bp[3];
            bp += 4

        if 0 == sum_type_dheaders:
            self.desc_hdrs_count += 1

        return sum_type_dheaders

    cdef int sg_inquiry(self) nogil:
        cdef int ret = -1, pd_type = 0
        cdef int resid
        cdef char buff[128]
        cdef char * cp

        ret = ses.sg_ll_inquiry_pt(self.ptvp, False, 0, self.rsp_buff, 36, 0, &resid, False, 0)
        if ret != 0:
            self.start += snprintf(self.start, self.end - self.start, "%s does not respond to SCSI INQUIRY!\n", self.device)
            self.clear_objs()
            return -1
        self.start += snprintf(self.start, self.end - self.start, "  %.8s  %.16s  %.4s\n", self.rsp_buff + 8, self.rsp_buff + 16, self.rsp_buff + 32)
        pd_type = 0x1f & self.rsp_buff[0]
        if 0xD != pd_type:
            cp = ses.sg_get_pdt_str(pd_type, sizeof(buff), buff)
            if 0x40 & self.rsp_buff[6]:
                    self.start += snprintf(self.start, self.end - self.start, "    %s device has EncServ bit set.\n", cp)
            elif 0 != memcmp(b"NVMe", self.rsp_buff + 8, 4):
                self.start += snprintf(self.start, self.end - self.start, "    %s device (not an enclosure).\n", cp)
                self.clear_objs()
                return -1
        self.clear_objs()
        return 0

    def get_element_descriptor(self):
        cdef int len = -1
        cdef int num_ths, desc_len
        cdef uint32_t gen, ref_gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef char el_buff[32]
        cdef ses.enclosure_info info
        cdef ses.type_desc_hdr_t * tp
        cdef int k, j

        with nogil:
            self.clear_r_buff()
            if self.sg_inquiry() != 0:
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            num_ths = self.build_tdhs(&ref_gen, &info)
            if num_ths < 0:
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            if 1 == self.desc_hdrs_count and info.have_info:
                self.start += snprintf(self.start, self.end - self.start, "  Primary enclosure logical identifier (hex): ")
                for i in range(8):
                    self.start += snprintf(self.start, self.end - self.start, "%02x", info.enc_log_id[i])
                self.start += snprintf(self.start, self.end - self.start, "\n")

            self.clear_ptvp()
            if self.get_diagnostic_page(self.ELEM_DESC_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            self.start += snprintf(self.start, self.end - self.start, "Element Descriptor diagnostic page:\n")
            if len < 8:
                self.start += snprintf(self.start, self.end - self.start, "Element Descriptor: response too short.\n")
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            last_bp = self.rsp_buff + len - 1
            gen = ses.sg_get_unaligned_be32(self.rsp_buff + 4)
            self.start += snprintf(self.start, self.end - self.start, "  generation code: 0x%x\n", gen)
            if gen != ref_gen:
                self.start += snprintf(self.start, self.end - self.start, "  <<state of enclosure changed, please try again>>\n")
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            self.start += snprintf(self.start, self.end - self.start, "  element descriptor list (grouped by type):\n")
            bp = self.rsp_buff + 8
            tp = self.desc_hdrs
            for k in range (0, num_ths):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "Element Descriptor: response too short.\n")
                    self.clear_objs()
                    with gil:
                        raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                desc_len = ses.sg_get_unaligned_be16(bp + 2) + 4
                memset(el_buff, 0, sizeof(el_buff))
                self.start += snprintf(self.start, self.end - self.start, "    Element type: %s, subenclosure id: %d [ti=%d]\n", self.etype_str(tp.etype, el_buff, sizeof(el_buff)), tp.se_id, k)
                if desc_len > 4:
                    self.start += snprintf(self.start, self.end - self.start, "      Element type code: %d, Overall descriptor: %.*s\n", tp.etype, desc_len - 4, bp + 4)
                else:
                    self.start += snprintf(self.start, self.end - self.start, "      Overall descriptor: <empty>\n")
                bp += desc_len
                for j in range (0, tp.num_elements):
                    desc_len = ses.sg_get_unaligned_be16(bp + 2) + 4
                    if desc_len > 4:
                        self.start += snprintf(self.start, self.end - self.start, "      Element %d descriptor: %.*s\n", j, desc_len - 4, bp + 4)
                    else:
                        self.start += snprintf(self.start, self.end - self.start, "      Element %d descriptor: <empty>\n", j)
                    bp += desc_len
                tp += 1
            self.clear_objs()
            with gil:
                    return bytes(self.r_buff, encoding='ascii').decode()

    def get_configuration(self):
        cdef int len = -1, el = 0
        cdef int desc_len, num_subs, el_types = 0
        cdef uint32_t gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef uint8_t *text_bp
        cdef char el_buff[32]
        cdef ses.type_desc_hdr_t * tp
        cdef int k, j

        with nogil:
            self.clear_r_buff()
            if self.sg_inquiry() != 0:
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            if self.get_diagnostic_page(self.CONFIGURATION_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            self.start += snprintf(self.start, self.end - self.start, "Configuration diagnostic page:\n")
            if len < 4:
                self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            num_subs = self.rsp_buff[1] + 1
            self.start += snprintf(self.start, self.end - self.start, "  number of secondary subenclosures: %d\n", num_subs - 1)
            gen = ses.sg_get_unaligned_be32(self.rsp_buff + 4)
            self.start += snprintf(self.start, self.end - self.start, "  generation code: 0x%x\n", gen)

            last_bp = self.rsp_buff + len - 1
            bp = self.rsp_buff + 8
            self.start += snprintf(self.start, self.end - self.start, "  enclosure descriptor list\n")
            for k in range(0, num_subs):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                    self.clear_objs()
                    with gil:
                        raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                el = bp[3] + 4
                el_types += bp[2];
                if bp[1] != 0:
                    self.start += snprintf(self.start, self.end - self.start, "    Subenclosure identifier: %d\n", bp[1]);
                else:
                    self.start += snprintf(self.start, self.end - self.start, "    Subenclosure identifier: %d [primary]\n", bp[1]);
                self.start += snprintf(self.start, self.end - self.start, "      relative ES process id: %d, number of ES processes: %d\n", ((bp[0] & 0x70) >> 4), (bp[0] & 0x7));
                self.start += snprintf(self.start, self.end - self.start, "      number of type descriptor headers: %d\n", bp[2]);
                if el < 40:
                    self.start += snprintf(self.start, self.end - self.start, "      enc descriptor len=%d ??\n", el);
                    bp += el
                    continue
                self.start += snprintf(self.start, self.end - self.start, "      enclosure logical identifier (hex): ")
                for j in range(8):
                    self.start += snprintf(self.start, self.end - self.start, "%02x", bp[4 + j])
                self.start += snprintf(self.start, self.end - self.start, "\n      enclosure vendor: %.8s  product: %.16s  rev: %.4s\n", bp + 12, bp + 20, bp + 36)
                bp += el

            self.start += snprintf(self.start, self.end - self.start, "  type descriptor header and text list\n")
            text_bp = bp + (el_types * 4)
            for k in range (0, el_types):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                    self.clear_objs()
                    with gil:
                        raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                memset(el_buff, 0, sizeof(el_buff))
                self.start += snprintf(self.start, self.end - self.start, "    Element type: %s, subenclosure id: %d\n", self.etype_str(bp[0], el_buff, sizeof(el_buff)), bp[2])
                self.start += snprintf(self.start, self.end - self.start, "      number of possible elements: %d\n", bp[1])
                if bp[3] > 0:
                    if text_bp > last_bp:
                        self.start += snprintf(self.start, self.end - self.start, "SES Confgiruation: Response too short.\n")
                        self.clear_objs()
                        with gil:
                            raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                    self.start += snprintf(self.start, self.end - self.start, "      text: %.*s\n", bp[3], text_bp)
                    text_bp += bp[3]
                    bp += 4

            self.clear_objs()
            with gil:
                return bytes(self.r_buff, encoding='ascii').decode()

    def get_enclosure_status(self):
        cdef int len = -1
        cdef int num_ths, desc_len
        cdef uint32_t gen, ref_gen
        cdef uint8_t * bp
        cdef uint8_t * last_bp
        cdef char el_buff[32]
        cdef ses.enclosure_info info
        cdef ses.type_desc_hdr_t * tp
        cdef int k, j
        cdef bint invop, infob, noncrit, crit, unrecov

        with nogil:
            self.clear_r_buff()
            if self.sg_inquiry() != 0:
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            num_ths = self.build_tdhs(&ref_gen, &info)
            if num_ths < 0:
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            if 1 == self.desc_hdrs_count and info.have_info:
                self.start += snprintf(self.start, self.end - self.start, "  Primary enclosure logical identifier (hex): ")
                for i in range(8):
                    self.start += snprintf(self.start, self.end - self.start, "%02x", info.enc_log_id[i])
                self.start += snprintf(self.start, self.end - self.start, "\n")

            self.clear_ptvp()
            if self.get_diagnostic_page(self.ENC_STATUS_DPC, self.rsp_buff, &len) != 0:
                raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
            self.start += snprintf(self.start, self.end - self.start, "Enclosure Status diagnostic page:\n")
            if len < 4:
                self.start += snprintf(self.start, self.end - self.start, "Enclosure Status: response too short.\n")
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            invop = not not (self.rsp_buff[1] & 0x10)
            infob = not not (self.rsp_buff[1] & 0x8)
            noncrit = not not (self.rsp_buff[1] & 0x4)
            crit = not not (self.rsp_buff[1] & 0x2)
            unrecov = not not (self.rsp_buff[1] & 0x1)
            self.start += snprintf(self.start, self.end - self.start, "  INVOP=%d, INFO=%d, NON-CRIT=%d, CRIT=%d, UNRECOV=%d\n", invop, infob, noncrit, crit, unrecov)
            if len < 8:
                self.start += snprintf(self.start, self.end - self.start, "Enclosure Status: response too short.\n")
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            last_bp = self.rsp_buff + len - 1
            gen = ses.sg_get_unaligned_be32(self.rsp_buff + 4)
            self.start += snprintf(self.start, self.end - self.start, "  generation code: 0x%x\n", gen)
            if gen != ref_gen:
                self.start += snprintf(self.start, self.end - self.start, "  <<state of enclosure changed, please try again>>\n")
                self.clear_objs()
                with gil:
                    raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())

            self.start += snprintf(self.start, self.end - self.start, "  status descriptor list\n")
            bp = self.rsp_buff + 8
            tp = self.desc_hdrs
            for k in range(0, num_ths):
                if bp + 3 > last_bp:
                    self.start += snprintf(self.start, self.end - self.start, "Enclosure Status: response too short.\n")
                    self.clear_objs()
                    with gil:
                        raise OSError(-1, bytes(self.r_buff, encoding='ascii').decode())
                self.start += snprintf(self.start, self.end - self.start, "    Element type: %s, subenclosure id: %d [ti=%d]\n", self.etype_str(tp.etype, el_buff, sizeof(el_buff)), tp.se_id, k)
                self.start += snprintf(self.start, self.end - self.start, "      Overall descriptor:\n")
                self.start += snprintf(self.start, self.end - self.start, "        %02x %02x %02x %02x\n", bp[0], bp[1], bp[2], bp[3])
                bp += 4
                for j in range (0, tp.num_elements):
                    self.start += snprintf(self.start, self.end - self.start, "      Element %d descriptor:\n", j)
                    self.start += snprintf(self.start, self.end - self.start, "        %02x %02x %02x %02x\n", bp[0], bp[1], bp[2], bp[3])
                    bp += 4
                tp += 1

            self.clear_objs()
            with gil:
                return bytes(self.r_buff, encoding='ascii').decode()

    def status(self):
        cfg = self.get_configuration()
        element_desc = self.get_element_descriptor()
        enc_status = self.get_enclosure_status()

        enclosure = {
                "id": "",
                "name": "",
                "status": set(),
                "elements": {},
            }

        id = re.search(r"\s+enclosure logical identifier \(hex\): ([0-9a-f]+)", cfg)
        if id:
            enclosure["id"] = id.group(1)
        enclosure["name"] = re.sub(r"\s+", " ", cfg.splitlines()[0].strip())
        st_dict = dict(x.split("=") for x in enc_status.splitlines()[2].strip().split(", "))
        if st_dict["INVOP"] == "0" and st_dict["INFO"] == "0" and st_dict["NON-CRIT"] == "0" and st_dict["CRIT"] == "0" and st_dict["UNRECOV"] == "0":
            enclosure["status"].add("OK")
        else:
            if st_dict["INVOP"] != "0":
                enclosure["status"].add("INVOP")
            elif st_dict["INFO"] != "0":
                enclosure["status"].add("INFO")
            elif st_dict["NON-CRIT"] != "0":
                enclosure["status"].add("NON-CRIT")
            elif st_dict["CRIT"] != "0":
                enclosure["status"].add("CRIT")
            elif st_dict["UNRECOV"] != "0":
                enclosure["status"].add("UNRECOV")

        ind = 0
        curr_type = -1
        curr_desc = ""
        elements = {}
        for line in element_desc.splitlines():
            if re.search(r"Element type code:", line):
                curr_type = int(line.split(", ")[0].split(": ")[1])
                curr_desc = line.split(", ")[1].split(": ")[1].strip()
                elements[ind] = {'type' : curr_type, 'descriptor' : curr_desc}
            elif re.search(r"Element \d+ descriptor:", line):
                elements[ind] = {'type' : curr_type, 'descriptor' : line.split(": ")[1].strip()}
            else:
                continue
            ind += 1

        in_stts = re.findall(r"Element \d+ descriptor:\n\s+.*|Overall descriptor:\n\s+.*", enc_status)
        in_stts = [x.split('\n')[1].strip() for x in in_stts]
        in_stts = [[int(x, 16) for x in y.split()] for y in in_stts]
        for i in range (ind):
            elements[i]["status"] = in_stts[i]

        enclosure["elements"] = elements
        return enclosure
