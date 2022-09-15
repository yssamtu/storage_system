/*
 * MIT License
Copyright (c) 2021 - current
Authors:  Animesh Trivedi
This code is part of the Storage System Course at VU Amsterdam
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#ifndef STOSYS_PROJECT_NVMEPRINT_H
#define STOSYS_PROJECT_NVMEPRINT_H

#include <cstdio>
#include <cinttypes>

// most of this file is lifted from with changes, https://github.com/linux-nvme/nvme-cli/blob/master/nvme-print.h
// there are some subtle differences
enum {
    /*
     * Generic Command Status:
     */
    NVMEx_SC_SUCCESS = 0x0,
    NVMEx_SC_INVALID_OPCODE = 0x1,
    NVMEx_SC_INVALID_FIELD = 0x2,
    NVMEx_SC_CMDID_CONFLICT = 0x3,
    NVMEx_SC_DATA_XFER_ERROR = 0x4,
    NVMEx_SC_POWER_LOSS = 0x5,
    NVMEx_SC_INTERNAL = 0x6,
    NVMEx_SC_ABORT_REQ = 0x7,
    NVMEx_SC_ABORT_QUEUE = 0x8,
    NVMEx_SC_FUSED_FAIL = 0x9,
    NVMEx_SC_FUSED_MISSING = 0xa,
    NVMEx_SC_INVALID_NS = 0xb,
    NVMEx_SC_CMD_SEQ_ERROR = 0xc,
    NVMEx_SC_SGL_INVALID_LAST = 0xd,
    NVMEx_SC_SGL_INVALID_COUNT = 0xe,
    NVMEx_SC_SGL_INVALID_DATA = 0xf,
    NVMEx_SC_SGL_INVALID_METADATA = 0x10,
    NVMEx_SC_SGL_INVALID_TYPE = 0x11,
    NVMEx_SC_CMB_INVALID_USE = 0x12,
    NVMEx_SC_PRP_INVALID_OFFSET = 0x13,
    NVMEx_SC_ATOMIC_WRITE_UNIT_EXCEEDED = 0x14,
    NVMEx_SC_OPERATION_DENIED = 0x15,
    NVMEx_SC_SGL_INVALID_OFFSET = 0x16,

    NVMEx_SC_INCONSISTENT_HOST_ID = 0x18,
    NVMEx_SC_KEEP_ALIVE_EXPIRED = 0x19,
    NVMEx_SC_KEEP_ALIVE_INVALID = 0x1A,
    NVMEx_SC_PREEMPT_ABORT = 0x1B,
    NVMEx_SC_SANITIZE_FAILED = 0x1C,
    NVMEx_SC_SANITIZE_IN_PROGRESS = 0x1D,

    NVMEx_SC_NS_WRITE_PROTECTED = 0x20,
    NVMEx_SC_CMD_INTERRUPTED = 0x21,
    NVMEx_SC_TRANSIENT_TRANSPORT = 0x22,

    NVMEx_SC_LBA_RANGE = 0x80,
    NVMEx_SC_CAP_EXCEEDED = 0x81,
    NVMEx_SC_NS_NOT_READY = 0x82,
    NVMEx_SC_RESERVATION_CONFLICT = 0x83,
    NVMEx_SC_FORMAT_IN_PROGRESS = 0x84,

    /*
     * Command Specific Status:
     */
    NVMEx_SC_CQ_INVALID = 0x100,
    NVMEx_SC_QID_INVALID = 0x101,
    NVMEx_SC_QUEUE_SIZE = 0x102,
    NVMEx_SC_ABORT_LIMIT = 0x103,
    NVMEx_SC_ABORT_MISSING = 0x104,
    NVMEx_SC_ASYNC_LIMIT = 0x105,
    NVMEx_SC_FIRMWARE_SLOT = 0x106,
    NVMEx_SC_FIRMWARE_IMAGE = 0x107,
    NVMEx_SC_INVALID_VECTOR = 0x108,
    NVMEx_SC_INVALID_LOG_PAGE = 0x109,
    NVMEx_SC_INVALID_FORMAT = 0x10a,
    NVMEx_SC_FW_NEEDS_CONV_RESET = 0x10b,
    NVMEx_SC_INVALID_QUEUE = 0x10c,
    NVMEx_SC_FEATURE_NOT_SAVEABLE = 0x10d,
    NVMEx_SC_FEATURE_NOT_CHANGEABLE = 0x10e,
    NVMEx_SC_FEATURE_NOT_PER_NS = 0x10f,
    NVMEx_SC_FW_NEEDS_SUBSYS_RESET = 0x110,
    NVMEx_SC_FW_NEEDS_RESET = 0x111,
    NVMEx_SC_FW_NEEDS_MAX_TIME = 0x112,
    NVMEx_SC_FW_ACTIVATE_PROHIBITED = 0x113,
    NVMEx_SC_OVERLAPPING_RANGE = 0x114,
    NVMEx_SC_NS_INSUFFICIENT_CAP = 0x115,
    NVMEx_SC_NS_ID_UNAVAILABLE = 0x116,
    NVMEx_SC_NS_ALREADY_ATTACHED = 0x118,
    NVMEx_SC_NS_IS_PRIVATE = 0x119,
    NVMEx_SC_NS_NOT_ATTACHED = 0x11a,
    NVMEx_SC_THIN_PROV_NOT_SUPP = 0x11b,
    NVMEx_SC_CTRL_LIST_INVALID = 0x11c,
    NVMEx_SC_DEVICE_SELF_TEST_IN_PROGRESS = 0x11d,
    NVMEx_SC_BP_WRITE_PROHIBITED = 0x11e,
    NVMEx_SC_INVALID_CTRL_ID = 0x11f,
    NVMEx_SC_INVALID_SECONDARY_CTRL_STATE = 0x120,
    NVMEx_SC_INVALID_NUM_CTRL_RESOURCE = 0x121,
    NVMEx_SC_INVALID_RESOURCE_ID = 0x122,
    NVMEx_SC_PMR_SAN_PROHIBITED = 0x123,
    NVMEx_SC_ANA_INVALID_GROUP_ID = 0x124,
    NVMEx_SC_ANA_ATTACH_FAIL = 0x125,

    /*
     * Command Set Specific - Namespace Types commands:
     */
    NVMEx_SC_IOCS_NOT_SUPPORTED = 0x129,
    NVMEx_SC_IOCS_NOT_ENABLED = 0x12A,
    NVMEx_SC_IOCS_COMBINATION_REJECTED = 0x12B,
    NVMEx_SC_INVALID_IOCS = 0x12C,

    /*
     * I/O Command Set Specific - NVM commands:
     */
    NVMEx_SC_BAD_ATTRIBUTES = 0x180,
    NVMEx_SC_INVALID_PI = 0x181,
    NVMEx_SC_READ_ONLY = 0x182,
    NVMEx_SC_CMD_SIZE_LIMIT_EXCEEDED = 0x183,

    /*
     * I/O Command Set Specific - Fabrics commands:
     */
    NVMEx_SC_CONNECT_FORMAT = 0x180,
    NVMEx_SC_CONNECT_CTRL_BUSY = 0x181,
    NVMEx_SC_CONNECT_INVALID_PARAM = 0x182,
    NVMEx_SC_CONNECT_RESTART_DISC = 0x183,
    NVMEx_SC_CONNECT_INVALID_HOST = 0x184,

    NVMEx_SC_DISCOVERY_RESTART = 0x190,
    NVMEx_SC_AUTH_REQUIRED = 0x191,

    /*
     * I/O Command Set Specific - Zoned Namespace commands:
     */
    NVMEx_SC_ZONE_BOUNDARY_ERROR = 0x1B8,
    NVMEx_SC_ZONE_IS_FULL = 0x1B9,
    NVMEx_SC_ZONE_IS_READ_ONLY = 0x1BA,
    NVMEx_SC_ZONE_IS_OFFLINE = 0x1BB,
    NVMEx_SC_ZONE_INVALID_WRITE = 0x1BC,
    NVMEx_SC_TOO_MANY_ACTIVE_ZONES = 0x1BD,
    NVMEx_SC_TOO_MANY_OPEN_ZONES = 0x1BE,
    NVMEx_SC_ZONE_INVALID_STATE_TRANSITION = 0x1BF,

    /*
     * Media and Data Integrity Errors:
     */
    NVMEx_SC_WRITE_FAULT = 0x280,
    NVMEx_SC_READ_ERROR = 0x281,
    NVMEx_SC_GUARD_CHECK = 0x282,
    NVMEx_SC_APPTAG_CHECK = 0x283,
    NVMEx_SC_REFTAG_CHECK = 0x284,
    NVMEx_SC_COMPARE_FAILED = 0x285,
    NVMEx_SC_ACCESS_DENIED = 0x286,
    NVMEx_SC_UNWRITTEN_BLOCK = 0x287,

    /*
     * Path-related Errors:
     */
    NVMEx_SC_INTERNAL_PATH_ERROR = 0x300,
    NVMEx_SC_ANA_PERSISTENT_LOSS = 0x301,
    NVMEx_SC_ANA_INACCESSIBLE = 0x302,
    NVMEx_SC_ANA_TRANSITION = 0x303,

    /*
     * Controller Detected Path errors
     */
    NVMEx_SC_CTRL_PATHING_ERROR = 0x360,

    /*
     * Host Detected Path Errors
     */
    NVMEx_SC_HOST_PATHING_ERROR = 0x370,
    NVMEx_SC_HOST_CMD_ABORT = 0x371,

    NVMEx_SC_CRD = 0x1800,
    NVMEx_SC_DNR = 0x4000,
};
// I am putting ss_* (StoSys) prefix in front of these functions to make sure their definition does not collide with
// the functions defined in the library
char *ss_zone_state_to_string(__u8 state);
char *ss_zone_type_to_string(__u8 cond);
void ss_nvme_show_status(__u16 status);
void ss_nvme_show_id_ns(struct nvme_id_ns *ns);
void ss_dump_raw(unsigned char *buf, int len, int width, int group);
void ss_nvme_show_zns_id_ns(struct nvme_zns_id_ns *zns, struct nvme_id_ns *id_ns);
void ss_nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *zctrl);
void ss_nvme_show_status(__u16 status);
#endif //STOSYS_PROJECT_NVMEPRINT_H
