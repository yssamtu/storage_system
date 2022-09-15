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

#include <libnvme.h>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include "nvmeprint.h"

// most of this file is lifted from with changes, https://github.com/linux-nvme/nvme-cli/blob/master/nvme-print.c
// there are some subtle differences, i prefix some function with ss_

void ss_dump_raw(unsigned char *buf, int len, int width, int group)
{
    int i, offset = 0, line_done = 0;
    char ascii[32 + 1];

    assert(width < ((int) sizeof(ascii)));
    printf("     ");
    for (i = 0; i <= 15; i++)
        printf("%3x", i);
    for (i = 0; i < len; i++) {
        line_done = 0;
        if (i % width == 0)
            printf( "\n%04x:", offset);
        if (i % group == 0)
            printf( " %02x", buf[i]);
        else
            printf( "%02x", buf[i]);
        ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
        if (((i + 1) % width) == 0) {
            ascii[i % width + 1] = '\0';
            printf( " \"%.*s\"", width, ascii);
            offset += width;
            line_done = 1;
        }
    }
    if (!line_done) {
        unsigned b = width - (i % width);
        ascii[i % width + 1] = '\0';
        printf( " %*s \"%.*s\"",
                2 * b + b / group + (b % group ? 1 : 0), "",
                width, ascii);
    }
    printf( "\n");
}

char *ss_zone_state_to_string(__u8 state) {
    switch (state) {
        case NVME_ZNS_ZS_EMPTY:
            return (char*) "EMPTY";
        case NVME_ZNS_ZS_IMPL_OPEN:
            return (char*) "IMP_OPENED";
        case NVME_ZNS_ZS_EXPL_OPEN:
            return (char*) "EXP_OPENED";
        case NVME_ZNS_ZS_CLOSED:
            return (char*) "CLOSED";
        case NVME_ZNS_ZS_READ_ONLY:
            return (char*) "READONLY";
        case NVME_ZNS_ZS_FULL:
            return (char*) "FULL";
        case NVME_ZNS_ZS_OFFLINE:
            return (char*) "OFFLINE";
        default:
            return (char*) "Unknown State";
    }
}

char *ss_zone_type_to_string(__u8 cond) {
    switch (cond) {
        case NVME_ZONE_TYPE_SEQWRITE_REQ:
            return (char*) "SEQWRITE_REQ";
        default:
            return (char*) "Unknown";
    }
}

const char *ss_nvme_status_to_string(__u16 status) {
    switch (status & 0x7ff) {
        case NVMEx_SC_SUCCESS:
            return "SUCCESS: The command completed successfully";
        case NVMEx_SC_INVALID_OPCODE:
            return "INVALID_OPCODE: The associated command opcode field is not valid";
        case NVMEx_SC_INVALID_FIELD:
            return "INVALID_FIELD: A reserved coded value or an unsupported value in a defined field";
        case NVMEx_SC_CMDID_CONFLICT:
            return "CMDID_CONFLICT: The command identifier is already in use";
        case NVMEx_SC_DATA_XFER_ERROR:
            return "DATA_XFER_ERROR: Error while trying to transfer the data or metadata";
        case NVMEx_SC_POWER_LOSS:
            return "POWER_LOSS: Command aborted due to power loss notification";
        case NVMEx_SC_INTERNAL:
            return "INTERNAL: The command was not completed successfully due to an internal error";
        case NVMEx_SC_ABORT_REQ:
            return "ABORT_REQ: The command was aborted due to a Command Abort request";
        case NVMEx_SC_ABORT_QUEUE:
            return "ABORT_QUEUE: The command was aborted due to a Delete I/O Submission Queue request";
        case NVMEx_SC_FUSED_FAIL:
            return "FUSED_FAIL: The command was aborted due to the other command in a fused operation failing";
        case NVMEx_SC_FUSED_MISSING:
            return "FUSED_MISSING: The command was aborted due to a Missing Fused Command";
        case NVMEx_SC_INVALID_NS:
            return "INVALID_NS: The namespace or the format of that namespace is invalid";
        case NVMEx_SC_CMD_SEQ_ERROR:
            return "CMD_SEQ_ERROR: The command was aborted due to a protocol violation in a multicommand sequence";
        case NVMEx_SC_SGL_INVALID_LAST:
            return "SGL_INVALID_LAST: The command includes an invalid SGL Last Segment or SGL Segment descriptor.";
        case NVMEx_SC_SGL_INVALID_COUNT:
            return "SGL_INVALID_COUNT: There is an SGL Last Segment descriptor or an SGL Segment descriptor in a location other than the last descriptor of a segment based on the length indicated.";
        case NVMEx_SC_SGL_INVALID_DATA:
            return "SGL_INVALID_DATA: This may occur if the length of a Data SGL is too short.";
        case NVMEx_SC_SGL_INVALID_METADATA:
            return "SGL_INVALID_METADATA: This may occur if the length of a Metadata SGL is too short";
        case NVMEx_SC_SGL_INVALID_TYPE:
            return "SGL_INVALID_TYPE: The type of an SGL Descriptor is a type that is not supported by the controller.";
        case NVMEx_SC_CMB_INVALID_USE:
            return "CMB_INVALID_USE: The attempted use of the Controller Memory Buffer is not supported by the controller.";
        case NVMEx_SC_PRP_INVALID_OFFSET:
            return "PRP_INVALID_OFFSET: The Offset field for a PRP entry is invalid.";
        case NVMEx_SC_ATOMIC_WRITE_UNIT_EXCEEDED:
            return "ATOMIC_WRITE_UNIT_EXCEEDED: The length specified exceeds the atomic write unit size.";
        case NVMEx_SC_OPERATION_DENIED:
            return "OPERATION_DENIED: The command was denied due to lack of access rights.";
        case NVMEx_SC_SGL_INVALID_OFFSET:
            return "SGL_INVALID_OFFSET: The offset specified in a descriptor is invalid.";
        case NVMEx_SC_INCONSISTENT_HOST_ID:
            return "INCONSISTENT_HOST_ID: The NVM subsystem detected the simultaneous use of 64-bit and 128-bit Host Identifier values on different controllers.";
        case NVMEx_SC_KEEP_ALIVE_EXPIRED:
            return "KEEP_ALIVE_EXPIRED: The Keep Alive Timer expired.";
        case NVMEx_SC_KEEP_ALIVE_INVALID:
            return "KEEP_ALIVE_INVALID: The Keep Alive Timeout value specified is invalid.";
        case NVMEx_SC_PREEMPT_ABORT:
            return "PREEMPT_ABORT: The command was aborted due to a Reservation Acquire command with the Reservation Acquire Action (RACQA) set to 010b (Preempt and Abort).";
        case NVMEx_SC_SANITIZE_FAILED:
            return "SANITIZE_FAILED: The most recent sanitize operation failed and no recovery actions has been successfully completed";
        case NVMEx_SC_SANITIZE_IN_PROGRESS:
            return "SANITIZE_IN_PROGRESS: The requested function is prohibited while a sanitize operation is in progress";
        case NVMEx_SC_IOCS_NOT_SUPPORTED:
            return "IOCS_NOT_SUPPORTED: The I/O command set is not supported";
        case NVMEx_SC_IOCS_NOT_ENABLED:
            return "IOCS_NOT_ENABLED: The I/O command set is not enabled";
        case NVMEx_SC_IOCS_COMBINATION_REJECTED:
            return "IOCS_COMBINATION_REJECTED: The I/O command set combination is rejected";
        case NVMEx_SC_INVALID_IOCS:
            return "INVALID_IOCS: the I/O command set is invalid";
        case NVMEx_SC_LBA_RANGE:
            return "LBA_RANGE: The command references a LBA that exceeds the size of the namespace";
        case NVMEx_SC_NS_WRITE_PROTECTED:
            return "NS_WRITE_PROTECTED: The command is prohibited while the namespace is write protected by the host.";
        case NVMEx_SC_TRANSIENT_TRANSPORT:
            return "TRANSIENT_TRANSPORT: A transient transport error was detected.";
        case NVMEx_SC_CAP_EXCEEDED:
            return "CAP_EXCEEDED: The execution of the command has caused the capacity of the namespace to be exceeded";
        case NVMEx_SC_NS_NOT_READY:
            return "NS_NOT_READY: The namespace is not ready to be accessed as a result of a condition other than a condition that is reported as an Asymmetric Namespace Access condition";
        case NVMEx_SC_RESERVATION_CONFLICT:
            return "RESERVATION_CONFLICT: The command was aborted due to a conflict with a reservation held on the accessed namespace";
        case NVMEx_SC_FORMAT_IN_PROGRESS:
            return "FORMAT_IN_PROGRESS: A Format NVM command is in progress on the namespace.";
        case NVMEx_SC_ZONE_BOUNDARY_ERROR:
            return "ZONE_BOUNDARY_ERROR: Invalid Zone Boundary crossing";
        case NVMEx_SC_ZONE_IS_FULL:
            return "ZONE_IS_FULL: The accessed zone is in ZSF:Full state";
        case NVMEx_SC_ZONE_IS_READ_ONLY:
            return "ZONE_IS_READ_ONLY: The accessed zone is in ZSRO:Read Only state";
        case NVMEx_SC_ZONE_IS_OFFLINE:
            return "ZONE_IS_OFFLINE: The access zone is in ZSO:Offline state";
        case NVMEx_SC_ZONE_INVALID_WRITE:
            return "ZONE_INVALID_WRITE: The write to zone was not at the write pointer offset";
        case NVMEx_SC_TOO_MANY_ACTIVE_ZONES:
            return "TOO_MANY_ACTIVE_ZONES: The controller does not allow additional active zones";
        case NVMEx_SC_TOO_MANY_OPEN_ZONES:
            return "TOO_MANY_OPEN_ZONES: The controller does not allow additional open zones";
        case NVMEx_SC_ZONE_INVALID_STATE_TRANSITION:
            return "INVALID_ZONE_STATE_TRANSITION: The zone state change was invalid";
        case NVMEx_SC_CQ_INVALID:
            return "CQ_INVALID: The Completion Queue identifier specified in the command does not exist";
        case NVMEx_SC_QID_INVALID:
            return "QID_INVALID: The creation of the I/O Completion Queue failed due to an invalid queue identifier specified as part of the command. An invalid queue identifier is one that is currently in use or one that is outside the range supported by the controller";
        case NVMEx_SC_QUEUE_SIZE:
            return "QUEUE_SIZE: The host attempted to create an I/O Completion Queue with an invalid number of entries";
        case NVMEx_SC_ABORT_LIMIT:
            return "ABORT_LIMIT: The number of concurrently outstanding Abort commands has exceeded the limit indicated in the Identify Controller data structure";
        case NVMEx_SC_ABORT_MISSING:
            return "ABORT_MISSING: The abort command is missing";
        case NVMEx_SC_ASYNC_LIMIT:
            return "ASYNC_LIMIT: The number of concurrently outstanding Asynchronous Event Request commands has been exceeded";
        case NVMEx_SC_FIRMWARE_SLOT:
            return "FIRMWARE_SLOT: The firmware slot indicated is invalid or read only. This error is indicated if the firmware slot exceeds the number supported";
        case NVMEx_SC_FIRMWARE_IMAGE:
            return "FIRMWARE_IMAGE: The firmware image specified for activation is invalid and not loaded by the controller";
        case NVMEx_SC_INVALID_VECTOR:
            return "INVALID_VECTOR: The creation of the I/O Completion Queue failed due to an invalid interrupt vector specified as part of the command";
        case NVMEx_SC_INVALID_LOG_PAGE:
            return "INVALID_LOG_PAGE: The log page indicated is invalid. This error condition is also returned if a reserved log page is requested";
        case NVMEx_SC_INVALID_FORMAT:
            return "INVALID_FORMAT: The LBA Format specified is not supported. This may be due to various conditions";
        case NVMEx_SC_FW_NEEDS_CONV_RESET:
            return "FW_NEEDS_CONVENTIONAL_RESET: The firmware commit was successful, however, activation of the firmware image requires a conventional reset";
        case NVMEx_SC_INVALID_QUEUE:
            return "INVALID_QUEUE: This error indicates that it is invalid to delete the I/O Completion Queue specified. The typical reason for this error condition is that there is an associated I/O Submission Queue that has not been deleted.";
        case NVMEx_SC_FEATURE_NOT_SAVEABLE:
            return "FEATURE_NOT_SAVEABLE: The Feature Identifier specified does not support a saveable value";
        case NVMEx_SC_FEATURE_NOT_CHANGEABLE:
            return "FEATURE_NOT_CHANGEABLE: The Feature Identifier is not able to be changed";
        case NVMEx_SC_FEATURE_NOT_PER_NS:
            return "FEATURE_NOT_PER_NS: The Feature Identifier specified is not namespace specific. The Feature Identifier settings apply across all namespaces";
        case NVMEx_SC_FW_NEEDS_SUBSYS_RESET:
            return "FW_NEEDS_SUBSYSTEM_RESET: The firmware commit was successful, however, activation of the firmware image requires an NVM Subsystem";
        case NVMEx_SC_FW_NEEDS_RESET:
            return "FW_NEEDS_RESET: The firmware commit was successful; however, the image specified does not support being activated without a reset";
        case NVMEx_SC_FW_NEEDS_MAX_TIME:
            return "FW_NEEDS_MAX_TIME_VIOLATION: The image specified if activated immediately would exceed the Maximum Time for Firmware Activation (MTFA) value reported in Identify Controller. To activate the firmware, the Firmware Commit command needs to be re-issued and the image activated using a reset";
        case NVMEx_SC_FW_ACTIVATE_PROHIBITED:
            return "FW_ACTIVATION_PROHIBITED: The image specified is being prohibited from activation by the controller for vendor specific reasons";
        case NVMEx_SC_OVERLAPPING_RANGE:
            return "OVERLAPPING_RANGE: This error is indicated if the firmware image has overlapping ranges";
        case NVMEx_SC_NS_INSUFFICIENT_CAP:
            return "NS_INSUFFICIENT_CAPACITY: Creating the namespace requires more free space than is currently available. The Command Specific Information field of the Error Information Log specifies the total amount of NVM capacity required to create the namespace in bytes";
        case NVMEx_SC_NS_ID_UNAVAILABLE:
            return "NS_ID_UNAVAILABLE: The number of namespaces supported has been exceeded";
        case NVMEx_SC_NS_ALREADY_ATTACHED:
            return "NS_ALREADY_ATTACHED: The controller is already attached to the namespace specified";
        case NVMEx_SC_NS_IS_PRIVATE:
            return "NS_IS_PRIVATE: The namespace is private and is already attached to one controller";
        case NVMEx_SC_NS_NOT_ATTACHED:
            return "NS_NOT_ATTACHED: The request to detach the controller could not be completed because the controller is not attached to the namespace";
        case NVMEx_SC_THIN_PROV_NOT_SUPP:
            return "THIN_PROVISIONING_NOT_SUPPORTED: Thin provisioning is not supported by the controller";
        case NVMEx_SC_CTRL_LIST_INVALID:
            return "CONTROLLER_LIST_INVALID: The controller list provided is invalid";
        case NVMEx_SC_DEVICE_SELF_TEST_IN_PROGRESS:
            return "DEVICE_SELF_TEST_IN_PROGRESS: The controller or NVM subsystem already has a device self-test operation in process.";
        case NVMEx_SC_BP_WRITE_PROHIBITED:
            return "BOOT PARTITION WRITE PROHIBITED: The command is trying to modify a Boot Partition while it is locked";
        case NVMEx_SC_INVALID_CTRL_ID:
            return "INVALID_CTRL_ID: An invalid Controller Identifier was specified.";
        case NVMEx_SC_INVALID_SECONDARY_CTRL_STATE:
            return "INVALID_SECONDARY_CTRL_STATE: The action requested for the secondary controller is invalid based on the current state of the secondary controller and its primary controller.";
        case NVMEx_SC_INVALID_NUM_CTRL_RESOURCE:
            return "INVALID_NUM_CTRL_RESOURCE: The specified number of Flexible Resources is invalid";
        case NVMEx_SC_INVALID_RESOURCE_ID:
            return "INVALID_RESOURCE_ID: At least one of the specified resource identifiers was invalid";
        case NVMEx_SC_ANA_INVALID_GROUP_ID:
            return "ANA_INVALID_GROUP_ID: The specified ANA Group Identifier (ANAGRPID) is not supported in the submitted command.";
        case NVMEx_SC_ANA_ATTACH_FAIL:
            return "ANA_ATTACH_FAIL: The controller is not attached to the namespace as a result of an ANA condition";
        case NVMEx_SC_BAD_ATTRIBUTES:
            return "BAD_ATTRIBUTES: Bad attributes were given";
        case NVMEx_SC_INVALID_PI:
            return "INVALID_PROTECION_INFO: The Protection Information Field settings specified in the command are invalid";
        case NVMEx_SC_READ_ONLY:
            return "WRITE_ATTEMPT_READ_ONLY_RANGE: The LBA range specified contains read-only blocks";
        case NVMEx_SC_CMD_SIZE_LIMIT_EXCEEDED:
            return "CMD_SIZE_LIMIT_EXCEEDED: Command size limit exceeded";
        case NVMEx_SC_WRITE_FAULT:
            return "WRITE_FAULT: The write data could not be committed to the media";
        case NVMEx_SC_READ_ERROR:
            return "READ_ERROR: The read data could not be recovered from the media";
        case NVMEx_SC_GUARD_CHECK:
            return "GUARD_CHECK: The command was aborted due to an end-to-end guard check failure";
        case NVMEx_SC_APPTAG_CHECK:
            return "APPTAG_CHECK: The command was aborted due to an end-to-end application tag check failure";
        case NVMEx_SC_REFTAG_CHECK:
            return "REFTAG_CHECK: The command was aborted due to an end-to-end reference tag check failure";
        case NVMEx_SC_COMPARE_FAILED:
            return "COMPARE_FAILED: The command failed due to a miscompare during a Compare command";
        case NVMEx_SC_ACCESS_DENIED:
            return "ACCESS_DENIED: Access to the namespace and/or LBA range is denied due to lack of access rights";
        case NVMEx_SC_UNWRITTEN_BLOCK:
            return "UNWRITTEN_BLOCK: The command failed due to an attempt to read from an LBA range containing a deallocated or unwritten logical block";
        case NVMEx_SC_INTERNAL_PATH_ERROR:
            return "INTERNAL_PATH_ERROT: The command was not completed as the result of a controller internal error";
        case NVMEx_SC_ANA_PERSISTENT_LOSS:
            return "ASYMMETRIC_NAMESPACE_ACCESS_PERSISTENT_LOSS: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace being in the ANA Persistent Loss state";
        case NVMEx_SC_ANA_INACCESSIBLE:
            return "ASYMMETRIC_NAMESPACE_ACCESS_INACCESSIBLE: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace being in the ANA Inaccessible state";
        case NVMEx_SC_ANA_TRANSITION:
            return "ASYMMETRIC_NAMESPACE_ACCESS_TRANSITION: The requested function (e.g., command) is not able to be performed as a result of the relationship between the controller and the namespace transitioning between Asymmetric Namespace Access states";
        case NVMEx_SC_CTRL_PATHING_ERROR:
            return "CONTROLLER_PATHING_ERROR: A pathing error was detected by the controller";
        case NVMEx_SC_HOST_PATHING_ERROR:
            return "HOST_PATHING_ERROR: A pathing error was detected by the host";
        case NVMEx_SC_HOST_CMD_ABORT:
            return "HOST_COMMAND_ABORT: The command was aborted as a result of host action";
        case NVMEx_SC_CMD_INTERRUPTED:
            return "CMD_INTERRUPTED: Command processing was interrupted and the controller is unable to successfully complete the command. The host should retry the command.";
        case NVMEx_SC_PMR_SAN_PROHIBITED:
            return "Sanitize Prohibited While Persistent Memory Region is Enabled: A sanitize operation is prohibited while the Persistent Memory Region is enabled.";
        default:
            return "Unknown";
    }
}

static const char *nvme_feature_lba_type_to_string(__u8 type) {
    switch (type) {
        case 0:
            return "Reserved";
        case 1:
            return "Filesystem";
        case 2:
            return "RAID";
        case 3:
            return "Cache";
        case 4:
            return "Page / Swap file";
        default:
            if (type >= 0x05 && type <= 0x7f)
                return "Reserved";
            else
                return "Vendor Specific";
    }
}

static void nvme_show_id_ns_nsfeat(__u8 nsfeat) {
    __u8 rsvd = (nsfeat & 0xE0) >> 5;
    __u8 ioopt = (nsfeat & 0x10) >> 4;
    __u8 uidreuse = (nsfeat & 0x8) >> 3;
    __u8 dulbe = (nsfeat & 0x4) >> 2;
    __u8 na = (nsfeat & 0x2) >> 1;
    __u8 thin = nsfeat & 0x1;
    if (rsvd)
        printf("  [7:5] : %#x\tReserved\n", rsvd);
    printf("  [4:4] : %#x\tNPWG, NPWA, NPDG, NPDA, and NOWS are %sSupported\n",
           ioopt, ioopt ? "" : "Not ");
    printf("  [3:3] : %#x\tNGUID and EUI64 fields if non-zero, %sReused\n",
           uidreuse, uidreuse ? "Never " : "");
    printf("  [2:2] : %#x\tDeallocated or Unwritten Logical Block error %sSupported\n",
           dulbe, dulbe ? "" : "Not ");
    printf("  [1:1] : %#x\tNamespace uses %s\n",
           na, na ? "NAWUN, NAWUPF, and NACWU" : "AWUN, AWUPF, and ACWU");
    printf("  [0:0] : %#x\tThin Provisioning %sSupported\n",
           thin, thin ? "" : "Not ");
    printf("\n");
}

static void nvme_show_id_ns_flbas(__u8 flbas) {
    __u8 rsvd = (flbas & 0xE0) >> 5;
    __u8 mdedata = (flbas & 0x10) >> 4;
    __u8 lbaf = flbas & 0xF;
    if (rsvd)
        printf("  [7:5] : %#x\tReserved\n", rsvd);
    printf("  [4:4] : %#x\tMetadata Transferred %s\n",
           mdedata, mdedata ? "at End of Data LBA" : "in Separate Contiguous Buffer");
    printf("  [3:0] : %#x\tCurrent LBA Format Selected\n", lbaf);
    printf("\n");
}

static void nvme_show_id_ns_mc(__u8 mc) {
    __u8 rsvd = (mc & 0xFC) >> 2;
    __u8 mdp = (mc & 0x2) >> 1;
    __u8 extdlba = mc & 0x1;
    if (rsvd)
        printf("  [7:2] : %#x\tReserved\n", rsvd);
    printf("  [1:1] : %#x\tMetadata Pointer %sSupported\n",
           mdp, mdp ? "" : "Not ");
    printf("  [0:0] : %#x\tMetadata as Part of Extended Data LBA %sSupported\n",
           extdlba, extdlba ? "" : "Not ");
    printf("\n");
}

static void nvme_show_id_ns_dpc(__u8 dpc) {
    __u8 rsvd = (dpc & 0xE0) >> 5;
    __u8 pil8 = (dpc & 0x10) >> 4;
    __u8 pif8 = (dpc & 0x8) >> 3;
    __u8 pit3 = (dpc & 0x4) >> 2;
    __u8 pit2 = (dpc & 0x2) >> 1;
    __u8 pit1 = dpc & 0x1;
    if (rsvd)
        printf("  [7:5] : %#x\tReserved\n", rsvd);
    printf("  [4:4] : %#x\tProtection Information Transferred as Last 8 Bytes of Metadata %sSupported\n",
           pil8, pil8 ? "" : "Not ");
    printf("  [3:3] : %#x\tProtection Information Transferred as First 8 Bytes of Metadata %sSupported\n",
           pif8, pif8 ? "" : "Not ");
    printf("  [2:2] : %#x\tProtection Information Type 3 %sSupported\n",
           pit3, pit3 ? "" : "Not ");
    printf("  [1:1] : %#x\tProtection Information Type 2 %sSupported\n",
           pit2, pit2 ? "" : "Not ");
    printf("  [0:0] : %#x\tProtection Information Type 1 %sSupported\n",
           pit1, pit1 ? "" : "Not ");
    printf("\n");
}

static void nvme_show_id_ns_dps(__u8 dps) {
    __u8 rsvd = (dps & 0xF0) >> 4;
    __u8 pif8 = (dps & 0x8) >> 3;
    __u8 pit = dps & 0x7;
    if (rsvd)
        printf("  [7:4] : %#x\tReserved\n", rsvd);
    printf("  [3:3] : %#x\tProtection Information is Transferred as %s 8 Bytes of Metadata\n",
           pif8, pif8 ? "First" : "Last");
    printf("  [2:0] : %#x\tProtection Information %s\n", pit,
           pit == 3 ? "Type 3 Enabled" :
           pit == 2 ? "Type 2 Enabled" :
           pit == 1 ? "Type 1 Enabled" :
           pit == 0 ? "Disabled" : "Reserved Enabled");
    printf("\n");
}

static void nvme_show_id_ns_nmic(__u8 nmic) {
    __u8 rsvd = (nmic & 0xFE) >> 1;
    __u8 mp = nmic & 0x1;
    if (rsvd)
        printf("  [7:1] : %#x\tReserved\n", rsvd);
    printf("  [0:0] : %#x\tNamespace Multipath %sCapable\n",
           mp, mp ? "" : "Not ");
    printf("\n");
}

static void nvme_show_id_ns_rescap(__u8 rescap) {
    __u8 iekr = (rescap & 0x80) >> 7;
    __u8 eaar = (rescap & 0x40) >> 6;
    __u8 wear = (rescap & 0x20) >> 5;
    __u8 earo = (rescap & 0x10) >> 4;
    __u8 wero = (rescap & 0x8) >> 3;
    __u8 ea = (rescap & 0x4) >> 2;
    __u8 we = (rescap & 0x2) >> 1;
    __u8 ptpl = rescap & 0x1;

    printf("  [7:7] : %#x\tIgnore Existing Key - Used as defined in revision %s\n",
           iekr, iekr ? "1.3 or later" : "1.2.1 or earlier");
    printf("  [6:6] : %#x\tExclusive Access - All Registrants %sSupported\n",
           eaar, eaar ? "" : "Not ");
    printf("  [5:5] : %#x\tWrite Exclusive - All Registrants %sSupported\n",
           wear, wear ? "" : "Not ");
    printf("  [4:4] : %#x\tExclusive Access - Registrants Only %sSupported\n",
           earo, earo ? "" : "Not ");
    printf("  [3:3] : %#x\tWrite Exclusive - Registrants Only %sSupported\n",
           wero, wero ? "" : "Not ");
    printf("  [2:2] : %#x\tExclusive Access %sSupported\n",
           ea, ea ? "" : "Not ");
    printf("  [1:1] : %#x\tWrite Exclusive %sSupported\n",
           we, we ? "" : "Not ");
    printf("  [0:0] : %#x\tPersist Through Power Loss %sSupported\n",
           ptpl, ptpl ? "" : "Not ");
    printf("\n");
}

static void nvme_show_id_ns_fpi(__u8 fpi) {
    __u8 fpis = (fpi & 0x80) >> 7;
    __u8 fpii = fpi & 0x7F;
    printf("  [7:7] : %#x\tFormat Progress Indicator %sSupported\n",
           fpis, fpis ? "" : "Not ");
    if (fpis || (!fpis && fpii))
        printf("  [6:0] : %#x\tFormat Progress Indicator (Remaining %d%%)\n",
               fpii, fpii);
    printf("\n");
}

static void nvme_show_id_ns_dlfeat(__u8 dlfeat) {
    __u8 rsvd = (dlfeat & 0xE0) >> 5;
    __u8 guard = (dlfeat & 0x10) >> 4;
    __u8 dwz = (dlfeat & 0x8) >> 3;
    __u8 val = dlfeat & 0x7;
    if (rsvd)
        printf("  [7:5] : %#x\tReserved\n", rsvd);
    printf("  [4:4] : %#x\tGuard Field of Deallocated Logical Blocks is set to %s\n",
           guard, guard ? "CRC of The Value Read" : "0xFFFF");
    printf("  [3:3] : %#x\tDeallocate Bit in the Write Zeroes Command is %sSupported\n",
           dwz, dwz ? "" : "Not ");
    printf("  [2:0] : %#x\tBytes Read From a Deallocated Logical Block and its Metadata are %s\n",
           val, val == 2 ? "0xFF" :
                val == 1 ? "0x00" :
                val == 0 ? "Not Reported" : "Reserved Value");
    printf("\n");
}

static long double int128_to_double(__u8 *data) {
    int i;
    long double result = 0;

    for (i = 0; i < 16; i++) {
        result *= 256;
        result += data[15 - i];
    }
    return result;
}

void ss_nvme_show_id_ns(struct nvme_id_ns *ns) {
    int i, human = 1;
    printf("nsze    : %#" PRIx64"\n", le64_to_cpu(ns->nsze));
    printf("ncap    : %#" PRIx64"\n", le64_to_cpu(ns->ncap));
    printf("nuse    : %#" PRIx64"\n", le64_to_cpu(ns->nuse));
    printf("nsfeat  : %#x\n", ns->nsfeat);
    if (human)
        nvme_show_id_ns_nsfeat(ns->nsfeat);
    printf("nlbaf   : %d\n", ns->nlbaf);
    printf("flbas   : %#x\n", ns->flbas);
    if (human)
        nvme_show_id_ns_flbas(ns->flbas);
    printf("mc      : %#x\n", ns->mc);
    if (human)
        nvme_show_id_ns_mc(ns->mc);
    printf("dpc     : %#x\n", ns->dpc);
    if (human)
        nvme_show_id_ns_dpc(ns->dpc);
    printf("dps     : %#x\n", ns->dps);
    if (human)
        nvme_show_id_ns_dps(ns->dps);
    printf("nmic    : %#x\n", ns->nmic);
    if (human)
        nvme_show_id_ns_nmic(ns->nmic);
    printf("rescap  : %#x\n", ns->rescap);
    if (human)
        nvme_show_id_ns_rescap(ns->rescap);
    printf("fpi     : %#x\n", ns->fpi);
    if (human)
        nvme_show_id_ns_fpi(ns->fpi);
    printf("dlfeat  : %d\n", ns->dlfeat);
    if (human)
        nvme_show_id_ns_dlfeat(ns->dlfeat);
    printf("nawun   : %d\n", le16_to_cpu(ns->nawun));
    printf("nawupf  : %d\n", le16_to_cpu(ns->nawupf));
    printf("nacwu   : %d\n", le16_to_cpu(ns->nacwu));
    printf("nabsn   : %d\n", le16_to_cpu(ns->nabsn));
    printf("nabo    : %d\n", le16_to_cpu(ns->nabo));
    printf("nabspf  : %d\n", le16_to_cpu(ns->nabspf));
    printf("noiob   : %d\n", le16_to_cpu(ns->noiob));
    printf("nvmcap  : %.0Lf\n", int128_to_double(ns->nvmcap));
    if (ns->nsfeat & 0x10) {
        printf("npwg    : %u\n", le16_to_cpu(ns->npwg));
        printf("npwa    : %u\n", le16_to_cpu(ns->npwa));
        printf("npdg    : %u\n", le16_to_cpu(ns->npdg));
        printf("npda    : %u\n", le16_to_cpu(ns->npda));
        printf("nows    : %u\n", le16_to_cpu(ns->nows));
    }
    printf("mssrl   : %u\n", le16_to_cpu(ns->mssrl));
    printf("mcl     : %d\n", le32_to_cpu(ns->mcl));
    printf("msrc    : %u\n", ns->msrc);
    printf("anagrpid: %u\n", le32_to_cpu(ns->anagrpid));
    printf("nsattr	: %u\n", ns->nsattr);
    printf("nvmsetid: %d\n", le16_to_cpu(ns->nvmsetid));
    printf("endgid  : %d\n", le16_to_cpu(ns->endgid));

    printf("nguid   : ");
    for (i = 0; i < 16; i++)
        printf("%02x", ns->nguid[i]);
    printf("\n");

    printf("eui64   : ");
    for (i = 0; i < 8; i++)
        printf("%02x", ns->eui64[i]);
    printf("\n");

    for (i = 0; i <= ns->nlbaf; i++) {
        if (human)
            printf("LBA Format %2d : Metadata Size: %-3d bytes - "
                   "Data Size: %-2d bytes - Relative Performance: %#x %s %s\n",
                   i, le16_to_cpu(ns->lbaf[i].ms),
                   1 << ns->lbaf[i].ds, ns->lbaf[i].rp,
                   ns->lbaf[i].rp == 3 ? "Degraded" :
                   ns->lbaf[i].rp == 2 ? "Good" :
                   ns->lbaf[i].rp == 1 ? "Better" : "Best",
                   i == (ns->flbas & 0xf) ? "(in use)" : "");
        else
            printf("lbaf %2d : ms:%-3d lbads:%-2d rp:%#x %s\n", i,
                   le16_to_cpu(ns->lbaf[i].ms), ns->lbaf[i].ds,
                   ns->lbaf[i].rp,
                   i == (ns->flbas & 0xf) ? "(in use)" : "");
    }
    printf("size of vs is %lu \n", sizeof(ns->vs));
}

void ss_nvme_show_zns_id_ns(struct nvme_zns_id_ns *zns, struct nvme_id_ns *id_ns)
{
    // see figure 8, section 3.1.1 in the ZNS specification TP 5043
    uint8_t lbaf = id_ns->flbas & NVME_NS_FLBAS_LBA_MASK;
    int i;

    printf("ZNS Command Set Identify Namespace:\n");
    printf("zoc     : %u\tZone Operation Characteristics\n", le16_to_cpu(zns->zoc));
    printf("ozcs    : %u\tOptional Zoned Command Support\n", le16_to_cpu(zns->ozcs));
    if (zns->mar == 0xffffffff) {
        printf("mar     : No Active Resource Limit\n");
    } else {
        printf("mar     : %u\tActive Resources\n", le32_to_cpu(zns->mar) + 1);
    }
    if (zns->mor == 0xffffffff) {
        printf("mor     : No Open Resource Limit\n");
    } else {
        printf("mor     : %u\tOpen Resources\n", le32_to_cpu(zns->mor) + 1);
    }
    if (!le32_to_cpu(zns->rrl))
        printf("rrl     : Not Reported\n");
    else
        printf("rrl     : %d\n", le32_to_cpu(zns->rrl));

    if (!le32_to_cpu(zns->frl))
        printf("frl     : Not Reported\n");
    else
        printf("frl     : %d\n", le32_to_cpu(zns->frl));

    for (i = 0; i <= id_ns->nlbaf; i++){
            printf("LBA Format Extension %2d : Zone Size: 0x%" PRIx64" LBAs - "
                                                                    "Zone Descriptor Extension Size: %-1d bytes%s\n",
                   i, le64_to_cpu(zns->lbafe[i].zsze), zns->lbafe[i].zdes << 6,
                   i == lbaf ? " (in use)" : "");
    }
    printf("vs[]    :\n");
    ss_dump_raw(zns->vs, sizeof(zns->vs), 16, 1);
}

void ss_nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *zctrl)
{
    // see figure 10, section 3.1.2 in the ZNS specification TP 5043
    printf("NVMe ZNS Identify Controller:\n");
    printf("Zone Append Size Limit (zasl) : %u\n", zctrl->zasl);
    printf("a non-zero value in this field indicates the maximum data transfer size for the\n"
           "Zone Append command (refer to section 4.5); and\n"
           "b) a value of 0h in this field indicates that the maximum data transfer size for the\n"
           "Zone Append command is indicated by the Maximum Data Transfer Size\n"
           "(MDTS) field (refer to NVMe Base specification).\n"
           "The value is in units of the minimum memory page size (CAP.MPSMIN) and is reported\n"
           "as a power of two (2^n). This field includes the length of metadata if metadata is\n"
           "interleaved with the stored logical block data.\n");

}

void ss_nvme_show_status(__u16 status)
{
    fprintf(stderr, "NVMe status: %s (hex return code: %#x)\n", ss_nvme_status_to_string(status),
            status);
}