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


#include <cstdio>
#include <cstdlib>
#include <cstdbool>
#include <cerrno>
#include <libnvme.h>
#include "zns_device.h"

extern "C" {

int init_ss_zns_device(struct zdev_init_params *params, struct user_zns_device **my_dev)
{
    *my_dev = (struct user_zns_device *)calloc(1, sizeof(struct user_zns_device));
    (*my_dev)->_private = calloc(1, sizeof(struct zns_info));
    struct zns_info *info = (struct zns_info *)(*my_dev)->_private;
    // get fd
    info->fd = nvme_open(params->name);
    if (info->fd < 0) {
        printf("Device %s opened failed %d errno %d\n", params->name, info->fd, errno);
        return 1;
    }
    // get nsid
    int ret = nvme_get_nsid(info->fd, &info->nsid);
    if (ret) {
        printf("Error: failed to retrieve the namespace id %d\n", ret);
        return 1;
    }
    // reset device
    if (params->force_reset) {
        ret = nvme_zns_mgmt_send(info->fd, info->nsid, 0, true, NVME_ZNS_ZSA_RESET, 0, NULL);
        if (ret) {
            printf("Zone reset failed %d\n", ret);
            return 1;
        }
    }
    // get zns_lba_size
    struct nvme_id_ns ns;
    ret = nvme_identify_ns(info->fd, info->nsid, &ns);
    if (ret) {
        printf("Error: failed to retrieve the nvme identify namespace %d\n", ret);
        return 1;
    }
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[ns.flbas & 0xF].ds;
    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    // get zns_zone_capacity
    struct nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    (*my_dev)->tparams.zns_zone_capacity = data.lbafe[ns.flbas & 0xF].zsze * (*my_dev)->tparams.zns_lba_size;
    (*my_dev)->capacity_bytes = (*my_dev)->tparams.zns_zone_capacity;
    // get zns_num_zones
    struct nvme_zone_report zns_report;
    ret = nvme_zns_mgmt_recv(info->fd, info->nsid, 0, NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL, false, sizeof(zns_report), &zns_report);
    if (ret) {
        printf("Failed to report zones, ret %d \n", ret);
        return 1;
    }
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zns_report.nr_zones);
    return 0;
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size)
{
    return -ENOSYS;
}
int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size)
{
    return -ENOSYS;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev)
{
    free(my_dev->_private);
    free(my_dev);
    return -ENOSYS;
}
}
