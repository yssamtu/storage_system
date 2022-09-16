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
    // get gc_trigger
    info->gc_trigger = params->gc_wmark;
    // get no_of_log_zones
    info->no_of_log_zones = params->log_zones;
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
    // get zns_lba_size lba_size_bytes nvm_page_size
    struct nvme_id_ns ns;
    ret = nvme_identify_ns(info->fd, info->nsid, &ns);
    if (ret) {
        printf("Error: failed to retrieve the nvme identify namespace %d\n", ret);
        return 1;
    }
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[ns.flbas & 0xF].ds;
    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    info->nvm_page_size = (*my_dev)->tparams.zns_lba_size;
    // get zns_zone_capacity capacity_bytes zones_capacity
    struct nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    (*my_dev)->tparams.zns_zone_capacity = data.lbafe[ns.flbas & 0xF].zsze * (*my_dev)->tparams.zns_lba_size;
    (*my_dev)->capacity_bytes = (*my_dev)->tparams.zns_zone_capacity;
    info->zone_capacity = (*my_dev)->tparams.zns_zone_capacity;
    // get zns_num_zones no_of_zones
    struct nvme_zone_report zns_report;
    ret = nvme_zns_mgmt_recv(info->fd, info->nsid, 0, NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL, false, sizeof(zns_report), &zns_report);
    if (ret) {
        printf("Failed to report zones, ret %d \n", ret);
        return 1;
    }
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zns_report.nr_zones);
    info->no_of_zones = (*my_dev)->tparams.zns_num_zones;
    // set no_of_used_log_zones
    info->no_of_used_log_zones = 0;
    // set curr_log_zone_starting_addr
    info->curr_log_zone_starting_addr = 0;
    // init upper_logical_addr_bound
    // init map
    return 0;
}



int hash_function(uint64_t key, int index) {
	
}

void update_log_map(metadata_log_map map, uint64_t logical_addr, uint64_t physical_addr) {
    int index = hash_function(logical_addr);

}

int lookup_log_map(metadata_log_map map, uint64_t logical_addr, uint64_t *physical_addr) {

}

int append_data_to_log_zone(zns_info *ptr, void *buffer, uint32_t size, uint64_t zslba, uint64_t *addr_written) {
    int errno;
    void *mbuffer = NULL;
    long long mbuffer_size = 0;
    uint32_t number_of_pages; //calc from size and page_size
    //FIXME: Later make provision to include meta data containing lba and write size. For persistent log storage.
    errno = nvme_zns_append(ptr->fd, ptr->nsid, ptr->zslba, number_of_pages, 0,
                    0, 0, 0, size, buffer, mbuffer_size, mbuffer, addr_written);
    ss_nvme_show_status(errno);
    return errno;	
}


int read_data_from_nvme(zns_info *ptr, uint64_t address, void *buffer, uint32_t size) {
    int errno;
    void *mbuffer = NULL;
    long long mbuffer_size = 0;
    uint32_t number_of_pages;
    errno = nvme_read(ptr->fd, ptr->nsid, address, number_of_pages, 0, 0, 0, 
		    0, 0, size, buffer, mbuffer_size, mbuffer);
    ss_nvme_show_status(errno);
    return errno; 
}


int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int errno;
    uint64_t physical_addr;

    //FIXME: Proision for contiguos block read, but not written contiguous
    //Get physical addr mapped for the provided logical addr
    errno = lookup_map(my_dev->_private->map, address, &physical_addr);
    if(errno != 0)
       return errno;


    errno = read_data_from_nvme(my_dev->_private, physical_addr, buffer, size);

    return errno;
}


int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    int errno;
    uint64_t *zone_slba, *physical_page_addr;
    
    errno = append_data_to_log_zone(my_dec->_private, buffer, size, physical_page_addr);
    if(errno != 0)
        return 0;

    update_ftl_map(my_dec->_private->metadata_log_map, address, physical_page_addr);
    return errno;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev)
{
    free(my_dev->_private);
    free(my_dev);
    return -ENOSYS;
}


}
