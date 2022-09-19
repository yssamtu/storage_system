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
#include <cstdint>
#include <cstdbool>
#include <cerrno>
#include <libnvme.h>
#include "zns_device.h"

extern "C" {

enum {METADATA_MAP_LEN = 9999};

struct metadata_map {
    //FIXME: Add No of blocks written as well.
    uint64_t logical_addr;
    unsigned long long physical_addr;
    metadata_map *next;
};

struct zns_info {
    // Fixed values
    // int num_log_zones;
    // int gc_trigger;
    int fd;
    unsigned nsid;
    unsigned long long zone_num_pages;
    uint32_t no_of_zones;
    // uint64_t upper_logical_addr_bound;
 
    // Log zone maintainance
    uint32_t no_of_used_log_zones; // Keep track of used log zones
    uint32_t no_of_log_zones;
    unsigned long long curr_log_zone_saddr; // Point to current log zone starting address
    metadata_map *map[METADATA_MAP_LEN]; // Hashmap to store log
};


static inline int hash_function(uint64_t key)
{
	return key % METADATA_MAP_LEN;
}

static void check_to_trigger_GC(zns_info *info, unsigned long long last_append_addr)
{
    //TODO: Add a check on no of log zone used, trigger gc if it reaches the condition
    //Check if current log zone is ended, then change to next log zone
    if (last_append_addr - info->curr_log_zone_saddr == info->zone_num_pages - 1) {
	    info->no_of_used_log_zones ++;
	    info->curr_log_zone_saddr = last_append_addr + 1;
    }
}

static int lookup_map(metadata_map *map[METADATA_MAP_LEN],
                      uint64_t logical_addr, unsigned long long *physical_addr)
{
    int index = hash_function(logical_addr);
    metadata_map *head = map[index];
    while (head) {
        if (head->logical_addr == logical_addr) {
            *physical_addr = head->physical_addr;
            return 0;
        }
        head = head->next;
    }
    return 1;
}

static void update_map(metadata_map *map[METADATA_MAP_LEN],
                       uint64_t logical_addr, unsigned long long physical_addr)
{
    int index = hash_function(logical_addr);
    //Fill in hashmap
    if (map[index] == NULL) {
        metadata_map *entry = (metadata_map *)calloc(1, sizeof(metadata_map));
        entry->logical_addr = logical_addr;
        entry->physical_addr = physical_addr;
        map[index] = entry;
        return;
    }
    if (map[index]->logical_addr == logical_addr) {
        map[index]->physical_addr = physical_addr;
        return;
    }
    metadata_map *head = map[index];
    while (head->next) {
        if (head->next->logical_addr == logical_addr) {
            head->physical_addr = physical_addr;
            return;
        }
        head = head->next;
    }
    metadata_map *entry = (metadata_map *)calloc(1, sizeof(metadata_map));
    entry->logical_addr = logical_addr;
    entry->physical_addr = physical_addr;
    head->next = entry;
}

static int read_from_nvme(user_zns_device *my_dev, unsigned long long physical_addr,
                          void *buffer, uint32_t size)
{
    // void *metadata = NULL;
    // unsigned metadata_len = 0;
    unsigned short number_of_pages = size / my_dev->tparams.zns_lba_size - 1;
    zns_info *info = (zns_info *)my_dev->_private;
    nvme_read(info->fd, info->nsid, physical_addr, number_of_pages,
              0, 0, 0, 0, 0, size, buffer, 0, NULL);
    //ss_nvme_show_status(errno);
    return errno; 
}

static int append_to_log_zone(user_zns_device *my_dev, unsigned long long *physical_addr,
                              void *buffer, uint32_t size)
{
    // void *metadata = NULL;
    // unsigned metadata_len = 0;
    unsigned short number_of_pages = size / my_dev->tparams.zns_lba_size - 1; //calc from size and page_size
    //FIXME: Later make provision to include meta data containing lba and write size. For persistent log storage.
    zns_info *info = (zns_info *)my_dev->_private;
    nvme_zns_append(info->fd, info->nsid, info->curr_log_zone_saddr, number_of_pages,
                    0, 0, 0, 0, size, buffer, 0, NULL, physical_addr);
    //ss_nvme_show_status(errno);
    return errno;
}

int init_ss_zns_device(struct zdev_init_params *params, struct user_zns_device **my_dev)
{
    *my_dev = (user_zns_device *)calloc(1, sizeof(user_zns_device));
    (*my_dev)->_private = calloc(1, sizeof(zns_info));
    zns_info *info = (zns_info *)(*my_dev)->_private;
    // set num_log_zones
    // info->num_log_zones = params->log_zones;
    // set gc_trigger
    // info->gc_trigger = params->gc_wmark;
    // set fd
    info->fd = nvme_open(params->name);
    if (info->fd < 0) {
        printf("Dev %s opened failed %d\n", params->name, info->fd);
        return errno;
    }
    // set nsid
    int ret = nvme_get_nsid(info->fd, &info->nsid);
    if (ret) {
        printf("Error: failed to retrieve the namespace id %d\n", ret);
        return ret;
    }
    // reset device
    if (params->force_reset) {
        ret = nvme_zns_mgmt_send(info->fd, info->nsid, 0, true,
                                 NVME_ZNS_ZSA_RESET, 0, NULL);
        if (ret) {
            printf("Zone reset failed %d\n", ret);
            return ret;
        }
    }
    // set zns_lba_size
    nvme_id_ns ns;
    ret = nvme_identify_ns(info->fd, info->nsid, &ns);
    if (ret) {
        printf("Failed to retrieve the nvme identify namespace %d\n", ret);
        return ret;
    }
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[ns.flbas & 0xF].ds;
    // set lba_size_bytes
    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    // set zns_num_zones
    nvme_zone_report zns_report;
    ret = nvme_zns_mgmt_recv(info->fd, info->nsid, 0,
                             NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL, false,
                             sizeof(zns_report), &zns_report);
    if (ret) {
        printf("Failed to report zones, ret %d\n", ret);
        return ret;
    }
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zns_report.nr_zones);
    info->no_of_zones = (*my_dev)->tparams.zns_num_zones;
    
    // set zone_num_pages
    nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    info->zone_num_pages = data.lbafe[ns.flbas & 0xF].zsze;
    // set zns_zone_capacity = #page_per_zone * zone_size
    (*my_dev)->tparams.zns_zone_capacity = info->zone_num_pages *
                                           (*my_dev)->tparams.zns_lba_size;
    // set capacity_bytes = #zone * zone_capacity
    (*my_dev)->capacity_bytes = ((*my_dev)->tparams.zns_num_zones - params->log_zones) *
                                (*my_dev)->tparams.zns_zone_capacity;
    info->no_of_log_zones = params->log_zones;
    // init upper_logical_addr_bound
    return 0;
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address,
                     void *buffer, uint32_t size)
{
    unsigned long long physical_addr = 0;
    zns_info *info = (zns_info *)my_dev->_private; 
    //FIXME: Proision for contiguos block read, but not written contiguous
    //Get physical addr mapped for the provided logical addr
    int ret = lookup_map(info->map, address, &physical_addr);
    if (ret)
       return ret;
    read_from_nvme(my_dev, physical_addr, buffer, size);
    return errno;
}

int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address,
                      void *buffer, uint32_t size)
{
    unsigned long long physical_addr = 0;
    zns_info *info = (zns_info *)my_dev->_private;
    int ret = append_to_log_zone(my_dev, &physical_addr, buffer, size);
    if (ret)
        return ret;
    check_to_trigger_GC(info, physical_addr);
    update_map(info->map, address, physical_addr);
    return 0;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev)
{
    metadata_map **map = ((zns_info *)my_dev->_private)->map;
    //free hashmap
    for (int i = 0; i < METADATA_MAP_LEN; ++i) {
        while (map[i]) {
            metadata_map *tmp = map[i];
            map[i] = map[i]->next;
            free(tmp);
        }
    }
    free(my_dev->_private);
    free(my_dev);
    return 0;
}
}
