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
#include <cstring>
#include <cerrno>
#include <libnvme.h>
#include "zns_device.h"

extern "C" {

enum {METADATA_MAP_LEN = 9999, BUF_SIZE = 128 * 4096};
// enum {BUF_SIZE = 128 * 4096};
// static uint32_t used_buf_size = 0; // #lba

struct metadata_map {
    //FIXME: Add No of blocks written as well.
    uint64_t logical_addr;
    unsigned long long physical_addr;
    // void *data;
    // uint32_t size;
    // uint64_t count;
    metadata_map *next;
};
struct zns_info {
    // Fixed values
    // int num_log_zones;
    // int gc_trigger;
    int fd;
    unsigned nsid;
    unsigned long long zone_num_pages;
    // uint64_t upper_logical_addr_bound;
    // Log zone maintainance
    // uint32_t no_of_used_log_zones; // Keep track of used log zones
    unsigned long long curr_log_zone_saddr; // Point to current log zone starting address
    metadata_map *map[METADATA_MAP_LEN]; // Hashmap to store log
};


static inline int hash_function(uint64_t key)
{
	return key % METADATA_MAP_LEN;
}

static void check_to_trigger_GC(zns_info *info, unsigned long long last_append_addr)
{
    //Check if current log zone is ended, then change to next log zone
    if (last_append_addr - info->curr_log_zone_saddr == info->zone_num_pages - 1)
	    info->curr_log_zone_saddr = last_append_addr + 1;
}

// static void update_cache(metadata_map *map[METADATA_MAP_LEN], metadata_map *metadata,
//                          void *buf, uint32_t size, uint32_t count_threshold)
// {
//     metadata->data = NULL;
//     metadata->size = 0;
//     if (size <= BUF_SIZE - used_buf_size) {
//         metadata->data = calloc(1, size);
//         memcpy(metadata->data, buf, size);
//         metadata->size = size;
//         used_buf_size += size;
//         return;
//     }
//     for (int i = 0; i < METADATA_MAP_LEN; ++i) {
//         for (metadata_map *head = map[i]; head; head = head->next) {
//             if (head->count < count_threshold && head->size >= size) {
//                 free(head->data);
//                 head->data = NULL;
//                 used_buf_size -= head->size;
//                 head->size = 0;
//                 metadata->data = calloc(1, size);
//                 memcpy(metadata->data, buf, size);
//                 metadata->size = size;
//                 used_buf_size += size;
//                 return;
//             }
//         }
//     }
// }

// static int lookup_map(metadata_map *map[METADATA_MAP_LEN],
//                       uint64_t logical_addr, unsigned long long *physical_addr,
//                       void *buf, uint32_t size, bool *get)
static int lookup_map(metadata_map *map[METADATA_MAP_LEN],
                      uint64_t logical_addr, unsigned long long *physical_addr)
{
    int index = hash_function(logical_addr);
    metadata_map *head = map[index];
    while (head) {
        if (head->logical_addr == logical_addr) {
            *physical_addr = head->physical_addr;
            // ++head->count;
            // if (head->size) {
            //     memcpy(buf, head->data, size);
            //     *get = true;
            // } else {
            //     update_cache(map, head, buf, size, head->count);
            // }
            return 0;
        }
        head = head->next;
    }
    return 1;
}

// static void update_map(metadata_map *map[METADATA_MAP_LEN],
//                        uint64_t logical_addr, unsigned long long physical_addr,
//                        void *buf, uint32_t size)
static void update_map(metadata_map *map[METADATA_MAP_LEN],
                       uint64_t logical_addr, unsigned long long physical_addr)
{
    int index = hash_function(logical_addr);
    //Fill in hashmap
    if (map[index] == NULL) {
        map[index] = (metadata_map *)calloc(1, sizeof(metadata_map));
        map[index]->logical_addr = logical_addr;
        map[index]->physical_addr = physical_addr;
        // update_cache(map, map[index], buf, size, 1);
        return;
    }
    if (map[index]->logical_addr == logical_addr) {
        map[index]->physical_addr = physical_addr;
        // free(map[index]->data);
        // used_buf_size -= map[index]->size;
        // update_cache(map, map[index], buf, size, 1);
        return;
    }
    metadata_map *head = map[index];
    while (head->next) {
        if (head->next->logical_addr == logical_addr) {
            head->next->physical_addr = physical_addr;
            // free(head->next->data);
            // used_buf_size -= head->next->size;
            // update_cache(map, head->next, buf, size, 1);
            return;
        }
        head = head->next;
    }
    head->next = (metadata_map *)calloc(1, sizeof(metadata_map));
    head->next->logical_addr = logical_addr;
    head->next->physical_addr = physical_addr;
    // update_cache(map, head->next, buf, size, 1);
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
    // set zone_num_pages
    nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    info->zone_num_pages = data.lbafe[ns.flbas & 0xF].zsze;
    // set zns_zone_capacity = #page_per_zone * zone_size
    (*my_dev)->tparams.zns_zone_capacity = info->zone_num_pages *
                                           (*my_dev)->tparams.zns_lba_size;
    // set capacity_bytes = #zone * zone_capacity
    (*my_dev)->capacity_bytes = (*my_dev)->tparams.zns_num_zones *
                                (*my_dev)->tparams.zns_zone_capacity;
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
    // bool get = false;
    // int ret = lookup_map(info->map, address, &physical_addr, buffer, size, &get);
    int ret = lookup_map(info->map, address, &physical_addr);
    if (ret)
       return ret;
    // if (!get)
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
    // update_map(info->map, address, physical_addr, buffer, size);
    update_map(info->map, address, physical_addr);
    return 0;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev)
{
    metadata_map **map = ((zns_info *)my_dev->_private)->map;
    //free hashmap
    for (int i = 0; i < METADATA_MAP_LEN; ++i) {
        while (map[i]) {
            // if (map[i]->data)
            //     free(map[i]->data);
            metadata_map *tmp = map[i];
            map[i] = map[i]->next;
            free(tmp);
        }
    }
    free(my_dev->_private);
    free(my_dev);
    return 0;
}

//FIXME: Update log zone if current zone cant support current write req
/*
static int check_update_curr_log_zone_validity(zns_info *info, uint32_t size) {
    if info
}
*/

}
