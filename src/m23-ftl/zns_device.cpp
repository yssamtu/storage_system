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

// enum {BUF_SIZE = 128 * 4096};
// static uint32_t used_buf_size = 0;

struct metadata_map {
    //FIXME: Add No of blocks written as well.
    uint64_t logical_addr;
    unsigned long long physical_addr;
    // void *data;
    // uint32_t size;
    // uint64_t count;
    metadata_map *next;
};

struct log_zone_info {
    unsigned long long num_valid_pages; // counter
    // metadata_map **metadata; // which map data in this log zone
    uint32_t *log_zone_index;
    unsigned long long write_index; // like write pointer
};

struct zns_info {
    // Fixed values
    int fd;
    unsigned nsid;
    int num_log_zones;
    uint32_t num_data_zones;
    int gc_trigger;
    unsigned long long zone_num_pages;
    // uint64_t upper_logical_addr_bound;
 
    // Log zone maintainance
    uint32_t no_of_used_log_zones; // Keep track of used log zones
    unsigned long long curr_log_zone_saddr; // Point to current log zone starting address
    metadata_map **map; // Hashmap to store log
    log_zone_info *log_zones_info;
    uint32_t *used_log_zones_list; // let the new log zone at the end of the array
    uint32_t curr_used_log_zone_index; // the index of used_log_zones_list, which is equal to curr_log_zone_saddr / zns_zone_capacity
    uint32_t *free_zones_list; // use free() and calloc() to change size dynamically

};


static inline int hash_function(uint64_t key, uint32_t zns_zone_capacity)
{
	return key / zns_zone_capacity;
}

static void trigger_GC(zns_info *info, unsigned long long last_append_addr)
{
    //TODO: Add a check on no of log zone used, trigger gc if it reaches the condition
    //Check if current log zone is ended, then change to next log zone
    if (last_append_addr - info->curr_log_zone_saddr == info->zone_num_pages - 1) {
	    ++info->no_of_used_log_zones;
	    info->curr_log_zone_saddr = last_append_addr + 1;
    }
}

// static void update_cache(zns_info *info, metadata_map *metadata,
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
//     for (int i = 0; i < info->num_data_zones; ++i) {
//         for (metadata_map *head = info->map[i]; head; head = head->next) {
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

// static int lookup_map(user_zns_device *my_dev,
//                       uint64_t logical_addr, unsigned long long *physical_addr,
//                       void *buf, uint32_t size, bool *get)
static int lookup_map(user_zns_device *my_dev,
                      uint64_t logical_addr, unsigned long long *physical_addr)
{
    int index = hash_function(logical_addr, my_dev->tparams.zns_zone_capacity);
    zns_info *info = ((zns_info *)my_dev->_private);
    metadata_map *head = info->map[index];
    while (head) {
        if (head->logical_addr == logical_addr) {
            *physical_addr = head->physical_addr;
            // ++head->count;
            // if (head->size) {
            //     memcpy(buf, head->data, size);
            //     *get = true;
            // } else {
            //     update_cache(info, head, buf, size, head->count);
            // }
            return 0;
        }
        head = head->next;
    }
    return 1;
}

static void update_curr_used_log_zone(zns_info *info, uint32_t num_lba)
{
    log_zone_info *log_zone = &info->log_zones_info[info->curr_used_log_zone_index];
    if (log_zone->write_index + num_lba >= info->zone_num_pages) {
        uint32_t curr_zone_num_lba = info->zone_num_pages - log_zone->write_index;
        log_zone->write_index += curr_zone_num_lba;
        log_zone->num_valid_pages += curr_zone_num_lba;
        ++info->curr_used_log_zone_index;
        if (info->curr_used_log_zone_index == (uint32_t)info->num_log_zones) {
            --info->curr_used_log_zone_index;
            // move current log_zone info to freed zone info place
            log_zone->write_index = 0;
            log_zone->num_valid_pages = 0;
            // memset(log_zone->metadata, (int)NULL, info->zone_num_pages);
            memset(log_zone->log_zone_index, -1, info->num_log_zones);
        }
        log_zone =  &info->log_zones_info[info->curr_used_log_zone_index];
        log_zone->write_index += num_lba - curr_zone_num_lba;
        log_zone->num_valid_pages += num_lba - curr_zone_num_lba;
    } else {
        log_zone->write_index += num_lba;
        log_zone->num_valid_pages += num_lba;
    }
}

// static void update_map(user_zns_device *my_dev,
//                        uint64_t logical_addr, unsigned long long physical_addr,
//                        void *buf, uint32_t size)
static void update_map_and_log_info(user_zns_device *my_dev,
                       uint64_t logical_addr, unsigned long long physical_addr,
                       uint32_t num_lba)
{
    int index = hash_function(logical_addr, my_dev->tparams.zns_zone_capacity);
    zns_info *info = ((zns_info *)my_dev->_private);
    metadata_map **map = info->map;
    log_zone_info *log_zone = &info->log_zones_info[info->curr_used_log_zone_index];
    //Fill in hashmap
    if (map[index] == NULL) {
        map[index] = (metadata_map *)calloc(1, sizeof(metadata_map));
        map[index]->logical_addr = logical_addr;
        map[index]->physical_addr = physical_addr;
        // log_zone->metadata[log_zone->write_index] = map[index];
        log_zone->log_zone_index[log_zone->write_index] = index;
        update_curr_used_log_zone(info, num_lba);
        // update_cache(info, map[index], buf, size, 1);
        return;
    }
    if (map[index]->logical_addr == logical_addr) {
        // for (unsigned long long i = 0; i < log_zone->write_index; ++i) {
        //     if (log_zone->metadata[i] == map[index]) {
        //         log_zone->metadata[i] = NULL;
        //         break;
        //     }
        // }
        map[index]->physical_addr = physical_addr;
        // log_zone->metadata[log_zone->write_index] = map[index];
        log_zone->log_zone_index[log_zone->write_index] = index;
        update_curr_used_log_zone(info, num_lba);
        // free(map[index]->data);
        // used_buf_size -= map[index]->size;
        // update_cache(info, map[index], buf, size, 1);
        return;
    }
    metadata_map *head = map[index];
    while (head->next) {
        if (head->next->logical_addr == logical_addr) {
            // for (unsigned long long i = 0; i < log_zone->write_index; ++i) {
            //     if (log_zone->metadata[i] == head->next) {
            //         log_zone->metadata[i] = NULL;
            //         break;
            //     }
            // }
            head->next->physical_addr = physical_addr;
            // log_zone->metadata[log_zone->write_index] = head->next;
            log_zone->log_zone_index[log_zone->write_index] = index;
            update_curr_used_log_zone(info, num_lba);
            // free(head->next->data);
            // used_buf_size -= head->next->size;
            // update_cache(info, head->next, buf, size, 1);
            return;
        }
        head = head->next;
    }
    head->next = (metadata_map *)calloc(1, sizeof(metadata_map));
    head->next->logical_addr = logical_addr;
    head->next->physical_addr = physical_addr;
    // log_zone->metadata[log_zone->write_index] = head->next;
    log_zone->log_zone_index[log_zone->write_index] = index;
    update_curr_used_log_zone(info, num_lba);
    // update_cache(info, head->next, buf, size, 1);
}

static int read_from_nvme(user_zns_device *my_dev, unsigned long long physical_addr,
                          void *buffer, uint32_t size)
{
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
    info->num_log_zones = params->log_zones;
    // set gc_trigger
    info->gc_trigger = params->gc_wmark;
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
    // set num_data_zones = zns_num_zones - num_log_zones
    info->num_data_zones = (*my_dev)->tparams.zns_num_zones - info->num_log_zones;
    // set map's size = num_data_zones
    info->map = (metadata_map **)calloc(info->num_data_zones, sizeof(metadata_map *));
    // set used_log_zones_list
    info->used_log_zones_list = (uint32_t *)calloc(info->num_log_zones, sizeof(uint32_t));
    for (int i = 0; i < info->num_log_zones; ++i)
        info->used_log_zones_list[i] = i;
    // set free_zones_list
    info->free_zones_list = (uint32_t *)calloc(info->num_data_zones, sizeof(uint32_t));
    for (uint32_t i = info->num_log_zones; i < (*my_dev)->tparams.zns_num_zones; ++i)
        info->free_zones_list[i - info->num_log_zones] = i;
    // set zone_num_pages
    nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    info->zone_num_pages = data.lbafe[ns.flbas & 0xF].zsze;
    // set log_zones_info
    info->log_zones_info = (log_zone_info *)calloc(info->num_log_zones, sizeof(log_zone_info));
    // for (int i = 0; i < info->num_log_zones; ++i)
    //     info->log_zones_info[i].metadata = (metadata_map **)calloc(info->zone_num_pages, sizeof(metadata_map *));
    for (int i = 0; i < info->num_log_zones; ++i)
        info->log_zones_info[i].log_zone_index = (uint32_t *)calloc(info->zone_num_pages, sizeof(uint32_t));
    // set zns_zone_capacity = #page_per_zone * zone_size
    (*my_dev)->tparams.zns_zone_capacity = info->zone_num_pages *
                                           (*my_dev)->tparams.zns_lba_size;
    // set capacity_bytes = #zone * zone_capacity
    (*my_dev)->capacity_bytes = info->num_data_zones * (*my_dev)->tparams.zns_zone_capacity;
    // init upper_logical_addr_bound
    return 0;
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address,
                     void *buffer, uint32_t size)
{
    unsigned long long physical_addr = 0;
    //FIXME: Proision for contiguos block read, but not written contiguous
    //Get physical addr mapped for the provided logical addr
    // bool get = false;
    // int ret = lookup_map(my_dev, address, &physical_addr, buffer, size, &get);
    int ret = lookup_map(my_dev, address, &physical_addr);
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
    // update_map(my_dev, address, physical_addr, buffer, size);
    update_map_and_log_info(my_dev, address, physical_addr, size / my_dev->tparams.zns_lba_size);
    trigger_GC(info, physical_addr);
    return 0;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev)
{
    zns_info *info = (zns_info *)my_dev->_private;
    metadata_map **map = info->map;
    //free hashmap
    for (uint32_t i = 0; i < info->num_data_zones; ++i) {
        while (map[i]) {
            // if (map[i]->data)
            //     free(map[i]->data);
            metadata_map *tmp = map[i];
            map[i] = map[i]->next;
            free(tmp);
        }
    }
    free(map);
    // for (int i = 0; i < info->num_log_zones; ++i)
    //     free(info->log_zones_info[i].metadata);
    for (int i = 0; i < info->num_log_zones; ++i)
        free(info->log_zones_info[i].log_zone_index);
    free(info->log_zones_info);
    free(info->used_log_zones_list);
    free(info->free_zones_list);
    free(my_dev->_private);
    free(my_dev);
    return 0;
}

}
