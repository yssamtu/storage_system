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

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libnvme.h>
#include <pthread.h>
#include "zns_device.h"

extern "C" {

enum {
    dev_write = 0x0,
    user_read = 0x1,
    gc_read = 0x2,
    sb_read = user_read | gc_read, // user or gc is reading
    user_write = 0x10,
    gc_write = 0x20,
    sb_write = user_write | gc_write // user or gc is writing
};

// zone in zns
typedef struct zone_info {
    unsigned long long saddr; // starting physical address
    uint32_t num_valid_pages; // the number of valid pages (used for log zone)
    pthread_mutex_t num_valid_pages_lock;
    uint32_t write_ptr; // writer pointer (used for data zone)
    pthread_mutex_t write_ptr_lock;
    struct zone_info *next; // linked in used_log_zones and free_zones
} zone_info;

// page map for log zones
typedef struct page_map {
    unsigned long long page_addr; // logical page address
    unsigned long long physical_addr; // phisical address
    zone_info *zone; // the zone this page map in
    struct page_map *next;
} page_map;

// Contains data in log zone (page map) and data in data zone (block map)
typedef struct logical_block {
    unsigned long long s_page_addr; // starting logical page address
    page_map *page_maps; // page mapping for this logical block (log zone)
    page_map *old_page_maps; // temporily store old page maps while gc
    page_map *page_maps_tail;
    zone_info *data_zone; // block mapping for this logical block (data zone)
    uint8_t *bitmap;
    pthread_mutex_t lock;
} logical_block;

typedef struct zns_info {
    // information of device
    int fd;
    unsigned nsid;
    uint32_t page_size;
    uint32_t zone_num_pages;
    uint32_t num_zones;
    uint32_t num_log_zones;
    uint32_t num_data_zones;
    // max data transfer size (read + append limit)
    uint32_t mdts;
    // zone append size limit (append limit)
    uint32_t zasl;
    // load balancing varaible
    uint32_t free_transfer_size;
    uint32_t free_append_size;
    uint8_t used_status;
    pthread_mutex_t size_limit_lock;
    // logical block corresponding to each data zone
    logical_block *logical_blocks;
    // current log zone
    zone_info *curr_log_zone;
    // used log zone
    zone_info *used_log_zones;
    zone_info *used_log_zones_tail;
    uint32_t num_used_log_zones;
    // Free zones
    zone_info *free_zones;
    zone_info *free_zones_tail;
    uint32_t num_free_zones;
    // Lock for changing used_log_zone and free_zone
    pthread_mutex_t zones_lock;
    // garbage collection variable
    uint32_t gc_wmark;
    bool run_gc;
    pthread_t gc_thread;
} zns_info;

static inline void increase_num_valid_page(zone_info *zone, uint32_t num_pages);
static inline void decrease_num_valid_page(zone_info *zone, uint32_t num_pages);
static inline void increase_write_ptr(zone_info *zone, uint32_t num_pages);
static inline void decrease_write_ptr(zone_info *zone, uint32_t num_pages);
static inline uint32_t get_block_index(unsigned long long page_addr,
                                       uint32_t zone_num_pages);
static inline uint32_t get_data_offset(unsigned long long page_addr,
                                       uint32_t zone_num_pages);
static bool read_bitmap(const uint8_t bitmap[],
                        uint32_t offset, uint32_t num_pages);
static void write_bitmap(uint8_t bitmap[], uint32_t offset, uint32_t num_pages);
static void change_log_zone(zns_info *info);
static void update_page_map(zns_info *info, unsigned long long page_addr,
                            unsigned long long physical_addr,
                            uint32_t num_pages);
static unsigned request_transfer_size(zns_info *info, uint8_t type);
static void release_transfer_size(zns_info *info, uint8_t type, unsigned size);
static int read_from_zns(zns_info *info, unsigned long long physical_addr,
                         void *buffer, uint64_t size, uint8_t type);
static int append_to_data_zone(zns_info *info, zone_info *zone,
                               void *buffer, uint64_t size, uint8_t type);
static int append_to_log_zone(zns_info *info, unsigned long long page_addr,
                              void *buffer, uint32_t size);
static int read_logical_block(zns_info *info, logical_block *block,
                              void *buffer);
static void merge(zns_info *info, logical_block *block);
static void *garbage_collection(void *info_ptr);

int init_ss_zns_device(zdev_init_params *params, user_zns_device **my_dev)
{
    *my_dev = (user_zns_device *)calloc(1UL, sizeof(user_zns_device));
    (*my_dev)->_private = calloc(1UL, sizeof(zns_info));
    zns_info *info = (zns_info *)(*my_dev)->_private;
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
    // set zns_lba_size or page_size : Its same for now!
    nvme_id_ns ns;
    ret = nvme_identify_ns(info->fd, info->nsid, &ns);
    if (ret) {
        printf("Failed to retrieve the nvme identify namespace %d\n", ret);
        return ret;
    }
    info->page_size = 1U << ns.lbaf[ns.flbas & 0xF].ds;
    (*my_dev)->tparams.zns_lba_size = info->page_size;
    (*my_dev)->lba_size_bytes = info->page_size;
    // set zone_num_pages
    nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    info->zone_num_pages = data.lbafe[ns.flbas & 0xF].zsze;
    // set zns_zone_capacity = zone_num_pages * page_size
    (*my_dev)->tparams.zns_zone_capacity = info->zone_num_pages *
                                           info->page_size;
    // set num_zones
    nvme_zone_report zns_report;
    ret = nvme_zns_mgmt_recv(info->fd, info->nsid, 0ULL,
                             NVME_ZNS_ZRA_REPORT_ZONES,
                             NVME_ZNS_ZRAS_REPORT_ALL, false,
                             sizeof(zns_report), &zns_report);
    if (ret) {
        printf("Failed to report zones, ret %d\n", ret);
        return ret;
    }
    info->num_zones = le64_to_cpu(zns_report.nr_zones);
    (*my_dev)->tparams.zns_num_zones = info->num_zones;
    // set num_log_zones
    info->num_log_zones = params->log_zones > 0 ? params->log_zones : 0U;
    // set num_data_zones = num_zones - num_log_zones
    info->num_data_zones = info->num_zones - info->num_log_zones;
    // set user capacity bytes = num_data_zones * zone_capacity
    (*my_dev)->capacity_bytes = (info->num_data_zones) *
                                (*my_dev)->tparams.zns_zone_capacity;
    // set max_data_transfer_size and free_transfer_size
    nvme_id_ctrl id0;
    nvme_identify_ctrl(info->fd, &id0);
    info->mdts = ((1U << id0.mdts) - 2U) * info->page_size;
    info->free_transfer_size = info->mdts;
    // set zone_append_size_limit and free_append_size
    nvme_zns_id_ctrl id1;
    nvme_zns_identify_ctrl(info->fd, &id1);
    info->zasl = ((1U << id1.zasl) - 2U) * info->page_size;
    info->free_append_size = info->zasl;
    // initialise size_limit_lock
    pthread_mutex_init(&info->size_limit_lock, NULL);
    // reset device
    if (params->force_reset) {
        ret = nvme_zns_mgmt_send(info->fd, info->nsid, 0ULL, true,
                                 NVME_ZNS_ZSA_RESET, 0U, NULL);
        if (ret) {
            printf("Zone reset failed %d\n", ret);
            return ret;
        }
    } else {
        ;
    }
    // set log zone page mapped hashmap size to num_data_zones
    info->logical_blocks = (logical_block *)calloc(info->num_data_zones,
                                                   sizeof(logical_block));
    for (uint32_t i = 0U; i < info->num_data_zones; ++i) {
        info->logical_blocks[i].s_page_addr = i * info->zone_num_pages;
        info->logical_blocks[i].bitmap = (uint8_t *)
                                         calloc(((info->zone_num_pages - 1UL)
                                                 >> 3UL) + 1UL,
                                                sizeof(uint8_t));
        pthread_mutex_init(&info->logical_blocks[i].lock, NULL);
    }
    // set all zone to free_zones
    info->free_zones = (zone_info *)calloc(1UL, sizeof(zone_info));
    info->free_zones_tail = info->free_zones;
    pthread_mutex_init(&info->free_zones->num_valid_pages_lock, NULL);
    pthread_mutex_init(&info->free_zones->write_ptr_lock, NULL);
    for (uint32_t i = 1U; i < info->num_zones; ++i) {
        info->free_zones_tail->next = (zone_info *)calloc(1UL,
                                                          sizeof(zone_info));
        info->free_zones_tail = info->free_zones_tail->next;
        info->free_zones_tail->saddr = i * info->zone_num_pages;
        pthread_mutex_init(&info->free_zones_tail->num_valid_pages_lock, NULL);
        pthread_mutex_init(&info->free_zones_tail->write_ptr_lock, NULL);
    }
    // set num_free_zones
    info->num_free_zones = info->num_zones;
    //Set current log zone to 0th zone
    info->curr_log_zone = info->free_zones;
    info->free_zones = info->free_zones->next;
    if (!info->free_zones)
        info->free_zones_tail = NULL;
    info->curr_log_zone->next = NULL;
    --info->num_free_zones;
    // init zones_lock
    pthread_mutex_init(&info->zones_lock, NULL);
    // set gc_wmark
    info->gc_wmark = params->gc_wmark > 0 ? params->gc_wmark : 0U;
    //Start GC
    info->run_gc = true;
    pthread_create(&info->gc_thread, NULL, &garbage_collection, info);
    return 0;
}

int zns_udevice_read(user_zns_device *my_dev, uint64_t address,
                     void *buffer, uint32_t size)
{
    zns_info *info = (zns_info *)my_dev->_private;
    unsigned long long page_addr = address / info->page_size;
    while (size) {
        uint32_t index = get_block_index(page_addr, info->zone_num_pages);
        uint32_t offset = get_data_offset(page_addr, info->zone_num_pages);
        logical_block *block = &info->logical_blocks[index];
        uint32_t curr_block_read_size = (info->zone_num_pages - offset) *
                                        info->page_size;
        if (curr_block_read_size > size)
            curr_block_read_size = size;
        if (!read_bitmap(block->bitmap, offset,
                         curr_block_read_size / info->page_size))
            return -1;
        pthread_mutex_lock(&block->lock);
        if (block->data_zone) {
            uint32_t curr_read_size = block->data_zone->write_ptr *
                                      info->page_size;
            if (curr_read_size > curr_block_read_size)
                curr_read_size = curr_block_read_size;
            read_from_zns(info, block->data_zone->saddr + offset,
                          buffer, curr_read_size, user_read);
        }
        page_map *curr = block->page_maps ? block->page_maps :
                                            block->old_page_maps;
        while (curr && curr->page_addr < page_addr)
            curr = curr->next;
        unsigned long long max_page_addr = page_addr + curr_block_read_size /
                                                       info->page_size - 1ULL;
        if (curr && curr->page_addr <= max_page_addr) {
            page_map *prev = curr;
            page_map *start = curr;
            curr = curr->next;
            while (curr) {
                if (curr->page_addr > max_page_addr)
                    break;
                if (curr->page_addr - prev->page_addr != 1ULL ||
                    curr->physical_addr - prev->physical_addr != 1ULL) {
                    unsigned long long buff_offset = (start->page_addr -
                                                      page_addr) *
                                                     info->page_size;
                    uint32_t curr_read_size = (prev->page_addr -
                                               start->page_addr + 1ULL) *
                                              info->page_size;
                    read_from_zns(info, start->physical_addr,
                                  (uint8_t *)buffer + buff_offset,
                                  curr_read_size, user_read);
                    start = curr;
                }
                prev = curr;
                curr = curr->next;
            }
            unsigned long long buff_offset = (start->page_addr - page_addr) *
                                             info->page_size;
            uint32_t curr_read_size = (prev->page_addr - start->page_addr +
                                       1ULL) * info->page_size;
            read_from_zns(info, start->physical_addr,
                          (uint8_t *)buffer + buff_offset, curr_read_size,
                          user_read);
        }
        pthread_mutex_unlock(&block->lock);
        page_addr += curr_block_read_size / info->page_size;
        buffer = (uint8_t *)buffer + curr_block_read_size;
        size -= curr_block_read_size;
    }
    pthread_mutex_lock(&info->size_limit_lock);
    info->used_status &= ~user_read;
    pthread_mutex_unlock(&info->size_limit_lock);
    return errno;
}

int zns_udevice_write(user_zns_device *my_dev, uint64_t address,
                      void *buffer, uint32_t size)
{
    zns_info *info = (zns_info *)my_dev->_private;
    while (size) {
        uint32_t index = get_block_index(address / info->page_size,
                                         info->zone_num_pages);
        uint32_t offset = get_data_offset(address / info->page_size,
                                          info->zone_num_pages);
        logical_block *block = &info->logical_blocks[index];
        uint32_t curr_append_size = 0U;
        pthread_mutex_lock(&block->lock);
        // if can write to data zone directly
        if (!block->old_page_maps &&
            block->data_zone && block->data_zone->write_ptr <= offset) {
            if (block->data_zone->write_ptr < offset) {
                // append null data until arrive offset
                uint32_t null_size = (offset - block->data_zone->write_ptr) *
                                     info->page_size;
                uint8_t null_buffer[null_size];
                memset(null_buffer, 0, null_size);
                int ret = append_to_data_zone(info, block->data_zone,
                                              null_buffer, null_size,
                                              user_write);
                if (ret) {
                    pthread_mutex_unlock(&block->lock);
                    return ret;
                }
            }
            curr_append_size = (info->zone_num_pages - offset) *
                               info->page_size;
            if (curr_append_size > size)
                curr_append_size = size;
            int ret = append_to_data_zone(info, block->data_zone,
                                          buffer, curr_append_size, user_write);
            if (ret) {
                pthread_mutex_unlock(&block->lock);
                return ret;
            }
            pthread_mutex_unlock(&block->lock);
        } else {
            curr_append_size = size;
            if (block->data_zone) {
                uint32_t diff_size = (block->data_zone->write_ptr - offset) *
                                     info->page_size;
                if (curr_append_size > diff_size)
                    curr_append_size = diff_size;
            }
            pthread_mutex_unlock(&block->lock);
            int ret = append_to_log_zone(info, address / info->page_size,
                                         buffer, curr_append_size);
            if (ret)
                return ret;
        }
        write_bitmap(block->bitmap, offset, curr_append_size / info->page_size);
        address += curr_append_size;
        buffer = (uint8_t *)buffer + curr_append_size;
        size -= curr_append_size;
    }
    pthread_mutex_lock(&info->size_limit_lock);
    info->used_status &= ~user_write;
    pthread_mutex_unlock(&info->size_limit_lock);
    return errno;
}

int deinit_ss_zns_device(user_zns_device *my_dev)
{
    zns_info *info = (zns_info *)my_dev->_private;
    // Kill gc
    pthread_mutex_lock(&info->zones_lock);
    if (info->used_log_zones)
        info->used_log_zones_tail->next = info->curr_log_zone;
    else
        info->used_log_zones = info->curr_log_zone;
    info->used_log_zones_tail = info->curr_log_zone;
    info->curr_log_zone = NULL;
    ++info->num_used_log_zones;
    pthread_mutex_unlock(&info->zones_lock);
    info->run_gc = false;
    pthread_join(info->gc_thread, NULL);
    logical_block *blocks = info->logical_blocks;
    // free hashmap
    for (uint32_t i = 0U; i < info->num_data_zones; ++i) {
	    // Clear all log heads for a logical block
        if (blocks[i].data_zone) {
            pthread_mutex_destroy(&blocks[i].data_zone->num_valid_pages_lock);
            pthread_mutex_destroy(&blocks[i].data_zone->write_ptr_lock);
	        free(blocks[i].data_zone);
        }
        free(blocks[i].bitmap);
        pthread_mutex_destroy(&blocks[i].lock);
    }
    free(blocks);
    while (info->free_zones) {
        zone_info *tmp = info->free_zones;
        info->free_zones = info->free_zones->next;
        pthread_mutex_destroy(&tmp->num_valid_pages_lock);
        pthread_mutex_destroy(&tmp->write_ptr_lock);
        free(tmp);
    }
    pthread_mutex_destroy(&info->size_limit_lock);
    pthread_mutex_destroy(&info->zones_lock);
    free(info);
    free(my_dev);
    return 0;
}

static inline void increase_num_valid_page(zone_info *zone, uint32_t num_pages)
{
    pthread_mutex_lock(&zone->num_valid_pages_lock);
    zone->num_valid_pages += num_pages;
    pthread_mutex_unlock(&zone->num_valid_pages_lock);
}

static inline void decrease_num_valid_page(zone_info *zone, uint32_t num_pages)
{
    pthread_mutex_lock(&zone->num_valid_pages_lock);
    zone->num_valid_pages -= num_pages;
    pthread_mutex_unlock(&zone->num_valid_pages_lock);
}

static inline void increase_write_ptr(zone_info *zone, uint32_t num_pages)
{
    pthread_mutex_lock(&zone->write_ptr_lock);
    zone->write_ptr += num_pages;
    pthread_mutex_unlock(&zone->write_ptr_lock);
}

static inline void decrease_write_ptr(zone_info *zone, uint32_t num_pages)
{
    pthread_mutex_lock(&zone->write_ptr_lock);
    zone->write_ptr -= num_pages;
    pthread_mutex_unlock(&zone->write_ptr_lock);
}

static inline uint32_t get_block_index(unsigned long long page_addr,
                                       uint32_t zone_num_pages)
{
    return page_addr / zone_num_pages;
}

static inline uint32_t get_data_offset(unsigned long long page_addr,
                                       uint32_t zone_num_pages)
{
    return page_addr % zone_num_pages;
}

static bool read_bitmap(const uint8_t bitmap[],
                        uint32_t offset, uint32_t num_pages)
{
    while (num_pages--) {
        if (!(bitmap[offset >> 3U] & 1U << (offset & 0x7U)))
            return false;
        ++offset;
    }
    return true;
}

static void write_bitmap(uint8_t bitmap[], uint32_t offset, uint32_t num_pages)
{
    while (num_pages--) {
        bitmap[offset >> 3U] |= 1U << (offset & 0x7U);
        ++offset;
    }
}

static void change_log_zone(zns_info *info)
{
    pthread_mutex_lock(&info->zones_lock);
    if (info->used_log_zones)
        info->used_log_zones_tail->next = info->curr_log_zone;
    else
        info->used_log_zones = info->curr_log_zone;
    info->used_log_zones_tail = info->curr_log_zone;
    info->curr_log_zone = NULL;
    ++info->num_used_log_zones;
    pthread_mutex_unlock(&info->zones_lock);
    while (info->num_used_log_zones == info->num_log_zones);
    //Dequeue from free_zone to curr_log_zone;
    while (!info->curr_log_zone) {
        pthread_mutex_lock(&info->zones_lock);
        if (info->num_free_zones) {
            info->curr_log_zone = info->free_zones;
            info->free_zones = info->free_zones->next;
            info->curr_log_zone->next = NULL;
            --info->num_free_zones;
        }
        pthread_mutex_unlock(&info->zones_lock);
    }
}

static void update_page_map(zns_info *info, unsigned long long page_addr,
                            unsigned long long physical_addr,
                            uint32_t num_pages)
{
    while (num_pages--) {
        uint32_t index = get_block_index(page_addr, info->zone_num_pages);
        logical_block *block = &info->logical_blocks[index];
        //Lock for updating page map
        pthread_mutex_lock(&block->lock);
        if (!block->page_maps) {
            block->page_maps = (page_map *)calloc(1, sizeof(page_map));
            block->page_maps_tail = block->page_maps;
            block->page_maps->page_addr = page_addr;
            block->page_maps->physical_addr = physical_addr;
            block->page_maps->zone = info->curr_log_zone;
            pthread_mutex_unlock(&block->lock);
            return;
        }
        if (block->page_maps->page_addr == page_addr) {
            //Update log counter
            decrease_num_valid_page(block->page_maps->zone, 1U);
            block->page_maps->physical_addr = physical_addr;
            block->page_maps->zone = info->curr_log_zone;
            pthread_mutex_unlock(&block->lock);
            return;
        }
        if (block->page_maps->page_addr > page_addr) {
            page_map *tmp = (page_map *)calloc(1, sizeof(page_map));
            tmp->next = block->page_maps;
            block->page_maps = tmp;
            tmp->page_addr = page_addr;
            tmp->physical_addr = physical_addr;
            tmp->zone = info->curr_log_zone;
            pthread_mutex_unlock(&block->lock);
            return;
        }
        page_map *ptr = block->page_maps;
        while (ptr->next) {
            if (ptr->next->page_addr == page_addr) {
                //Update log counter
                decrease_num_valid_page(ptr->next->zone, 1U);
                ptr->next->physical_addr = physical_addr;
                ptr->next->zone = info->curr_log_zone;
                pthread_mutex_unlock(&block->lock);
                return;
            } else if (ptr->next->page_addr > page_addr) {
                page_map *tmp =  (page_map *)calloc(1, sizeof(page_map));
                tmp->next = ptr->next;
                ptr->next = tmp;
                tmp->page_addr = page_addr;
                tmp->physical_addr = physical_addr;
                tmp->zone = info->curr_log_zone;
                pthread_mutex_unlock(&block->lock);
                return;
            }
            ptr = ptr->next;
        }
        ptr->next = (page_map *)calloc(1, sizeof(page_map));
        block->page_maps_tail = ptr->next;
        ptr->next->page_addr = page_addr;
        ptr->next->physical_addr = physical_addr;
        ptr->next->zone = info->curr_log_zone;
        pthread_mutex_unlock(&block->lock);
        ++page_addr;
        ++physical_addr;
    }
}

static unsigned request_transfer_size(zns_info *info, uint8_t type)
{
    if (type & sb_read) {
        uint32_t max_transfer_size = info->mdts;
        for (;;) {
            if (info->free_transfer_size) {
                pthread_mutex_lock(&info->size_limit_lock);
                break;
            }
        }
        if (info->used_status & sb_write)
            max_transfer_size -= info->zasl;
        if (info->used_status & (sb_read & ~type))
            max_transfer_size >>= 1;
        if (info->free_transfer_size < max_transfer_size)
            max_transfer_size = info->free_transfer_size;
        info->free_transfer_size -= max_transfer_size;
        info->used_status |= type;
        pthread_mutex_unlock(&info->size_limit_lock);
        return max_transfer_size;
    } else {
        uint32_t max_transfer_size = info->zasl;
        for (;;) {
            if (info->free_transfer_size && info->free_append_size) {
                pthread_mutex_lock(&info->size_limit_lock);
                break;
            }
        }
        if (info->used_status & sb_write)
            max_transfer_size >>= 1;
        if (info->free_append_size < max_transfer_size)
            max_transfer_size = info->free_append_size;
        if (info->free_transfer_size < max_transfer_size)
            max_transfer_size = info->free_transfer_size;
        info->free_transfer_size -= max_transfer_size;
        info->free_append_size -= max_transfer_size;
        info->used_status |= type;
        pthread_mutex_unlock(&info->size_limit_lock);
        return max_transfer_size;
    }
}

static void release_transfer_size(zns_info *info, uint8_t type, unsigned size)
{
    pthread_mutex_lock(&info->size_limit_lock);
    if (type & sb_write)
        info->free_append_size += size;
    info->free_transfer_size += size;
    pthread_mutex_unlock(&info->size_limit_lock);
}

static int read_from_zns(zns_info *info, unsigned long long physical_addr,
                         void *buffer, uint64_t size, uint8_t type)
{
    while (size) {
        unsigned curr_transfer_size = request_transfer_size(info, type);
        unsigned curr_read_size = size < curr_transfer_size ?
                                  size : curr_transfer_size;
        unsigned short num_pages = curr_read_size / info->page_size;
        nvme_read(info->fd, info->nsid, physical_addr, num_pages - 1,
                  0U, 0U, 0U, 0U, 0U, curr_read_size, buffer, 0U, NULL);
        release_transfer_size(info, type, curr_transfer_size);
        physical_addr += num_pages;
        buffer = (uint8_t *)buffer + curr_read_size;
        size -= curr_read_size;
    }
    return errno;
}

static int append_to_data_zone(zns_info *info, zone_info *zone,
                               void *buffer, uint64_t size, uint8_t type)
{
    increase_write_ptr(zone, size / info->page_size);
    while (size) {
        unsigned long long physical_addr = 0ULL;
        unsigned curr_transfer_size = request_transfer_size(info, type);
        unsigned curr_append_size = curr_transfer_size;
        if (curr_append_size > size)
            curr_append_size = size;
        unsigned short num_curr_append_pages = curr_append_size /
                                               info->page_size;
        nvme_zns_append(info->fd, info->nsid, zone->saddr,
                        num_curr_append_pages - 1, 0U, 0U, 0U, 0U,
                        curr_append_size, buffer, 0U, NULL, &physical_addr);
        release_transfer_size(info, type, curr_transfer_size);
        if (errno)
            return errno;
        buffer = (uint8_t *)buffer + curr_append_size;
        size -= curr_append_size;
    }
    return errno;
}

static int append_to_log_zone(zns_info *info, unsigned long long page_addr,
                              void *buffer, uint32_t size)
{
    while (size) {
        bool change = true;
        unsigned curr_transfer_size = request_transfer_size(info, user_write);
        unsigned curr_append_size = (info->zone_num_pages -
                                     info->curr_log_zone->write_ptr) *
                                    info->page_size;
        if (curr_append_size > curr_transfer_size) {
            curr_append_size = curr_transfer_size;
            change = false;
        }
        if (curr_append_size > size) {
            curr_append_size = size;
            change = false;
        }
        unsigned long long physical_addr = 0ULL;
        unsigned short num_curr_append_pages = curr_append_size /
                                               info->page_size;
        nvme_zns_append(info->fd, info->nsid, info->curr_log_zone->saddr,
                        num_curr_append_pages - 1, 0U, 0U, 0U, 0U,
                        curr_append_size, buffer, 0U, NULL, &physical_addr);
        release_transfer_size(info, user_write, curr_transfer_size);
        if (errno)
            return errno;
        increase_num_valid_page(info->curr_log_zone, num_curr_append_pages);
        increase_write_ptr(info->curr_log_zone, num_curr_append_pages);
        update_page_map(info, page_addr, physical_addr, num_curr_append_pages);
        if (change)
            change_log_zone(info);
        page_addr += num_curr_append_pages;
        physical_addr += num_curr_append_pages;
        buffer = (uint8_t *)buffer + curr_append_size;
        size -= curr_append_size;
    }
    return errno;
}

static int read_logical_block(zns_info *info, logical_block *block,
                              void *buffer)
{
    //FIXME: Proision for contiguos block read, but not written 
    if (block->data_zone)
        read_from_zns(info, block->data_zone->saddr,
                      buffer, block->data_zone->write_ptr * info->page_size,
                      gc_read);
    page_map *prev = block->old_page_maps;
    page_map *start = block->old_page_maps;
    page_map *curr = block->old_page_maps->next;
    decrease_num_valid_page(prev->zone, 1U);
    while (curr) {
        if (curr->page_addr - prev->page_addr != 1ULL ||
            curr->physical_addr - prev->physical_addr != 1ULL) {
            unsigned long long buff_offset = (start->page_addr -
                                              block->s_page_addr) *
                                             info->page_size;
            uint32_t curr_read_size = (prev->page_addr - start->page_addr +
                                       1ULL) * info->page_size;
            read_from_zns(info, start->physical_addr,
                          (uint8_t *)buffer + buff_offset, curr_read_size,
                          gc_read);
            start = curr;
        }
        decrease_num_valid_page(curr->zone, 1U);
        prev = curr;
        curr = curr->next;
    }
    unsigned long long buff_offset = (start->page_addr - block->s_page_addr) *
                                     info->page_size;
    uint32_t curr_read_size = (prev->page_addr - start->page_addr + 1ULL) *
                              info->page_size;
    read_from_zns(info, start->physical_addr,
                  (uint8_t *)buffer + buff_offset, curr_read_size, gc_read);
    return errno;
}

static void merge(zns_info *info, logical_block *block)
{
    pthread_mutex_lock(&block->lock);
    block->old_page_maps = block->page_maps;
    block->page_maps = NULL;
    pthread_mutex_unlock(&block->lock);
    uint32_t size = get_data_offset(block->page_maps_tail->page_addr,
                                    info->zone_num_pages) + 1U;
    if (block->data_zone && block->data_zone->write_ptr > size)
        size = block->data_zone->write_ptr;
    size *= info->page_size;
    uint8_t buffer[size];
    read_logical_block(info, block, buffer);
    pthread_mutex_lock(&info->size_limit_lock);
    info->used_status &= ~gc_read;
    pthread_mutex_unlock(&info->size_limit_lock);
    pthread_mutex_lock(&block->lock);
    // Append old data zone to free zones list
    if (block->data_zone) {
        decrease_write_ptr(block->data_zone, block->data_zone->write_ptr);
        nvme_zns_mgmt_send(info->fd, info->nsid, block->data_zone->saddr,
                           false, NVME_ZNS_ZSA_RESET, 0U, NULL);
        pthread_mutex_lock(&info->zones_lock);
        if (info->free_zones)
            info->free_zones_tail->next = block->data_zone;
        else
            info->free_zones = block->data_zone;
        info->free_zones_tail = block->data_zone;
        ++info->num_free_zones;
        pthread_mutex_unlock(&info->zones_lock);
    }
    pthread_mutex_lock(&info->zones_lock);
    // Get free zone and nullify the next
    block->data_zone = info->free_zones;
    info->free_zones = info->free_zones->next;
    if (!info->free_zones)
        info->free_zones_tail = NULL;
    block->data_zone->next = NULL;
    --info->num_free_zones;
    pthread_mutex_unlock(&info->zones_lock);
    append_to_data_zone(info, block->data_zone, buffer, size, gc_write);
    pthread_mutex_lock(&info->size_limit_lock);
    info->used_status &= ~gc_write;
    pthread_mutex_unlock(&info->size_limit_lock);
    while (block->old_page_maps) {
        page_map *tmp = block->old_page_maps;
        block->old_page_maps = block->old_page_maps->next;
        free(tmp);
    }
    pthread_mutex_unlock(&block->lock);
}

static void *garbage_collection(void *info_ptr)
{
    zns_info *info = (zns_info *)info_ptr;
    uint32_t index = 0U;
    for (;;) {
        while (info->run_gc &&
               info->num_log_zones - info->num_used_log_zones > info->gc_wmark);
        if (!info->num_used_log_zones)
            break;
        logical_block *block = &info->logical_blocks[index];
        while(!block->page_maps) {
	        index = (index + 1U) % info->num_data_zones;
            block = &info->logical_blocks[index];
        }
        // Merge logical block to data zone
        merge(info, block);
        // Check used log zone valid counter
        // if zero reset and add to free zone list
        // Remove zone from used_log_zones
        // if valid_page is zero and add that zone to free zones list
        zone_info *prev = NULL;
        zone_info *free = NULL;
        zone_info *curr = info->used_log_zones;
        while (curr) {
            if (!curr->num_valid_pages) {
                // reset
                decrease_write_ptr(curr, curr->write_ptr);
                nvme_zns_mgmt_send(info->fd, info->nsid, curr->saddr,
                                   false, NVME_ZNS_ZSA_RESET, 0U, NULL);
                pthread_mutex_lock(&info->zones_lock);
                // Remove from used_log_zones
                free = curr;
                curr = curr->next;
                if (prev) {
                    prev->next = curr;
                    if (free == info->used_log_zones_tail)
                        info->used_log_zones_tail = prev;
                } else {
                    info->used_log_zones = curr;
                    if (!info->used_log_zones)
                        info->used_log_zones_tail = NULL;
                }
                free->next = NULL;
                --info->num_used_log_zones;
                if (info->free_zones)
                    info->free_zones_tail->next = free;
                else
                    info->free_zones = free;
                info->free_zones_tail = free;
                ++info->num_free_zones;
                pthread_mutex_unlock(&info->zones_lock);
            } else {
                prev = curr;
                curr = curr->next;
            }
        }
        index = (index + 1U) % info->num_data_zones;
    }
    // check the first zone is free zone or not
    for (zone_info *zone = info->free_zones; zone; zone = zone->next) {
        if (!zone->saddr)
            return NULL;
    }
    // find which logical block has the first zone
    logical_block *block = NULL;
    for (uint32_t i = 0U; i < info->num_data_zones; ++i) {
        if (info->logical_blocks[i].data_zone &&
            !info->logical_blocks[i].data_zone->saddr) {
            block = &info->logical_blocks[i];
            break;
        }
    }
    // clean the first zone
    uint64_t size = block->data_zone->write_ptr * info->page_size;
    uint8_t buffer[size];
    read_from_zns(info, block->data_zone->saddr, buffer, size, gc_read);
    info->used_status &= ~gc_read;
    zone_info *old_data_zone = block->data_zone;
    old_data_zone->write_ptr = 0U;
    nvme_zns_mgmt_send(info->fd, info->nsid, old_data_zone->saddr, false,
                       NVME_ZNS_ZSA_RESET, 0U, NULL);
    block->data_zone = info->free_zones;
    old_data_zone->next = info->free_zones->next;
    if (info->num_free_zones == 1U)
        info->free_zones_tail = old_data_zone;
    info->free_zones = old_data_zone;
    block->data_zone->next = NULL;
    append_to_data_zone(info, block->data_zone, buffer, size, gc_write);
    info->used_status &= ~gc_write;
    return NULL;
}

}
