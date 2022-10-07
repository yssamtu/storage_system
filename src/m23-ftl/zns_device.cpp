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
#include <sys/mman.h>
#include <unistd.h>
#include "zns_device.h"

extern "C" {

// zone in zns
struct zone_info {
    unsigned long long zone_saddr;
    uint32_t num_valid_pages;
    uint32_t write_ptr;
    pthread_mutex_t num_valid_pages_lock;
    pthread_mutex_t write_ptr_lock;
    zone_info *next; // linked in free_zones and used_log_zones_list
};

// page map for log zones
struct page_map {
    uint64_t logical_page_addr;
    unsigned long long physical_addr;
    zone_info *page_zone_info;
    page_map *next; // page map for each logical block
};

// logical block contains data in log zone (page map) and data in data zone (block map)
struct logical_block {
    uint64_t logical_block_saddr;
    page_map *page_maps; // page mapping for this logical block (log zone)
    page_map *old_page_maps;
    zone_info *block_map; // block mapping for this logical block (data zone)
    //TODO: LOCK the access
    pthread_mutex_t logical_block_lock;
};

struct zns_info {
    // Values from init parameters
    int num_log_zones;
    int gc_wmark;
    pthread_t gc_thread;
    bool run_gc;
    // Query the nsid for following info
    int fd;
    unsigned nsid;
    uint32_t zns_page_size;
    uint32_t zns_num_zones;
    uint32_t zone_num_pages;
    uint32_t num_data_zones;
    uint32_t mdts; // max data transfer size (read limit)
    uint32_t zasl; // zone append size limit (append limit)
    // Log zones
    zone_info *curr_log_zone;
    int num_used_log_zones;
    zone_info *used_log_zones_list;
    zone_info *used_log_zones_list_tail;
    // Free zones
    uint32_t num_free_zones;
    zone_info *free_zones_list;
    zone_info *free_zones_list_tail;
    pthread_mutex_t zones_list_lock;
    // logical block corresponding to each data zone
    logical_block *logical_blocks;
};

static inline void increase_zone_num_valid_page(zone_info *zone,
                                                uint32_t num_pages);
static inline void decrease_zone_num_valid_page(zone_info *zone,
                                                uint32_t num_pages);
static inline void increase_zone_write_ptr(zone_info *zone,
                                           uint32_t num_pages);
static inline void decrease_zone_write_ptr(zone_info *zone,
                                           uint32_t num_pages);
static inline uint32_t get_block_index(uint32_t key, uint32_t base);
static inline uint32_t get_data_offset(uint32_t key, uint32_t base);
static void change_log_zone(zns_info *info);
static bool look_up_map(page_map *maps, uint64_t logical_page_addr,
                        unsigned long long *physical_addr);
static void update_map(zns_info *info, uint64_t logical_page_addr,
                       unsigned long long physical_addr);
static int read_from_zns(zns_info *info, unsigned long long physical_addr,
                         void *buffer, uint32_t size);
static int append_to_data_zone(zns_info *info, unsigned long long saddr,
                               void *buffer, uint32_t size);
static int append_to_log_zone(zns_info *info, uint64_t logical_page_addr,
                              void *buffer, uint32_t size);
static void merge(zns_info *info, logical_block *block, zone_info *new_zone);
static void *garbage_collection(void *info_ptr);

static inline void increase_zone_num_valid_page(zone_info *zone,
                                                uint32_t num_pages)
{
    pthread_mutex_lock(&zone->num_valid_pages_lock);
    zone->num_valid_pages += num_pages;
    pthread_mutex_unlock(&zone->num_valid_pages_lock);
}

static inline void decrease_zone_num_valid_page(zone_info *zone,
                                                uint32_t num_pages)
{
    pthread_mutex_lock(&zone->num_valid_pages_lock);
    zone->num_valid_pages -= num_pages;
    pthread_mutex_unlock(&zone->num_valid_pages_lock);
}

static inline void increase_zone_write_ptr(zone_info *zone,
                                           uint32_t num_pages)
{
    pthread_mutex_lock(&zone->write_ptr_lock);
    zone->write_ptr += num_pages;
    pthread_mutex_unlock(&zone->write_ptr_lock);
}

static inline void decrease_zone_write_ptr(zone_info *zone,
                                           uint32_t num_pages)
{
    pthread_mutex_lock(&zone->write_ptr_lock);
    zone->write_ptr -= num_pages;
    pthread_mutex_unlock(&zone->write_ptr_lock);
}

static inline uint32_t get_block_index(uint32_t key, uint32_t base)
{
    return key / base;
}

static inline uint32_t get_data_offset(uint32_t key, uint32_t base)
{
    return key % base;
}

static void change_log_zone(zns_info *info)
{
    pthread_mutex_lock(&info->zones_list_lock); // Lock for changing used_log_zones_list and accessing free zones list;
    if (info->used_log_zones_list)
        info->used_log_zones_list_tail->next = info->curr_log_zone;
    else
        info->used_log_zones_list = info->curr_log_zone;
    info->used_log_zones_list_tail = info->curr_log_zone;
    ++info->num_used_log_zones;
    info->curr_log_zone = NULL;
    pthread_mutex_unlock(&info->zones_list_lock);
    while (info->num_used_log_zones == info->num_log_zones);
    //Dequeue from free_zone to curr_log_zone;
    while (!info->curr_log_zone) {
        pthread_mutex_lock(&info->zones_list_lock);
        if (info->num_free_zones > 1) {
            info->curr_log_zone = info->free_zones_list;
            info->free_zones_list = info->free_zones_list->next;
            info->curr_log_zone->next = NULL;
            --info->num_free_zones;
        }
        pthread_mutex_unlock(&info->zones_list_lock);
    }
}

static bool look_up_map(page_map *maps, uint64_t logical_page_addr,
                        unsigned long long *physical_addr)
{
    //Lock the logical block
    //Search in log zone
    for (page_map *head = maps; head; head = head->next) {
        if (head->logical_page_addr > logical_page_addr)
            return false;
        if (head->logical_page_addr == logical_page_addr) {
            *physical_addr = head->physical_addr;
            return true;
        }
    }
    return false;
}

static void update_map(zns_info *info, uint64_t logical_page_addr,
                       unsigned long long physical_addr)
{
    uint32_t index = get_block_index(logical_page_addr, info->zone_num_pages);
    logical_block *block = &info->logical_blocks[index];
    increase_zone_num_valid_page(info->curr_log_zone, 1);
    increase_zone_write_ptr(info->curr_log_zone, 1);
    //Lock for updating page map
    pthread_mutex_lock(&block->logical_block_lock);
    if (!block->page_maps) {
    	block->page_maps = (page_map *)calloc(1, sizeof(page_map));
        block->page_maps->logical_page_addr = logical_page_addr;
        block->page_maps->physical_addr = physical_addr;
        block->page_maps->page_zone_info = info->curr_log_zone;
	    pthread_mutex_unlock(&block->logical_block_lock);
        return;
    }
    if (block->page_maps->logical_page_addr == logical_page_addr) {
        //Update log counter
        decrease_zone_num_valid_page(block->page_maps->page_zone_info, 1);
        block->page_maps->physical_addr = physical_addr;
        block->page_maps->page_zone_info = info->curr_log_zone;
        pthread_mutex_unlock(&block->logical_block_lock);
        return;
    }
    if (block->page_maps->logical_page_addr > logical_page_addr) {
        page_map *tmp = (page_map *)calloc(1, sizeof(page_map));
        tmp->next = block->page_maps;
        block->page_maps = tmp;
        tmp->logical_page_addr = logical_page_addr;
        tmp->physical_addr = physical_addr;
        tmp->page_zone_info = info->curr_log_zone;
        pthread_mutex_unlock(&block->logical_block_lock);
        return;
    }
    page_map *ptr = block->page_maps;
    while (ptr->next) {
        if (ptr->next->logical_page_addr == logical_page_addr) {
            //Update log counter
            decrease_zone_num_valid_page(ptr->next->page_zone_info, 1);
	        ptr->next->physical_addr = physical_addr;
            ptr->next->page_zone_info = info->curr_log_zone;
	        pthread_mutex_unlock(&block->logical_block_lock);
	        return;
        } else if (ptr->next->logical_page_addr > logical_page_addr) {
            page_map *tmp =  (page_map *)calloc(1, sizeof(page_map));
            tmp->next = ptr->next;
            ptr->next = tmp;
            tmp->logical_page_addr = logical_page_addr;
            tmp->physical_addr = physical_addr;
            tmp->page_zone_info = info->curr_log_zone;
	        pthread_mutex_unlock(&block->logical_block_lock);
            return;
        }
        ptr = ptr->next;
    }
    ptr->next = (page_map *)calloc(1, sizeof(page_map));
    ptr->next->logical_page_addr = logical_page_addr;
    ptr->next->physical_addr = physical_addr;
    ptr->next->page_zone_info = info->curr_log_zone;
    pthread_mutex_unlock(&block->logical_block_lock);
}

static int read_from_zns(zns_info *info, unsigned long long physical_addr,
                         void *buffer, uint32_t size)
{
    unsigned short num_pages = size / info->zns_page_size;
    nvme_read(info->fd, info->nsid, physical_addr, num_pages - 1,
              0U, 0U, 0U, 0U, 0U,size, buffer, 0U, NULL);
    return errno;
}

static int append_to_data_zone(zns_info *info, unsigned long long saddr,
                               void *buffer, uint32_t size)
{
    uint32_t appended_size = 0U;
    while (appended_size < size) {
        unsigned long long physical_addr = 0ULL;
        uint32_t curr_append_size = info->zasl;
        if (curr_append_size > size - appended_size)
            curr_append_size = size - appended_size;
        unsigned short num_curr_append_pages = curr_append_size / info->zns_page_size;
        nvme_zns_append(info->fd, info->nsid, saddr, num_curr_append_pages - 1,
                        0U, 0U, 0U, 0U, curr_append_size,
                        (char *)buffer + appended_size, 0U, NULL, &physical_addr);
        if (errno)
            return errno;
        appended_size += curr_append_size;
    }
    return errno;
}

static int append_to_log_zone(zns_info *info, uint64_t logical_page_addr,
                              void *buffer, uint32_t size)
{
    uint32_t appended_size = 0U;
    while (appended_size < size) {
        unsigned long long physical_addr = 0ULL;
        bool need_to_change_log_zone = true;
        uint32_t curr_append_size = (info->zone_num_pages -
                                    info->curr_log_zone->write_ptr) *
                                    info->zns_page_size;
        if (curr_append_size > info->zasl) {
            curr_append_size = info->zasl;
            need_to_change_log_zone = false;
        }
        if (curr_append_size > size - appended_size) {
            curr_append_size = size - appended_size;
            need_to_change_log_zone = false;
        }
        unsigned short num_curr_append_pages = curr_append_size /
                                               info->zns_page_size;
        nvme_zns_append(info->fd, info->nsid, info->curr_log_zone->zone_saddr,
                        num_curr_append_pages - 1, 0U, 0U, 0U, 0U,
                        curr_append_size, (char *)buffer + appended_size,
                        0U, NULL, &physical_addr);
        if (errno)
            return errno;
        for (uint32_t i = 0U; i < num_curr_append_pages;
             ++i, ++logical_page_addr, ++physical_addr)
            update_map(info, logical_page_addr, physical_addr);
        if (need_to_change_log_zone)
            change_log_zone(info);
        appended_size += curr_append_size;
    }
    return errno;
}

static void merge(zns_info *info, logical_block *block, zone_info *new_zone)
{
    pthread_mutex_lock(&block->logical_block_lock);
    block->old_page_maps = block->page_maps;
    block->page_maps = NULL;
    pthread_mutex_unlock(&block->logical_block_lock);
    page_map *ptr = block->old_page_maps;
    zone_info *old_used_data_zone = block->block_map;
    uint32_t zone_append_page_limit = info->zasl / info->zns_page_size;
    char * buffer = (char *)calloc(info->zasl, sizeof(char));
    for (uint32_t offset = 0U; offset < info->zone_num_pages; ++offset) {
        unsigned long long page_physical_addr = 0ULL;
        bool have_data = false;
        bool still_have_data = false;
        // if data in data zone
        if (old_used_data_zone) {
            have_data = true;
            page_physical_addr = old_used_data_zone->zone_saddr + offset;
            decrease_zone_write_ptr(old_used_data_zone, 1);
            if (old_used_data_zone->write_ptr)
                still_have_data = true;
        }
        // if data in log zone
        if (ptr &&
            ptr->logical_page_addr == block->logical_block_saddr + offset) {
            have_data = true;
            page_physical_addr = ptr->physical_addr;
            decrease_zone_num_valid_page(ptr->page_zone_info, 1);
            ptr = ptr->next;
            if (ptr)
                still_have_data = true;
        }
        if (have_data)
            read_from_zns(info, page_physical_addr,
                          buffer + (offset % zone_append_page_limit) * info->zns_page_size,
                          info->zns_page_size);
        if (!still_have_data) {
            append_to_data_zone(info, new_zone->zone_saddr, buffer,
                                (offset % zone_append_page_limit + 1) * info->zns_page_size);
            increase_zone_write_ptr(new_zone,
                                    offset % zone_append_page_limit + 1);
            break;
        }
        if (offset % zone_append_page_limit == zone_append_page_limit - 1) {
            append_to_data_zone(info, new_zone->zone_saddr,
                                buffer, info->zasl);
            increase_zone_write_ptr(new_zone, zone_append_page_limit);
            memset(buffer, 0, info->zasl);
        }
    }
    free(buffer);
    pthread_mutex_lock(&block->logical_block_lock);
    while (block->old_page_maps) {
        page_map *tmp = block->old_page_maps;
        block->old_page_maps = block->old_page_maps->next;
        free(tmp);
    }
    block->block_map = new_zone;
    pthread_mutex_unlock(&block->logical_block_lock);
    // Append old data zone to free zones list
    pthread_mutex_lock(&info->zones_list_lock);
    if (old_used_data_zone) {
        decrease_zone_write_ptr(old_used_data_zone,
                                old_used_data_zone->write_ptr);
        nvme_zns_mgmt_send(info->fd, info->nsid,
                           old_used_data_zone->zone_saddr, false,
                           NVME_ZNS_ZSA_RESET, 0U, NULL);
        if (info->free_zones_list)
            info->free_zones_list_tail->next = old_used_data_zone;
        else
            info->free_zones_list = old_used_data_zone;
        info->free_zones_list_tail = old_used_data_zone;
        ++info->num_free_zones;
    }
    pthread_mutex_unlock(&info->zones_list_lock);
}

static void *garbage_collection(void *info_ptr)
{
    zns_info *info = (zns_info *)info_ptr;
    uint32_t index = 0U;
    while (info->run_gc) {
        while (info->num_log_zones - info->num_used_log_zones >
               info->gc_wmark) {
            if (!info->run_gc)
                return NULL;
        }
        logical_block *block = &info->logical_blocks[index];
        while(!block->page_maps) {
	        index = (index + 1) % info->num_data_zones;
            block = &info->logical_blocks[index];
            if (!info->run_gc)
                return NULL;
        }
        pthread_mutex_lock(&info->zones_list_lock);
        // Get free zone and nullify the next
        zone_info *free_zone = info->free_zones_list;
        info->free_zones_list = info->free_zones_list->next;
        if (!info->free_zones_list)
            info->free_zones_list_tail = NULL;
        free_zone->next = NULL;
        --info->num_free_zones;
        pthread_mutex_unlock(&info->zones_list_lock);
        if (!info->run_gc)
            return NULL;
        // Merge logical block to data zone
        merge(info, block, free_zone);
        if (!info->run_gc)
            return NULL;
        // Check used log zone valid counter if zero reset and add to free zone list
        // Remove zone from used_log_zones_list if valid_page is zero and add that zone to free zones list
        pthread_mutex_lock(&info->zones_list_lock);
        for (zone_info *prev = NULL, *free = NULL,
                       *tmp = info->used_log_zones_list; info->run_gc && tmp;) {
            if (!tmp->num_valid_pages) {
                // Remove from used_log_zones
                free = tmp;
                tmp = tmp->next;
                if (prev) {
                    prev->next = tmp;
                } else {
                    info->used_log_zones_list = tmp;
                    if (!tmp)
                        info->used_log_zones_list_tail = tmp;
                }
                free->next = NULL;
                // reset
                decrease_zone_write_ptr(free, free->write_ptr);
                nvme_zns_mgmt_send(info->fd, info->nsid,
                                   free->zone_saddr, false,
                                   NVME_ZNS_ZSA_RESET, 0U, NULL);
                --info->num_used_log_zones;
                if (info->free_zones_list)
                    info->free_zones_list_tail->next = free;
                else
                    info->free_zones_list = free;
                info->free_zones_list_tail = free;
                ++info->num_free_zones;
            } else {
                prev = tmp;
                tmp = tmp->next;
            }
        }
        pthread_mutex_unlock(&info->zones_list_lock);
        index = (index + 1) % info->num_data_zones;
    }
    return NULL;
}

int init_ss_zns_device(struct zdev_init_params *params,
                       struct user_zns_device **my_dev)
{
    //Assign the private ptr to zns_info
    *my_dev = (user_zns_device *)calloc(1, sizeof(user_zns_device));
    (*my_dev)->_private = calloc(1, sizeof(zns_info));
    zns_info *info = (zns_info *)(*my_dev)->_private;
    // set num_log_zones
    info->num_log_zones = params->log_zones;
    // set gc_wmark
    info->gc_wmark = params->gc_wmark;
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
        ret = nvme_zns_mgmt_send(info->fd, info->nsid, 0ULL, true,
                                 NVME_ZNS_ZSA_RESET, 0U, NULL);
        if (ret) {
            printf("Zone reset failed %d\n", ret);
            return ret;
        }
    }
    // set zns_lba_size or zns_page_size : Its same for now!
    nvme_id_ns ns;
    ret = nvme_identify_ns(info->fd, info->nsid, &ns);
    if (ret) {
        printf("Failed to retrieve the nvme identify namespace %d\n", ret);
        return ret;
    }
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[ns.flbas & 0xF].ds;
    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    info->zns_page_size = (*my_dev)->tparams.zns_lba_size;
    // set zns_num_zones
    nvme_zone_report zns_report;
    ret = nvme_zns_mgmt_recv(info->fd, info->nsid, 0ULL,
                             NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL,
                             false, sizeof(zns_report), &zns_report);
    if (ret) {
        printf("Failed to report zones, ret %d\n", ret);
        return ret;
    }
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zns_report.nr_zones);
    info->zns_num_zones = (*my_dev)->tparams.zns_num_zones;
    // set num_data_zones = zns_num_zones - num_log_zones
    info->num_data_zones = info->zns_num_zones - info->num_log_zones;
    // set zone_num_pages
    nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    info->zone_num_pages = data.lbafe[ns.flbas & 0xF].zsze;
    // set zns_zone_capacity = #page_per_zone * zone_size
    (*my_dev)->tparams.zns_zone_capacity = info->zone_num_pages *
                                           (*my_dev)->tparams.zns_lba_size;
    // set user capacity bytes = #data_zones * zone_capacity
    (*my_dev)->capacity_bytes = (info->num_data_zones) *
                                (*my_dev)->tparams.zns_zone_capacity;
    // set max_data_transfer_size
    struct nvme_id_ctrl ctrl;
    nvme_identify_ctrl(info->fd, &ctrl);
    void *regs = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED, info->fd, 0L);
    if (errno) {
        printf("Failed to mmap\n");
        return errno;
    }
    info->mdts = ((1U << (NVME_CAP_MPSMIN(nvme_mmio_read64(regs)) + ctrl.mdts)) - 1) *
                 (*my_dev)->lba_size_bytes;
    // set zone_append_size_limit
    struct nvme_zns_id_ctrl id;
    nvme_zns_identify_ctrl(info->fd, &id);
    info->zasl = ((1U << (NVME_CAP_MPSMIN(nvme_mmio_read64(regs)) + id.zasl)) - 1) *
                 (*my_dev)->lba_size_bytes;
    munmap(regs, getpagesize());
    if (errno) {
        printf("Failed to munmap\n");
        return errno;
    }
    // init zones_list_lock
    pthread_mutex_init(&info->zones_list_lock, NULL);
    // set all zone index to free_zones_list
    info->free_zones_list = (zone_info *)calloc(1, sizeof(zone_info));
    info->free_zones_list_tail = info->free_zones_list;
    pthread_mutex_init(&info->free_zones_list->num_valid_pages_lock, NULL);
    pthread_mutex_init(&info->free_zones_list->write_ptr_lock, NULL);
    for (uint32_t i = 1; i < info->zns_num_zones; ++i) {
        info->free_zones_list_tail->next = (zone_info *)calloc(1, sizeof(zone_info));
        info->free_zones_list_tail = info->free_zones_list_tail->next;
        info->free_zones_list_tail->zone_saddr = i * info->zone_num_pages;
        pthread_mutex_init(&info->free_zones_list_tail->num_valid_pages_lock, NULL);
        pthread_mutex_init(&info->free_zones_list_tail->write_ptr_lock, NULL);
    }
    // set num_free_zones
    info->num_free_zones = info->zns_num_zones;
    //Set current log zone to 0th zone
    info->curr_log_zone = info->free_zones_list;
    info->free_zones_list = info->free_zones_list->next;
    if (!info->free_zones_list)
        info->free_zones_list_tail = NULL;
    info->curr_log_zone->next = NULL;
    info->curr_log_zone->num_valid_pages = 0U;
    --info->num_free_zones;
    // set log zone page mapped hashmap size to num_data_zones
    info->logical_blocks = (logical_block *)calloc(info->num_data_zones,
                                                   sizeof(logical_block));
    for (uint32_t i = 0U; i < info->num_data_zones; ++i) {
        info->logical_blocks[i].logical_block_saddr = i * info->zone_num_pages;
        pthread_mutex_init(&info->logical_blocks[i].logical_block_lock, NULL);
    }
    //Start GC
    info->run_gc = true;
    pthread_create(&info->gc_thread, NULL, &garbage_collection, (void *)info);
    return 0;
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address,
                     void *buffer, uint32_t size)
{
    zns_info *info = (zns_info *)my_dev->_private;
    //FIXME: Proision for contiguos block read, but not written contiguous
    uint32_t logical_page_addr = address / info->zns_page_size;
    uint32_t index = get_block_index(logical_page_addr, info->zone_num_pages);
    logical_block *block = &info->logical_blocks[index];
    pthread_mutex_lock(&block->logical_block_lock);
    // read data from data zone
    if (block->block_map) {
        uint32_t read_size = 0U;
        uint32_t offset = get_data_offset(logical_page_addr,
                                          info->zone_num_pages);
        while (read_size < size) {
            uint32_t curr_read_size = info->mdts;
            if (curr_read_size > size - read_size)
                curr_read_size = size - read_size;
            read_from_zns(info, block->block_map->zone_saddr + offset + read_size,
                          buffer, curr_read_size);
            read_size += curr_read_size;
        }
    }
    // read data from log zone
    unsigned long long curr_start_physical_addr = 0ULL;
    uint32_t curr_read_offset = 0U;
    uint32_t curr_read_size = 0U;
    unsigned long long prev_physical_addr = 0ULL;
    page_map *curr_page_map = block->page_maps ? block->page_maps :
                                                 block->old_page_maps;
    for (uint32_t i = 0U; i < size; i += info->zns_page_size, ++logical_page_addr) {
        unsigned long long physical_addr = 0ULL;
        bool get_addr = look_up_map(curr_page_map,
                                    logical_page_addr, &physical_addr);
        if (get_addr) {
            if (!curr_read_size) {
                curr_start_physical_addr = physical_addr;
                curr_read_offset = i;
            } else if (physical_addr - prev_physical_addr != 1) { // if physical address are not continuous
                read_from_zns(info, curr_start_physical_addr,
                              (char *)buffer + curr_read_offset, curr_read_size);
                curr_start_physical_addr = physical_addr;
                curr_read_offset = i;
                curr_read_size = 0U;
            }
            curr_read_size += info->zns_page_size;
            if (curr_read_size == info->mdts) { // if current read size is equal to mdts, then read data from zns
                read_from_zns(info, curr_start_physical_addr,
                              (char *)buffer + curr_read_offset, curr_read_size);
                curr_read_size = 0U;
            } else {
                prev_physical_addr = physical_addr;
            }
        } else if (curr_read_size) { // if physical address are not continuous
            read_from_zns(info, curr_start_physical_addr,
                          (char *)buffer + curr_read_offset, curr_read_size);
            curr_read_size = 0U;
        }
    }
    if (curr_read_size) // read the rest of data
        read_from_zns(info, curr_start_physical_addr,
                      (char *)buffer + curr_read_offset, curr_read_size);
    pthread_mutex_unlock(&block->logical_block_lock);
    return errno;
}

int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address,
                      void *buffer, uint32_t size)
{
    zns_info *info = (zns_info *)my_dev->_private;
    while (size > 0) {
        uint32_t index = get_block_index(address / info->zns_page_size,
                                         info->zone_num_pages);
        logical_block *block = &info->logical_blocks[index];
        uint32_t offset = get_data_offset(address / info->zns_page_size,
                                          info->zone_num_pages);
        uint32_t curr_append_size = 0U;
        pthread_mutex_lock(&block->logical_block_lock);
        // if can write to data zone directly
        if (!block->old_page_maps && block->block_map &&
            block->block_map->write_ptr <= offset) {
            if (block->block_map->write_ptr < offset) {
                // append null data until arrive offset
                uint32_t null_size = (offset - block->block_map->write_ptr) *
                                     info->zns_page_size;
                char *null_buffer = (char *)calloc(null_size, sizeof(char));
                int ret = append_to_data_zone(info, block->block_map->zone_saddr,
                                              null_buffer, null_size);
                free(null_buffer);
                if (ret) {
                    pthread_mutex_unlock(&block->logical_block_lock);
                    return ret;
                }
                increase_zone_write_ptr(block->block_map,
                                        offset - block->block_map->write_ptr);
            }
            curr_append_size = (info->zone_num_pages - offset) *
                               info->zns_page_size;
            if (curr_append_size > size)
                curr_append_size = size;
            int ret = append_to_data_zone(info, block->block_map->zone_saddr,
                                          buffer, curr_append_size);
            if (ret) {
                pthread_mutex_unlock(&block->logical_block_lock);
                return ret;
            }
            increase_zone_write_ptr(block->block_map,
                                    curr_append_size / info->zns_page_size);
            pthread_mutex_unlock(&block->logical_block_lock);
        } else {
            curr_append_size = size;
            if (!block->old_page_maps && block->block_map) {
                uint32_t diff_size = (block->block_map->write_ptr - offset) *
                                     info->zns_page_size;
                if (curr_append_size > diff_size)
                    curr_append_size = diff_size;
            }
            pthread_mutex_unlock(&block->logical_block_lock);
            int ret = append_to_log_zone(info, address / info->zns_page_size,
                                         buffer, curr_append_size);
            if (ret)
                return ret;
        }
        address += curr_append_size;
        buffer = (char *)buffer + curr_append_size;
        size -= curr_append_size;
    }
    return 0;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev)
{
    zns_info *info = (zns_info *)my_dev->_private;
    // Kill gc
    info->run_gc = false;
    pthread_join(info->gc_thread, NULL);
    logical_block *blocks = info->logical_blocks;
    // free hashmap
    for (uint32_t i = 0U; i < info->num_data_zones; ++i) {
	    // Clear all log heads for a logical block
        while (blocks[i].page_maps) {
            page_map *tmp = blocks[i].page_maps;
            blocks[i].page_maps = blocks[i].page_maps->next;
            free(tmp);
        }
        if (blocks[i].block_map) {
            pthread_mutex_destroy(&blocks[i].block_map->num_valid_pages_lock);
            pthread_mutex_destroy(&blocks[i].block_map->write_ptr_lock);
	        free(blocks[i].block_map);
        }
        pthread_mutex_destroy(&blocks[i].logical_block_lock);
    }
    free(blocks);
    while (info->used_log_zones_list) {
        zone_info *tmp = info->used_log_zones_list;
        info->used_log_zones_list = info->used_log_zones_list->next;
        pthread_mutex_destroy(&tmp->num_valid_pages_lock);
        pthread_mutex_destroy(&tmp->write_ptr_lock);
        free(tmp);
    }
    while (info->free_zones_list) {
        zone_info *tmp = info->free_zones_list;
        info->free_zones_list = info->free_zones_list->next;
        pthread_mutex_destroy(&tmp->num_valid_pages_lock);
        pthread_mutex_destroy(&tmp->write_ptr_lock);
        free(tmp);
    }
    pthread_mutex_destroy(&info->curr_log_zone->num_valid_pages_lock);
    pthread_mutex_destroy(&info->curr_log_zone->write_ptr_lock);
    free(info->curr_log_zone);
    pthread_mutex_destroy(&info->zones_list_lock);
    free(info);
    free(my_dev);
    return 0;
}

}
