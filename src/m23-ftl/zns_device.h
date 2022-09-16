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

#ifndef STOSYS_PROJECT_ZNS_DEVICE_H
#define STOSYS_PROJECT_ZNS_DEVICE_H

#include <cstdint>

#define METADATA_LOG_MAP_LEN 4000

extern "C" {
//https://github.com/mplulu/google-breakpad/issues/481 - taken from here
#define typeof __typeof__
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

/* after a successful initialization of a device, you must set these ZNS device parameters for testing */
struct zns_device_testing_params {
    // LBA size at the ZNS device
    uint32_t zns_lba_size;
    // Zone size at the ZNS device
    uint32_t zns_zone_capacity;
    // total number of zones
    uint32_t zns_num_zones;
};

struct user_zns_device {
    /* these are user visible properties */
    uint32_t lba_size_bytes; // the user device LBA size - should be some multiple of the ZNS device page size, you can keep it as it is
    uint64_t capacity_bytes; // total user device capacity
    struct zns_device_testing_params tparams; // report back some ZNS device-level properties to the user (for testing only, this is not needed for functions
    // your own private data
    void *_private; //Points to zns_info
};

struct zdev_init_params {
    char *name;
    int log_zones;
    int gc_wmark;
    bool force_reset;
};


struct metadata_log_map {
    //FIXME: Add No of blocks written as well.
    uint64_t logical_address;
    uint64_t physical_address;
    struct metadata_log_map *next;
};

struct zns_info {
    //Fixed values
    int fd;
    int gc_trigger;
    uint32_t nsid;
    uint32_t nvm_page_size;
    uint32_t zone_capacity;
    uint32_t no_of_zones;
    uint32_t no_of_log_zones;
    //Future use
    uint64_t upper_logical_addr_bound;

    //Log zone maintainance
    uint32_t no_of_used_log_zones; //Keep track of used log zones
    uint64_t curr_log_zone_starting_addr; //Point to current log zone starting address
    struct metadata_log_map *map[METADATA_LOG_MAP_LEN]; //Hashmap to store log
};


int hash_function(uint64_t key);
void update_log_map(metadata_log_map *map[METADATA_LOG_MAP_LEN], uint64_t logical_address, uint64_t physical_address);
int lookup_log_map(metadata_log_map *map[METADATA_LOG_MAP_LEN], uint64_t logical_address, uint64_t *physical_address);
int append_data_to_log_zone(zns_info *ptr, void *buffer, uint32_t size, uint64_t *address_written);



int init_ss_zns_device(struct zdev_init_params *params, struct user_zns_device **my_dev);
int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size);
int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size);
int deinit_ss_zns_device(struct user_zns_device *my_dev);
};

#endif //STOSYS_PROJECT_ZNS_DEVICE_H
