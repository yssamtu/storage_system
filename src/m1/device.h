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


#ifndef STOSYS_PROJECT_DEVICE_H
#define STOSYS_PROJECT_DEVICE_H

#include <libnvme.h>

extern "C" {
// we will use an ss_ extension to differentiate our struct definitions from the standard library
// In C++ we should use namespaces, but I am lazy
struct ss_nvme_ns {
    char *ctrl_name;
    bool supports_zns;
    uint32_t nsid;
};

struct zone_to_test {
    struct nvme_zns_desc desc;
    uint64_t lba_size_in_use;
};

// these three function examples are given to you
int count_and_show_all_nvme_devices();
int scan_and_identify_zns_devices(struct ss_nvme_ns *list);
int show_zns_zone_status(int fd, int nsid, struct zone_to_test *ztest);

// these follow nvme specification I added ss_ prefix to avoid namespace collision with other lbnvme functions
int ss_nvme_device_io_with_mdts(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size,
                                uint64_t lba_size, uint64_t mdts_size, bool read);
int ss_nvme_device_read(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size);
int ss_nvme_device_write(int fd, uint32_t nsid, uint64_t slba, uint16_t numbers, void *buffer, uint64_t buf_size);

// these are ZNS specific commands
int ss_zns_device_zone_reset(int fd, uint32_t nsid, uint64_t slba);
int ss_zns_device_zone_append(int fd, uint32_t nsid, uint64_t zslba, int numbers, void *buffer, uint32_t buf_size,
                              uint64_t *written_slba);

void update_lba(uint64_t &write_lba, const uint32_t lba_size, const int count);
uint64_t get_mdts_size(int fd);
}

#endif //STOSYS_PROJECT_DEVICE_H
