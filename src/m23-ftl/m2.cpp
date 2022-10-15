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

#include <cassert>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <unistd.h>
#include "./zns_device.h"
#include "../common/utils.h"

extern "C" {

static int write_read_random_lbas(const user_zns_device &my_dev, void *buf,
                                  const uint32_t &buf_size,
                                  const uint64_t &max_lbas_to_test)
{
    uint32_t max_lba_entries = my_dev.capacity_bytes / my_dev.lba_size_bytes;
    if (max_lba_entries < max_lbas_to_test) {
        std::cout << "Error: not sufficient LBAs available, pass a smaller \
number" << std::endl;
        return -1;
    }
    const uint64_t max_lba_to_generate = max_lba_entries - max_lbas_to_test;
    // lets pick a random start offset
    const uint64_t start_lba = 0UL + rand() % (max_lba_to_generate - 0UL);
    // now starting from "s" lba,
    // we are going to write out max_lbas_to_test LBAs
    for (uint64_t i = start_lba; i < start_lba + max_lbas_to_test; ++i) {
        // make a unique pattern for each write - ith iteration
        write_pattern_with_start(static_cast<char *>(buf), buf_size, i);
        int ret = zns_udevice_write(const_cast<user_zns_device *>(&my_dev),
                                    i * my_dev.lba_size_bytes, buf, buf_size);
        if (ret) {
            std::cout << "Error: writing the device failed at address 0x"
                      << std::hex << i * my_dev.lba_size_bytes << std::dec
                      << " [index " << i - start_lba << "]" << std::endl;
            return ret;
        }
    }
    std::cout << "Writing of " << max_lbas_to_test
              << " unique LBAs OK" << std::endl;
    // otherwise all writes passed - now we test reading
    for (uint64_t i = start_lba; i < start_lba + max_lbas_to_test; ++i) {
        // make a unique pattern for each write
        bzero(static_cast<char *>(buf), buf_size);
        int ret = zns_udevice_read(const_cast<user_zns_device *>(&my_dev),
                                   i * my_dev.lba_size_bytes, buf, buf_size);
        if (ret) {
            std::cout << "Error: writing the device failed at address 0x"
                      << std::hex << i * my_dev.lba_size_bytes << std::dec
                      << " [index " << i - start_lba << "]" << std::endl;
            return ret;
        }
        // now we match - for ith pattern - if it fails it asserts
        match_pattern_with_start(static_cast<char *>(buf), buf_size, i);
    }
    std::cout << "Reading and matching of " << max_lbas_to_test
              << " unique LBAs OK" << std::endl;
    return 0;
}

static int write_read_lba0(const user_zns_device &dev,
                           void *buf, const uint32_t &buf_size)
{
    write_pattern(static_cast<char *>(buf), buf_size);
    uint64_t test_lba = 0UL;
    int ret = zns_udevice_write(const_cast<user_zns_device *>(&dev), test_lba,
                                buf, buf_size);
    if (ret) {
        std::cout << "Error: writing the device failed at address 0x"
                  << std::hex << test_lba << std::dec << std::endl;
        return ret;
    }
    std::cout << buf_size << " bytes written successfully on lba 0x"
              << std::hex << test_lba << std::dec << std::endl;
    // zero it out
    bzero(buf, buf_size);
    ret = zns_udevice_read(const_cast<user_zns_device *>(&dev), test_lba,
                           buf, buf_size);
    if (ret) {
        std::cout << "Error: reading the device failed at address 0x"
                  << std::hex << test_lba << std::dec << std::endl;
        return ret;
    }
    std::cout << buf_size << " bytes read successfully on lba 0x"
              << std::hex << test_lba << std::dec << std::endl;
    match_pattern(static_cast<char *>(buf), buf_size);
    return 0;
}

static int show_help()
{
    std::cout << "Usage: m2 -d device_name -h -r" << std::endl;
    std::cout << "-d : /dev/nvmeXpY - in this format with the full path"
              << std::endl;
    std::cout << "-r : resume if the FTL can." << std::endl;
    std::cout << "-l : the number of zones to use for log/metadata \
(default, minimum = 3)." << std::endl;
    std::cout << "-h : shows help, and exits with success. No argument needed"
              << std::endl;
    return 0;
}

int main(int argc, char *argv[])
{
    uint64_t start = microseconds_since_epoch();
    srand(static_cast<unsigned>(time(nullptr)) * getpid());
    zdev_init_params params = {
        .name = nullptr,
        .log_zones = 3,
        .gc_wmark = 1,
        .force_reset = true
    };
    uint64_t max_num_lba_to_test = 0UL;
    std::cout << "=============================================================\
========================" << std::endl;
    std::cout << "This is M2. The goal of this milestone is to implement a \
hybrid log-structure ZTL (Zone Translation Layer) on top of the ZNS (no GC)"
              << std::endl;
    std::cout << "=============================================================\
========================" << std::endl;
    int c = 0;
    char *zns_device_name = const_cast<char *>("nvme0n1");
    char *str1 = nullptr;
    while ((c = getopt(argc, argv, "l:d:hr")) != -1) {
        switch (c) {
            case 'h':
                show_help();
                exit(0);
            case 'r':
                params.force_reset = false;
                break;
            case 'd':
                str1 = strdupa(optarg);
                if (!str1) {
                    std::cout << "Could not parse the arguments for the device "
                              << optarg << std::endl;
                    exit(EXIT_FAILURE);
                }
                for (int j = 1; ; ++j) {
                    char *token = strsep(&str1, "/"); // delimited is "/"
                    if (!token)
                        break;
                    // if there was a valid parse, just save it
                    zns_device_name = token;
                }
                free(str1);
                break;
            case 'l':
                params.log_zones = atoi(optarg);
                if (params.log_zones < 3) {
                    std::cout << "you need 3 or more zones for the log area \
(metadata (think: milestone 5) + log). You passed "
                              << params.log_zones << std::endl;
                    exit(-1);
                }
                break;
            default:
                show_help();
                exit(-1);
        }
    }
    params.name = strdup(zns_device_name);
    std::cout << "parameter settings are: device-name " << params.name
              << " log_zones " << params.log_zones
              << " gc-watermark " << params.gc_wmark
              << " force-reset " << (params.force_reset ? "yes" : "no")
              << std::endl;
    user_zns_device *my_dev = nullptr;
    int ret = init_ss_zns_device(&params, &my_dev);
    assert (!ret);
    assert(my_dev->lba_size_bytes);
    assert(my_dev->capacity_bytes);
    max_num_lba_to_test = (params.log_zones - 1) *
                          (my_dev->tparams.zns_zone_capacity /
                           my_dev->tparams.zns_lba_size);
    std::cout << "The amount of new pages to be written would be the number of \
(zones - 1) / lba_size : " << max_num_lba_to_test << std::endl;
    std::cout << "Why? we assume one zone will eventually be taken for writing \
metadata, and the rest will be used for the FTL log" << std::endl;
    std::unique_ptr<char []> test_buf(new char[my_dev->lba_size_bytes]());
    int t1 = write_read_lba0(*my_dev, test_buf.get(), my_dev->lba_size_bytes);
    // -1 because we have already written one LBA.
    int t2 = write_read_random_lbas(*my_dev, test_buf.get(),
                                    my_dev->lba_size_bytes,
                                    max_num_lba_to_test - 1UL);
    ret = deinit_ss_zns_device(my_dev);
    free(params.name);
    uint64_t end = microseconds_since_epoch();
    std::cout << "=============================================================\
=======" << std::endl;
    std::cout << "Milestone 2 results" << std::endl;
    std::cout << "[stosys-result] Test 1 (write, read, and match on LBA0)   : "
              << (t1 == 0 ? " Passed" : " Failed") << std::endl;
    printf("[stosys-result] Test 2 (%-3lu LBA write, read, match)       : %s \n",
           max_num_lba_to_test, (t2 == 0 ? " Passed" : " Failed"));
    std::cout << "=============================================================\
=======" << std::endl;
    std::cout << "[stosys-stats] The elapsed time is "
              << (end -  start) / 1000UL << " milliseconds" << std::endl;
    std::cout << "=============================================================\
=======" << std::endl;
    return ret;
}

}
