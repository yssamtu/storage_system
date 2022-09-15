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

#include <unistd.h>

#include <ctime>
#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include "./zns_device.h"
#include "../common/utils.h"

extern "C" {

static int write_read_random_lbas(struct user_zns_device *my_dev, void *buf, uint32_t buf_size, uint64_t max_lbas_to_test)
{
    int ret = -1;
    uint32_t max_lba_entries = my_dev->capacity_bytes / my_dev->lba_size_bytes;
    if (max_lba_entries < max_lbas_to_test) {
        printf("Error: not sufficient LBAs available, pass a smaller number \n");
        return -1;
    }
    const uint64_t max_lba_to_generate = max_lba_entries - max_lbas_to_test;
    // lets pick a random start offset
    const uint64_t start_lba = 0 + rand() % (max_lba_to_generate - 0);
    // now starting from "s" lba, we are going to write out max_lbas_to_test LBAs
    for (uint64_t i = start_lba; i < start_lba + max_lbas_to_test; ++i) {
        // make a unique pattern for each write - ith iteration
        write_pattern_with_start((char *)buf, buf_size, i);
        ret = zns_udevice_write(my_dev, i * my_dev->lba_size_bytes, buf, buf_size);
        if (ret) {
            printf("Error: writing the device failed at address 0x%lx [index %lu] \n",
                   i * my_dev->lba_size_bytes, i - start_lba);
            return ret;
        }
    }
    printf("Writing of %lu unique LBAs OK \n", max_lbas_to_test);
    // otherwise all writes passed - now we test reading
    for (uint64_t i = start_lba; i < start_lba + max_lbas_to_test; ++i) {
        // make a unique pattern for each write
        bzero((char *)buf, buf_size);
        ret = zns_udevice_read(my_dev, i * my_dev->lba_size_bytes, buf, buf_size);
        if (ret) {
            printf("Error: writing the device failed at address 0x%lx [index %lu] \n",
                   i * my_dev->lba_size_bytes, i - start_lba);
            return ret;
        }
        // now we match - for ith pattern - if it fails it asserts
        match_pattern_with_start((char *)buf, buf_size, i);
    }
    printf("Reading and matching of %lu unique LBAs OK \n", max_lbas_to_test);
    return 0;
}

static int write_read_lba0(struct user_zns_device *dev, void *buf, uint32_t buf_size)
{
    write_pattern((char *)buf, buf_size);
    uint64_t test_lba = 0;
    int ret = zns_udevice_write(dev, test_lba, buf, buf_size);
    if (ret) {
        printf("Error: writing the device failed at address 0x%lx \n", test_lba);
        return ret;
    }
    printf("%u bytes written successfully on lba 0x%lx \n", buf_size, test_lba);
    // zero it out
    bzero(buf, buf_size);
    ret = zns_udevice_read(dev, test_lba, buf, buf_size);
    if (ret) {
        printf("Error: reading the device failed at address 0x%lx \n", test_lba);
        return ret;
    }
    printf("%u bytes read successfully on lba 0x%lx \n", buf_size, test_lba);
    match_pattern((char *)buf, buf_size);
    return 0;
}

static int show_help()
{
    printf("Usage: m2 -d device_name -h -r \n");
    printf("-d : /dev/nvmeXpY - in this format with the full path \n");
    printf("-r : resume if the FTL can. \n");
    printf("-l : the number of zones to use for log/metadata (default, minimum = 3). \n");
    printf("-h : shows help, and exits with success. No argument needed\n");
    return 0;
}

int main(int argc, char **argv)
{
    uint64_t start, end;
    start = microseconds_since_epoch();
    srand((unsigned)time(NULL) * getpid());
    int ret, c;
    char *zns_device_name = (char *)"nvme0n1", *test_buf = nullptr, *str1 = nullptr;
    struct user_zns_device *my_dev = nullptr;
    struct zdev_init_params params;
    params.force_reset = true;
    params.log_zones = 3;
    params.gc_wmark = 1;

    uint64_t max_num_lba_to_test = 0;
    printf("===================================================================================== \n");
    printf("This is M2. The goal of this milestone is to implement a hybrid log-structure ZTL (Zone Translation Layer) on top of the ZNS (no GC) \n");
    printf("===================================================================================== \n");
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
                printf("Could not parse the arguments for the device %s '\n", optarg);
                exit(EXIT_FAILURE);
            }
            for (int j = 1; ; ++j) {
                char *token = strsep(&str1, "/"); // delimited is "/"
                if (token == nullptr)
                    break;
                // if there was a valid parse, just save it
                zns_device_name = token;
            }
            free(str1);
            break;
        case 'l':
            params.log_zones = atoi(optarg);
            if (params.log_zones < 3) {
                printf("you need 3 or more zones for the log area (metadata (think: milestone 5) + log). You passed %d \n", params.log_zones);
                exit(-1);
            }
            break;
        default:
            show_help();
            exit(-1);
        }
    }
    params.name = strdup(zns_device_name);
    printf("parameter settings are: device-name %s log_zones %d gc-watermark %d force-reset %s\n",
           params.name,params.log_zones, params.gc_wmark, params.force_reset == 1 ? "yes" : "no");
    ret = init_ss_zns_device(&params, &my_dev);
    assert (ret == 0);
    assert(my_dev->lba_size_bytes);
    assert(my_dev->capacity_bytes);
    max_num_lba_to_test = (params.log_zones - 1) * (my_dev->tparams.zns_zone_capacity / my_dev->tparams.zns_lba_size);
    printf("The amount of new pages to be written would be the number of (zones - 1) / lba_size : %lu \n", max_num_lba_to_test);
    printf("Why? we assume one zone will eventually be taken for writing metadata, and the rest will be used for the FTL log \n");
    test_buf = static_cast<char *>(calloc(1, my_dev->lba_size_bytes));
    int t1 = write_read_lba0(my_dev, test_buf, my_dev->lba_size_bytes);
    // -1 because we have already written one LBA.
    int t2 = write_read_random_lbas(my_dev, test_buf, my_dev->lba_size_bytes, max_num_lba_to_test - 1);
    free(test_buf);
    ret = deinit_ss_zns_device(my_dev);
    free(params.name);
    end = microseconds_since_epoch();
    printf("====================================================================\n");
    printf("Milestone 2 results \n");
    printf("[stosys-result] Test 1 (write, read, and match on LBA0)   : %s \n", (t1 == 0 ? " Passed" : " Failed"));
    printf("[stosys-result] Test 2 (%-3lu LBA write, read, match)       : %s \n", max_num_lba_to_test, (t2 == 0 ? " Passed" : " Failed"));
    printf("====================================================================\n");
    printf("[stosys-stats] The elapsed time is %lu milliseconds \n", (end -  start) / 1000);
    printf("====================================================================\n");
    return ret;
}
}