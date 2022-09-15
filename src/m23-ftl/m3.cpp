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

#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <iostream>
#include <random>
#include <fcntl.h>

#include "zns_device.h"
#include "../common/utils.h"


static int get_sequence_as_array (uint64_t capacity, uint64_t **arr, bool shuffle) {
    std::vector<uint64_t> myvector;
    std::random_device rd;
    std::mt19937 g(rd());
    uint64_t *tmp = nullptr;
    // set some values:
    for (uint64_t i = 0; i < capacity; i++) {
        myvector.push_back(i);
    }
    if(shuffle) {
        std::shuffle(myvector.begin(), myvector.end(), g);
    }
    tmp = new uint64_t[capacity];
    for(uint64_t i = 0; i < capacity; i++){
        tmp[i] = myvector[i];
    }
    *arr = tmp;
    return 0;
}

extern "C" {

static int _complete_file_io(int fd, uint64_t offset, void *buf, int sz, int is_read){
    int ret;
    uint64_t written_so_far = 0;
    uintptr_t ptr = (uintptr_t) buf;
    while (written_so_far < (uint64_t) sz) {
        if(is_read == 1) {
            ret = pread(fd, (void *) (ptr + written_so_far), sz - written_so_far, offset + written_so_far);
        } else {
            ret = pwrite(fd, (void *) (ptr + written_so_far), sz - written_so_far, offset + written_so_far);
        }
        if(ret < 0){
            printf("file writing failed %d \n", ret);
            return ret;
        }
        //other add and move along
        written_so_far+=ret;
    }
    return 0;
}

static int write_complete_file(int fd, uint64_t offset, void *buf, int sz){
    return _complete_file_io(fd, offset, buf, sz, 0);
}

static int read_complete_file(int fd, uint64_t offset, void *buf, int sz){
    return _complete_file_io(fd, offset, buf, sz, 1);
}

/*
 * Based on if the addr_list was in sequence or randomized - we will do sequential or random I/O
 * --
 * So the idea of this test is to write a parallel file on the side which has the same content, and the
 * ZNS device content should match with this file.
 *
 * addr_list = list of LBAs how they should be accessed
 * list_size = size of the address list
 * max_hammer_io = a random number, for how many times I should randomly do a write on a random LBA
 */
static int wr_full_device_verify(struct user_zns_device *dev,
                                 const uint64_t *addr_list, const uint32_t list_size,
                                 const uint32_t max_hammer_io){
    int ret;
    const char *tmp_file = "./tmp-output-fulld";
    char *b1 = (char*) calloc(1, dev->lba_size_bytes);
    char *b2 = (char*) calloc(1, dev->lba_size_bytes);
    assert(b1 != nullptr);
    assert(b2 != nullptr);

    write_pattern(b1, dev->lba_size_bytes);
    int fd = open(tmp_file, O_RDWR|O_CREAT, 0666);
    if (fd < 0) {
        printf("Error: opening of the temp file failed, ret %d ", fd);
        return -1;
    }
    // allocate this side file to the full capacity
    ret = posix_fallocate(fd, 0, dev->capacity_bytes);
    if(ret){
        printf("Error: fallocate failed, ret %d ", ret);
        return -1;
    }
    printf("fallocate OK with %s and size 0x%lx \n", tmp_file, dev->capacity_bytes);
    // https://stackoverflow.com/questions/29381843/generate-random-number-in-range-min-max
    const int min = 0;
    const int max = dev->lba_size_bytes;
    //initialize the device, otherwise we may have indexes where there is random garbage in both cases
    for(uint32_t i = 0; i < list_size; i++){
        uint64_t woffset = (addr_list[i]) * dev->lba_size_bytes;
        //random offset within the page and just write some random stuff = this is to make a unique I/O pattern
        b1[(min + (rand() % (max - min)))] = (char) rand();
        // now we need to write the buffer in parallel to the zns device, and the file
        ret = zns_udevice_write(dev, woffset, b1, dev->lba_size_bytes);
        if(ret != 0){
            printf("Error: ZNS device writing failed at offset 0x%lx \n", woffset);
            goto done;
        }
        ret = write_complete_file(fd, woffset, b1, dev->lba_size_bytes);
        if(ret != 0){
            printf("Error: file writing failed at offset 0x%lx \n", woffset);
            goto done;
        }
    }
    printf("the ZNS user device has been written (ONCE) completely OK\n");
    if(max_hammer_io > 0){
        printf("Hammering some random LBAs %d times \n", max_hammer_io);
        for(uint32_t i = 0; i < max_hammer_io; i++){
            // we should not generate offset which is within the list_size
            uint64_t woffset = (addr_list[ 0 +  (rand() % (list_size - 0))]) * dev->lba_size_bytes;
            //random offset within the page and just write some random stuff, like i
            b1[(min + (rand() % (max - min)))] = (char) rand();
            // now we need to write the buffer in parallel to the zns device, and the file
            ret = zns_udevice_write(dev, woffset, b1, dev->lba_size_bytes);
            if(ret != 0){
                printf("Error: ZNS device writing failed at offset 0x%lx \n", woffset);
                goto done;
            }
            ret = write_complete_file(fd, woffset, b1, dev->lba_size_bytes);
            if(ret != 0){
                printf("Error: file writing failed at offset 0x%lx \n", woffset);
                goto done;
            }
        }
        printf("Hammering done, OK for %d times \n", max_hammer_io);
    }
    printf("verifying the content of the ZNS device ....\n");
    // reset the buffers
    write_pattern(b1, dev->lba_size_bytes);
    write_pattern(b2, dev->lba_size_bytes);
    // and now read the whole device and compare the content with the file
    for(uint32_t i = 0; i < list_size; i++){
        uint64_t roffset = (addr_list[i]) * dev->lba_size_bytes;
        // now we need to write the buffer in parallel to the zns device, and the file
        ret = zns_udevice_read(dev, roffset, b1, dev->lba_size_bytes);
        assert(ret == 0);
        ret = read_complete_file(fd, roffset, b2, dev->lba_size_bytes);
        assert(ret == 0);
        //now both of these should match
        for(uint32_t j = 0; j < dev->lba_size_bytes; j++)
            if(b1[j] != b2[j]){
                printf("ERROR: buffer mismatch at i %d and j %d , address is 0%lx expecting %x found %x \n",
                       i, j, roffset, b2[j], b1[j]);
                ret = -EINVAL;
                goto done;
            }
    }
    printf("Verification passed on the while device \n");

    done:
    free(b1);
    free(b2);
    close(fd);
    ret = remove(tmp_file);
    if(ret != 0){
        printf("Error: file deleting failed with ret %d \n", ret);
    }
    return ret;
}

static int show_help(){
    printf("Usage: m2 -d device_name -h -r \n");
    printf("-d : /dev/nvmeXpY - in this format with the full path \n");
    printf("-r : resume if the FTL can. \n");
    printf("-l : the number of zones to use for log/metadata (default, minimum = 3). \n");
    printf("-w : watermark threshold, the number of free zones when to trigger the gc (default, minimum = 1). \n");
    printf("-o : overwrite so [int] times  (default, 10,000). \n");
    printf("-h : shows help, and exits with success. No argument needed\n");
    return 0;
}

int main(int argc, char **argv) {
    uint64_t start, end;
    start = microseconds_since_epoch();
    srand( (unsigned) time(NULL) * getpid());
    int ret, c;
    char *zns_device_name = (char*) "nvme0n1", *str1 = nullptr;
    struct user_zns_device *my_dev = nullptr;
    uint64_t *seq_addresses = nullptr, *random_addresses = nullptr;
    uint32_t to_hammer_lba = 10000;

    struct zdev_init_params params;
    params.force_reset = true;
    params.log_zones = 3;
    params.gc_wmark = 1;

    printf("===================================================================================== \n");
    printf("This is M3. The goal of this milestone is to implement a hybrid log-structure ZTL (Zone Translation Layer) on top of the ZNS WITH a GC \n");
    printf("                                                                                                                             ^^^^^^^^^ \n");
    printf("===================================================================================== \n");
    while ((c = getopt(argc, argv, "o:m:l:d:w:hr")) != -1) {
        switch (c) {
            case 'h':
                show_help();
                exit(0);
            case 'r':
                params.force_reset = false;
                break;
            case 'o':
                to_hammer_lba = atoi(optarg);
                break;
            case 'd':
                str1 = strdupa(optarg);
                if (!str1) {
                    printf("Could not parse the arguments for the device %s '\n", optarg);
                    exit(EXIT_FAILURE);
                }
                for (int j = 1; ; j++) {
                    char *token = strsep(&str1, "/"); // delimited is "/"
                    if (token == nullptr) {
                        break;
                    }
                    // if there was a valid parse, just save it
                    zns_device_name = token;
                }
                free(str1);
                break;
            case 'l':
                params.log_zones = atoi(optarg);
                if (params.log_zones < 3){
                    printf("you need 3 or more zones for the log area (metadata (think: milestone 5) + log). You passed %d \n", params.log_zones);
                    exit(-1);
                }
                break;
            case 'w':
                params.gc_wmark = atoi(optarg);
                if (params.gc_wmark < 1){
                    printf("you need 1 or more free zones for continuous working of the FTL. You passed %d \n", params.gc_wmark);
                    exit(-1);
                }
                break;
            default:
                show_help();
                exit(-1);
        }
    }
    params.name = strdup(zns_device_name);
    printf("parameter settings are: device-name %s log_zones %d gc-watermark %d force-reset %s hammer-time %d \n",
           params.name,params.log_zones,params.gc_wmark,params.force_reset==1?"yes":"no", to_hammer_lba);

    ret = init_ss_zns_device(&params, &my_dev);
    assert (ret == 0);
    assert(my_dev->lba_size_bytes != 0);
    assert(my_dev->capacity_bytes != 0);
    uint32_t max_lba_entries = my_dev->capacity_bytes / my_dev->lba_size_bytes;
    // get a sequential LBA address list
    get_sequence_as_array(max_lba_entries, &seq_addresses, false);
    // get a randomized LBA address list
    get_sequence_as_array(max_lba_entries, &random_addresses, true);
    // now we start the test
    printf("device %s is opened and initialized, reported LBA size is %u and capacity %lu , max total LBA %u to_hammer %u \n",
           params.name, my_dev->lba_size_bytes, my_dev->capacity_bytes, max_lba_entries, to_hammer_lba);
    int t1 = wr_full_device_verify(my_dev, seq_addresses, max_lba_entries, 0);
    int t2 = wr_full_device_verify(my_dev, random_addresses, max_lba_entries, 0);
    int t3 = wr_full_device_verify(my_dev, random_addresses, max_lba_entries, to_hammer_lba);
    // clean up
    ret = deinit_ss_zns_device(my_dev);
    // free all
    delete[] seq_addresses;
    delete[] random_addresses;
    end = microseconds_since_epoch();
    printf("====================================================================\n");
    printf("Milestone 3 results \n");
    printf("[stosys-result] Test 1 sequential write, read, and match (full device)                : %s \n", (t1 == 0 ? " Passed" : " Failed"));
    printf("[stosys-result] Test 2 randomized write, read, and match (full device)                : %s \n", (t2 == 0 ? " Passed" : " Failed"));
    printf("[stosys-result] Test 3 randomized write, read, and match (full device, hammer %-6u)   : %s \n", to_hammer_lba, (t3 == 0 ? " Passed" : " Failed"));
    printf("====================================================================\n");
    printf("[stosys-stats] The elapsed time is %lu milliseconds \n", ((end -  start)/1000));
    printf("====================================================================\n");
    return ret;
}
}

