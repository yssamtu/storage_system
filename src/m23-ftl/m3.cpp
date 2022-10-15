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

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include "zns_device.h"
#include "../common/utils.h"

static int get_sequence_as_array(const uint64_t &capacity, uint64_t *&arr,
                                 const bool &shuffle)
{
    std::vector<uint64_t> myvector;
    // set some values:
    for (uint64_t i = 0; i < capacity; ++i)
        myvector.emplace_back(i);
    std::random_device rd;
    std::mt19937 g(rd());
    if(shuffle)
        std::shuffle(myvector.begin(), myvector.end(), g);
    arr = new uint64_t[capacity];
    for (uint64_t i = 0; i < capacity; ++i)
        arr[i] = myvector[i];
    return 0;
}

extern "C" {

static int _complete_file_io(const int &fd, const uint64_t &offset,
                             void *buf, const uint32_t &sz, const bool &is_read)
{
    uint32_t written_so_far = 0;
    uintptr_t ptr = reinterpret_cast<uintptr_t>(buf);
    while (written_so_far < sz) {
        int ret = 0;
        if(is_read)
            ret = pread(fd, reinterpret_cast<void *>(ptr + written_so_far),
                        sz - written_so_far, offset + written_so_far);
        else
            ret = pwrite(fd, reinterpret_cast<const void *>
                             (ptr + written_so_far),
                         sz - written_so_far, offset + written_so_far);
        if (ret < 0) {
            std::cout << "file writing failed " << ret << std::endl;
            return ret;
        }
        //other add and move along
        written_so_far += ret;
    }
    return 0;
}

static int write_complete_file(const int &fd, const uint64_t &offset,
                               void *buf, const uint32_t &sz)
{
    return _complete_file_io(fd, offset, buf, sz, false);
}

static int read_complete_file(const int &fd, const uint64_t &offset,
                              void *buf, const uint32_t &sz)
{
    return _complete_file_io(fd, offset, buf, sz, true);
}

/*
 * Based on if the addr_list was in sequence or randomized -
 * we will do sequential or random I/O
 * --
 * So the idea of this test is to write a parallel file on the side
 * which has the same content, and the
 * ZNS device content should match with this file.
 *
 * addr_list = list of LBAs how they should be accessed
 * list_size = size of the address list
 * max_hammer_io = a random number,
 * for how many times I should randomly do a write on a random LBA
 */
static int wr_full_device_verify(const user_zns_device &dev,
                                 const uint64_t *addr_list,
                                 const uint32_t &list_size,
                                 const uint32_t &max_hammer_io)
{
    std::unique_ptr<char []> b1(new char[dev.lba_size_bytes]());
    std::unique_ptr<char []> b2(new char[dev.lba_size_bytes]());
    assert(b1);
    assert(b2);
    write_pattern(b1.get(), dev.lba_size_bytes);
    const char *tmp_file = "./tmp-output-fulld";
    int fd = open(tmp_file, O_RDWR|O_CREAT, 0666);
    if (fd < 0) {
        std::cout << "Error: opening of the temp file failed, ret " << fd;
        return -1;
    }
    // allocate this side file to the full capacity
    int ret = posix_fallocate(fd, 0, dev.capacity_bytes);
    if (ret) {
        std::cout << "Error: fallocate failed, ret " << ret;
        return -1;
    }
    std::cout << "fallocate OK with " << tmp_file << "s and size 0x"
              << std::hex << dev.capacity_bytes << std::dec << std::endl;
    // https://stackoverflow.com/questions/29381843/generate-random-number-in-range-min-max
    const int min = 0;
    const int max = dev.lba_size_bytes;
    //initialize the device, otherwise we may have indexes
    // where there is random garbage in both cases
    for (uint32_t i = 0; i < list_size; ++i) {
        uint64_t woffset = addr_list[i] * dev.lba_size_bytes;
        //random offset within the page and just write some random stuff =
        // this is to make a unique I/O pattern
        b1[(min + rand() % (max - min))] = (char) rand();
        // now we need to write the buffer in parallel to the zns device
        // and the file
        ret = zns_udevice_write(const_cast<user_zns_device *>(&dev), woffset,
                                b1.get(), dev.lba_size_bytes);
        if (ret) {
            std::cout << "Error: ZNS device writing failed at offset 0x"
                      << std::hex << woffset << std::dec << std::endl;
            goto done;
        }
        ret = write_complete_file(fd, woffset, b1.get(), dev.lba_size_bytes);
        if (ret) {
            std::cout << "Error: file writing failed at offset 0x"
                      << std::hex << woffset << std::dec << std::endl;
            goto done;
        }
    }
    std::cout << "the ZNS user device has been written (ONCE) completely OK"
              << std::endl;
    if (max_hammer_io > 0) {
        std::cout << "Hammering some random LBAs " << max_hammer_io << " times"
                  << std::endl;
        for (uint32_t i = 0; i < max_hammer_io; ++i) {
            // we should not generate offset which is within the list_size
            uint64_t woffset = addr_list[0 + rand() % (list_size - 0)] *
                               dev.lba_size_bytes;
            //random offset within the page and just write some random stuff,
            // like i
            b1[(min + rand() % (max - min))] = static_cast<char>(rand());
            // now we need to write the buffer in parallel to the zns device,
            // and the file
            ret = zns_udevice_write(const_cast<user_zns_device *>(&dev),
                                    woffset, b1.get(), dev.lba_size_bytes);
            if (ret) {
                std::cout << "Error: ZNS device writing failed at offset 0x"
                          << std::hex << woffset << std::dec << std::endl;
                goto done;
            }
            ret = write_complete_file(fd, woffset,
                                      b1.get(), dev.lba_size_bytes);
            if (ret) {
                std::cout << "Error: file writing failed at offset 0x"
                          << std::hex << woffset << std::dec << std::endl;
                goto done;
            }
        }
        std::cout << "Hammering done, OK for " << max_hammer_io << " times"
                  << std::endl;
    }
    std::cout << "verifying the content of the ZNS device ...." << std::endl;
    // reset the buffers
    write_pattern(b1.get(), dev.lba_size_bytes);
    write_pattern(b2.get(), dev.lba_size_bytes);
    // and now read the whole device and compare the content with the file
    for (uint32_t i = 0; i < list_size; ++i) {
        uint64_t roffset = addr_list[i] * dev.lba_size_bytes;
        // now we need to write the buffer in parallel to the zns device,
        // and the file
        ret = zns_udevice_read(const_cast<user_zns_device *>(&dev), roffset,
                               b1.get(), dev.lba_size_bytes);
        assert(!ret);
        ret = read_complete_file(fd, roffset, b2.get(), dev.lba_size_bytes);
        assert(!ret);
        //now both of these should match
        for(uint32_t j = 0; j < dev.lba_size_bytes; ++j)
            if (b1[j] != b2[j]) {
                std::cout << "ERROR: buffer mismatch at i " << i
                          << " and j " << j << " , address is 0"
                          << std::hex << roffset << " expecting " << b2[j]
                          << " found " << b1[j] << std::dec << std::endl;
                ret = -EINVAL;
                goto done;
            }
    }
    std::cout << "Verification passed on the while device" << std::endl;
    done:
    close(fd);
    ret = remove(tmp_file);
    if (ret) {
        std::cout << "Error: file deleting failed with ret " << ret
                  << std::endl;
    }
    return ret;
}

static int show_help()
{
    std::cout << "Usage: m2 -d device_name -h -r" << std::endl;
    std::cout << "-d : /dev/nvmeXpY - in this format with the full path"
              << std::endl;
    std::cout << "-r : resume if the FTL can." << std::endl;
    std::cout << "-l : the number of zones to use for log/metadata (default, \
minimum = 3)." << std::endl;
    std::cout << "-w : watermark threshold, the number of free zones when to \
trigger the gc (default, minimum = 1)." << std::endl;
    std::cout << "-o : overwrite so [int] times  (default, 10,000)."
              << std::endl;
    std::cout << "-h : shows help, and exits with success. No argument needed"
              << std::endl;
    return 0;
}

int main(int argc, char *argv[])
{
    uint64_t start = microseconds_since_epoch();
    srand(static_cast<unsigned>(time(NULL)) * getpid());
    std::cout << "=============================================================\
========================" << std::endl;
    std::cout << "This is M3. The goal of this milestone is to implement a \
hybrid log-structure ZTL (Zone Translation Layer) on top of the ZNS WITH a GC"
              << std::endl;
    std::cout << "                                                             \
                                                                ^^^^^^^^^"
              << std::endl;
    std::cout << "=============================================================\
========================" << std::endl;
    int c = 0;
    char *zns_device_name = const_cast<char *>("nvme0n1");
    char *str1 = nullptr;
    uint32_t to_hammer_lba = 10000U;
    zdev_init_params params = {
        .name = nullptr,
        .log_zones = 3,
        .gc_wmark = 1,
        .force_reset = true
    };
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
                    std::cout << "Could not parse the arguments for the device "
                              << optarg << std::endl;
                    exit(EXIT_FAILURE);
                }
                for (int j = 1; ; j++) {
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
(metadata (think: milestone 5) + log). You passed " << params.log_zones
                              << std::endl;
                    exit(-1);
                }
                break;
            case 'w':
                params.gc_wmark = atoi(optarg);
                if (params.gc_wmark < 1) {
                    std::cout << "you need 1 or more free zones for continuous \
working of the FTL. You passed " << params.gc_wmark << std::endl;
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
              << " hammer-time " << to_hammer_lba << std::endl;
    user_zns_device *my_dev = nullptr;
    int ret = init_ss_zns_device(&params, &my_dev);
    assert (!ret);
    assert(my_dev->lba_size_bytes);
    assert(my_dev->capacity_bytes);
    uint32_t max_lba_entries = my_dev->capacity_bytes / my_dev->lba_size_bytes;
    // get a sequential LBA address list
    uint64_t *seq_addresses = nullptr;
    get_sequence_as_array(max_lba_entries, seq_addresses, false);
    // get a randomized LBA address list
    uint64_t *random_addresses = nullptr;
    get_sequence_as_array(max_lba_entries, random_addresses, true);
    // now we start the test
    std::cout << "device " << params.name
              << " is opened and initialized, reported LBA size is "
              << my_dev->lba_size_bytes
              << " and capacity " << my_dev->capacity_bytes
              << " , max total LBA " << max_lba_entries
              << " to_hammer " << to_hammer_lba << std::endl;
    int t1 = wr_full_device_verify(*my_dev, seq_addresses, max_lba_entries, 0U);
    int t2 = wr_full_device_verify(*my_dev, random_addresses, max_lba_entries,
                                   0U);
    int t3 = wr_full_device_verify(*my_dev, random_addresses, max_lba_entries,
                                   to_hammer_lba);
    // clean up
    ret = deinit_ss_zns_device(my_dev);
    // free all
    delete[] seq_addresses;
    delete[] random_addresses;
    uint64_t end = microseconds_since_epoch();
    std::cout << "=============================================================\
=======" << std::endl;
    std::cout << "Milestone 3 results" << std::endl;
    std::cout << "[stosys-result] Test 1 sequential write, read, and match \
(full device)                : " <<  (!t1 ? " Passed" : " Failed") << std::endl;
    std::cout << "[stosys-result] Test 2 randomized write, read, and match \
(full device)                : " << (!t2 ? " Passed" : " Failed") << std::endl;
    printf("[stosys-result] Test 3 randomized write, read, and match (full \
device, hammer %-6u)   : %s \n", to_hammer_lba,
           (!t3 ? " Passed" : " Failed"));
    std::cout << "=============================================================\
=======" << std::endl;
    std::cout << "[stosys-stats] The elapsed time is "
              << (end -  start) / 1000UL << " milliseconds" << std::endl;
    std::cout << "=============================================================\
=======" << std::endl;
    return ret;
}

}
