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
#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
#include <libnvme.h>
#include "device.h"
#include "../common/nvmeprint.h"
#include "../common/utils.h"

extern "C" {

static int test1_lba_io_test(const int &zfd, const unsigned &nsid,
                             const zone_to_test &ztest)
{
    nvme_id_ns *s_nsid = nullptr;
    uint64_t test_lba_address = le64_to_cpu(ztest.desc.zslba);
    int ret = nvme_identify_ns(zfd, nsid, s_nsid);
    if (ret) {
        std::cout << "Failed to identify the controller" << std::endl;
        return -1;
    }
    // we know the Zone SIZE and CAPACITY,
    // see https://zonedstorage.io/introduction/zns/
    // (the difference between size and capacity)
    // Step 0: prepare the test pattern buffer
    std::unique_ptr<char []> w_pattern(new char[ztest.lba_size_in_use]());
    std::unique_ptr<char []> r_pattern(new char[ztest.lba_size_in_use]());
    assert(w_pattern);
    assert(r_pattern);
    write_pattern(w_pattern.get(), ztest.lba_size_in_use);
    // Step 1: this is an empty zone because we choose to pick so,
    // lets write the first LBA
    ret = ss_nvme_device_write(zfd, nsid, test_lba_address, 1U,
                               w_pattern.get(), ztest.lba_size_in_use);
    if (ret) {
        std::cout << "ERROR: writing failed on the zone? ret "
                  << ret << std::endl;
        goto done;
    }
    std::cout << "OK, success in writing the zone" << std::endl;
    
    // step 2: read the pattern, the same logic
    ret = ss_nvme_device_read(zfd, nsid, test_lba_address, 1U,
                              r_pattern.get(), ztest.lba_size_in_use);
    if (ret) {
        std::cout << "ERROR: reading failed on the zone? ret "
                  << ret << std::endl;
        goto done;
    }
    std::cout << "OK, success in reading the zone" << std::endl;
    std::cout << "Matching pattern ..." << std::endl;
    match_pattern(r_pattern.get(), ztest.lba_size_in_use);
    std::cout << "SUCCESS: pattern matched for a simple R/W test" << std::endl;
    // starting a looping test with zone reset
    // this test
    // step 1: resets a zone
    // step 2: writes 2x LBAs
    // step 3: appends 2x LBAs
    // step 4: writes 1x LBAs
    // step 5: read all 5 and match the pattern
    do {
        // step 1: reset the whole zone
        unsigned long long write_lba = le64_to_cpu(ztest.desc.zslba);
        unsigned long long zone_slba = le64_to_cpu(ztest.desc.zslba);
        unsigned long long returned_slba = -1;
        ret = ss_zns_device_zone_reset(zfd, nsid, zone_slba);
        assert(!ret);
        std::cout << "zone at 0x" << std::hex << zone_slba << std::dec
                  << " is reset successfully" << std::endl;
        // step 2: write 2x blocks, hence 2x the buffer size
        std::unique_ptr<char []> w_pattern2(new char[2UL *
                                                     ztest.lba_size_in_use]());
        // I am writing these patterns in two stages
        // so that I can test them independently.
        // nothing smart here, actually more like a dumb idea.
        // But I like dumb working code :)
        write_pattern(w_pattern2.get(), ztest.lba_size_in_use);
        write_pattern(w_pattern2.get() + ztest.lba_size_in_use,
                      ztest.lba_size_in_use);
        ret = ss_nvme_device_write(zfd, nsid, le64_to_cpu(ztest.desc.zslba),
                                   2U, w_pattern2.get(),
                                   2U * ztest.lba_size_in_use);
        assert(!ret);
        std::cout << "zone is written 2x successfully" << std::endl;
        update_lba(write_lba, 2);
        // step 3: append 2x LBA blocks
        ret = ss_zns_device_zone_append(zfd, nsid, zone_slba, 2U,
                                        w_pattern2.get(),
                                        2U * ztest.lba_size_in_use,
                                        &returned_slba);
        assert(!ret);
        std::cout << "zone is APPENDED 2x successfully, returned pointer is at "
                  << std::hex << returned_slba << std::dec << " (to match "
                  << std::hex << write_lba << std::dec << ")" << std::endl;
        // match that the returned pointer -
        // which should be the original write ptr location.
        // returned pointer is where the data is appended
        // (not where the write pointer _is_)
	    assert(returned_slba == write_lba);
        // move the returned pointer to the +2 LBAs -
        // we can now use the returned pointer
        update_lba(returned_slba, 2);
        // step 4: write the 5th 1x LBA using the returned LBA from the append
        ret = ss_nvme_device_write(zfd, nsid, returned_slba, 1U,
                                   w_pattern.get(), ztest.lba_size_in_use);
        assert(!ret);
        std::cout << "The final write is ok too, we should be at 5x LBAs \
writes now" << std::endl;
        // read all 5 blocks and match their patterns
        std::unique_ptr<char []> r_pattern2(new char[5UL *
                                                     ztest.lba_size_in_use]());
        // read from the start
        ret = ss_nvme_device_read(zfd, nsid, zone_slba, 5U, r_pattern2.get(),
                                  5U * ztest.lba_size_in_use);
        assert(!ret);
        std::cout << "The final 5x read is ok, matching pattern ..."
                  << std::endl;
        // now test them individually
        for (int i = 0 ; i < 5; ++i) {
            std::cout << "\t testing the " << i << " buffer out of 5...";
            match_pattern(r_pattern2.get() + i * ztest.lba_size_in_use,
                          ztest.lba_size_in_use);
            std::cout << " passed" << std::endl;
        }
    } while(0);

    done:
    std::cout << "ZNS I/O testing finished, status " << ret << std::endl;
    return ret;
}

static int test2_zone0_full_io_test(const int &zfd, const unsigned &nsid,
                                    const zone_to_test &ztest)
{
    uint64_t zone_size_in_bytes = ztest.lba_size_in_use * ztest.desc.zcap;
    unsigned long long zslba = le64_to_cpu(ztest.desc.zslba);
    uint32_t MDTS = get_mdts_size(zfd);
    std::cout << "Test 3: testing the max writing capacity of the device, \
trying to read and write a complete zone of size "
              << zone_size_in_bytes << " bytes" << std::endl;
    std::unique_ptr<char []> data(new char[zone_size_in_bytes]());
    assert(data);
    write_pattern(data.get(), zone_size_in_bytes);
    // now reset, and then write the full zone
    std::cout << "\t trying to reset the zone at 0x"
              << std::hex << zslba << std::dec << std::endl;
    int ret = ss_zns_device_zone_reset(zfd, nsid, zslba);
    if (ret) {
        std::cout << "Error: zone rest on 0x"
                  << std::hex << zslba << std::dec
                  << " failed, ret " << ret << std::endl;
        goto done;
    }
    ret = ss_nvme_device_io_with_mdts(zfd, nsid, zslba, data.get(),
                                      zone_size_in_bytes, ztest.lba_size_in_use,
                                      MDTS, false);
    if (ret) {
        std::cout << "Error: zone writing on 0x"
                  << std::hex << zslba << std::dec
                  << " failed, ret " << ret << std::endl;
        goto done;
    }
    // now read the zone
    bzero(data.get(), zone_size_in_bytes);
    ret = ss_nvme_device_io_with_mdts(zfd, nsid, zslba, data.get(),
                                      zone_size_in_bytes, ztest.lba_size_in_use,
                                      MDTS, true);
    if (ret) {
        std::cout << "Error: zone reading on 0x"
                  << std::hex << zslba << std::dec
                  << " failed, ret " << ret << std::endl;
        goto done;
    }
    std::cout << "\t the whole zone reading done" << std::endl;
    match_pattern(data.get(), zone_size_in_bytes);
    std::cout << "OK: the whole zone pattern matched" << std::endl;
    done:
    return ret;
}

int main()
{
    std::cout << "=============================================================\
=" << std::endl;
    std::cout << "Welcome to M1. This is lot of ZNS/NVMe exploration"
              << std::endl;
    std::cout << "=============================================================\
=" << std::endl;
    // scan all NVMe devices in the system - just like nvme list command
    int ret = count_and_show_all_nvme_devices();
    if (ret < 0) {
        std::cout << "the host device scans failed, " << ret << std::endl;
        return ret;
    }
    // now we are going to allocate scan the returned number of devices
    // to identify a ZNS device
    int num_devices = ret;
    std::cout << "total number of devices in the system is "
              << num_devices << std::endl;
    if (!num_devices) {
        std::cout << "Error: failed to open any device, zero devices in the \
system?" << std::endl;
        return -ENODEV;
    }
    std::unique_ptr<ss_nvme_ns[]> my_devices(new ss_nvme_ns[num_devices]());
    ret = scan_and_identify_zns_devices(my_devices.get());
    if (ret < 0) {
        std::cout << "scanning of the devices failed" << std::endl;
        return ret;
    }
    ss_nvme_ns *zns_device = nullptr;
    for (int i = 0; i < num_devices; ++i) {
        std::cout << "namespace: " << my_devices[i].ctrl_name
                  << " and zns " << (my_devices[i].supports_zns ? "YES" : "NO")
                  << std::endl;
        // with this we will just pick the last ZNS device to work with
        if (my_devices[i].supports_zns)
            zns_device = &my_devices[i];
    }
    std::cout << "Opening the device at " << zns_device->ctrl_name << std::endl;
    int fd = nvme_open(zns_device->ctrl_name);
    if (fd < 0) {
        std::cout << "device " << zns_device->ctrl_name
                  << " opening failed " << fd
                  << " errno " << errno << std::endl;
        return -fd;
    }
    std::cout << "device " << zns_device->ctrl_name
              << " opened successfully " << fd << std::endl;
    // now try to retrieve the NVMe namespace details - step 1 get the id
    unsigned nsid = 0U;
    ret = nvme_get_nsid(fd, &nsid);
    if (ret) {
        std::cout << "ERROR: failed to retrieve the nsid " << ret << std::endl;
        return ret;
    }
    // with the id now we can query the identify namespace -
    // see figure 249, section 5.15.2 in the NVMe specification
    nvme_id_ns ns;
    ret = nvme_identify_ns(fd, nsid, &ns);
    if (ret) {
        std::cout << "ERROR: failed to retrieve the nsid " << ret << std::endl;
        return ret;
    }
    ss_nvme_show_id_ns(&ns);
    std::cout << "number of LBA formats? " << ns.nlbaf
              << " (a zero based value)" << std::endl;
    // extract the in-use LBA size,
    // it could be the case that the device supports multiple LBA size
    zone_to_test ztest;
    ztest.lba_size_in_use = 1U << ns.lbaf[(ns.flbas & 0xf)].ds;
    std::cout << "the LBA size is " << ztest.lba_size_in_use
              << " bytes" << std::endl;
    // this function shows the zone status
    // and then return the first empty zone to do experiments on in ztest
    ret = show_zns_zone_status(fd, nsid, ztest);
    if (ret) {
        std::cout << "failed to get a workable zone, ret " << ret << std::endl;
        return ret;
    }
    int t1 = test1_lba_io_test(fd, nsid, ztest);
    int t2 = test2_zone0_full_io_test(fd, nsid, ztest);
    std::cout << "=============================================================\
=======" << std::endl;
    std::cout << "Milestone 1 results" << std::endl;
    std::cout << "Test 1 (read, write, append, reset) : "
              << (t1 == 0 ? " Passed" : " Failed") << std::endl;
    std::cout << "Test 2 (Large zone read, write)     : "
              << (t2 == 0 ? " Passed" : " Failed") << std::endl;
    std::cout << "=============================================================\
=======" << std::endl;
    for(int i = 0; i < num_devices; ++i)
        free(my_devices[i].ctrl_name);
    return 0;
}

}
