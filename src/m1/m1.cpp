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
#include <cerrno>

#include <libnvme.h>
#include <cstring>
#include <cassert>

#include "device.h"
#include "../common/nvmeprint.h"
#include "../common/utils.h"

extern "C" {

static int test1_lba_io_test(int zfd, uint32_t nsid, struct zone_to_test *ztest){
    struct nvme_id_ns *s_nsid = nullptr;
    int ret;
    uint64_t test_lba_address = le64_to_cpu(ztest->desc.zslba);

    ret = nvme_identify_ns(zfd, nsid, s_nsid);
    if(ret != 0){
        printf("Failed to identify the controller \n");
        return -1;
    }
    // we know the Zone SIZE and CAPACITY, see https://zonedstorage.io/introduction/zns/
    // (the difference between size and capacity)
    // Step 0: prepare the test pattern buffer
    char *w_pattern = (char *) calloc (1, ztest->lba_size_in_use);
    char *r_pattern = (char *) calloc (1, ztest->lba_size_in_use);

    assert(w_pattern != nullptr);
    assert(r_pattern != nullptr);

    write_pattern(w_pattern, ztest->lba_size_in_use);
    // Step 1: this is an empty zone because we choose to pick so, lets write the first LBA
    ret = ss_nvme_device_write(zfd, nsid, test_lba_address, 1, w_pattern, ztest->lba_size_in_use);
    if(ret != 0){
        printf("ERROR: writing failed on the zone? ret %d \n", ret);
        goto done;
    }
    printf("OK, success in writing the zone \n");
    
    // step 2: read the pattern, the same logic
    ret = ss_nvme_device_read(zfd, nsid, test_lba_address, 1, r_pattern, ztest->lba_size_in_use);
    if(ret != 0){
        printf("ERROR: reading failed on the zone? ret %d \n", ret);
        goto done;
    }
    printf("OK, success in reading the zone \n");
    printf("Matching pattern ...\n");
    match_pattern(r_pattern, ztest->lba_size_in_use);
    printf("SUCCESS: pattern matched for a simple R/W test \n");
    // starting a looping test with zone reset
    // this test
    // step 1: resets a zone
    // step 2: writes 2x LBAs
    // step 3: appends 2x LBAs
    // step 4: writes 1x LBAs
    // step 5: read all 5 and match the pattern
    do {
        // step 1: reset the whole zone
        uint64_t write_lba = le64_to_cpu(ztest->desc.zslba), zone_slba = le64_to_cpu(ztest->desc.zslba);
        uint64_t returned_slba = -1;
        ret = ss_zns_device_zone_reset(zfd, nsid, zone_slba);
        assert(ret == 0);
        printf("zone at 0x%lx is reset successfully \n", zone_slba);
        // step 2: write 2x blocks, hence 2x the buffer size
        char *w_pattern2 = (char *) calloc (2 , ztest->lba_size_in_use);
        // I am writing these patterns in two stages so that I can test them independently.
        // nothing smart here, actually more like a dumb idea. But I like dumb working code :)
        write_pattern(w_pattern2, ztest->lba_size_in_use);
        write_pattern(w_pattern2 + ztest->lba_size_in_use, ztest->lba_size_in_use);
        ret = ss_nvme_device_write(zfd, nsid, le64_to_cpu(ztest->desc.zslba), 2, w_pattern2, 2 * ztest->lba_size_in_use);
        assert(ret == 0);
        printf("zone is written 2x successfully \n");
        update_lba(write_lba, ztest->lba_size_in_use, 2);
        // step 3: append 2x LBA blocks
        ret = ss_zns_device_zone_append(zfd, nsid, zone_slba, 2, w_pattern2,
                                        2 * ztest->lba_size_in_use, &returned_slba);
        assert(ret == 0);
        printf("zone is APPENDED 2x successfully, returned pointer is at %lx (to match %lx) \n", returned_slba, write_lba);
        // match that the returned pointer - which should be the original write ptr location.
        // returned pointer is where the data is appended (not where the write pointer _is_)
	assert(returned_slba == write_lba);
        // move the returned pointer to the +2 LBAs - we can now use the returned pointer
        update_lba(returned_slba, ztest->lba_size_in_use, 2);
        // step 4: write the 5th 1x LBA using the returned LBA from the append
        ret = ss_nvme_device_write(zfd, nsid, returned_slba, 1, w_pattern, ztest->lba_size_in_use);
        assert(ret == 0);
        printf("The final write is ok too, we should be at 5x LBAs writes now \n");
        // read all 5 blocks and match their patterns
        char *r_pattern2 = (char *) calloc (5, ztest->lba_size_in_use);
        // read from the start
        ret = ss_nvme_device_read(zfd, nsid, zone_slba, 5, r_pattern2, 5 * ztest->lba_size_in_use);
        assert(ret == 0);
        printf("The final 5x read is ok, matching pattern ... \n");
        // now test them individually
        for(int i = 0 ; i < 5; i++){
            printf("\t testing the %d buffer out of 5...", i);
            match_pattern(r_pattern2 + (i * ztest->lba_size_in_use), ztest->lba_size_in_use);
            printf(" passed \n");
        }
        free(r_pattern2);
        free(w_pattern2);
    }while(false);

    done:
    free(w_pattern);
    free(r_pattern);
    printf("ZNS I/O testing finished, status %d \n", ret);
    return ret;
}

static int test2_zone0_full_io_test(int zfd, uint32_t nsid, struct zone_to_test *ztest){
    uint64_t zone_size_in_bytes = ztest->lba_size_in_use * ztest->desc.zcap;
    uint64_t zslba = le64_to_cpu(ztest->desc.zslba);
    uint64_t MDTS = get_mdts_size(zfd);
    printf("Test 3: testing the max writing capacity of the device, trying to read and write a complete zone of size %lu bytes \n",
           zone_size_in_bytes);
    uint8_t *data = (uint8_t *) calloc(1, zone_size_in_bytes);
    assert(data != nullptr);

    write_pattern((char*) data, zone_size_in_bytes);
    // now reset, and then write the full zone
    printf("\t trying to reset the zone at 0x%lx \n", zslba);
    int ret = ss_zns_device_zone_reset(zfd, nsid, zslba);
    if(ret != 0){
        printf("Error: zone rest on 0x%lx failed, ret %d \n", zslba, ret);
        goto done;
    }
    ret = ss_nvme_device_io_with_mdts(zfd, nsid, zslba, ztest->desc.zcap, data, zone_size_in_bytes,
                                      ztest->lba_size_in_use,
                                      MDTS,
                                      false);
    if(ret != 0){
        printf("Error: zone writing on 0x%lx failed, ret %d \n", zslba, ret);
        goto done;
    }
    // now read the zone
    bzero(data, zone_size_in_bytes);
    ret = ss_nvme_device_io_with_mdts(zfd, nsid, zslba, ztest->desc.zcap, data, zone_size_in_bytes,
                                      ztest->lba_size_in_use,
                                      MDTS,
                                      true);
    if(ret != 0){
        printf("Error: zone reading on 0x%lx failed, ret %d \n", zslba, ret);
        goto done;
    }
    printf("\t the whole zone reading done \n");
    match_pattern((char*) data, zone_size_in_bytes);
    printf("OK: the whole zone pattern matched \n");

    done:
    free(data);
    return ret;
}

int main() {
    int ret, num_devices, fd, t1, t2;
    uint32_t nsid;
    struct ss_nvme_ns *my_devices, *zns_device;
    struct nvme_id_ns ns{};
    struct zone_to_test ztest{};
    printf("============================================================== \n");
    printf("Welcome to M1. This is lot of ZNS/NVMe exploration \n");
    printf("============================================================== \n");
    // scan all NVMe devices in the system - just like nvme list command
    ret = count_and_show_all_nvme_devices();
    if(ret < 0){
        printf("the host device scans failed, %d \n", ret);
        return ret;
    }
    // now we are going to allocate scan the returned number of devices to identify a ZNS device
    num_devices = ret;
    printf("total number of devices in the system is %d \n", num_devices);
    if(num_devices == 0){
        printf("Error: failed to open any device, zero devices in the system? \n");
        return -ENODEV;
    }
    my_devices = (struct ss_nvme_ns *) calloc (num_devices, sizeof(*my_devices));
    if(!my_devices){
        printf("failed calloc, -ENOMEM \n");
        return -12;
    }
    ret = scan_and_identify_zns_devices(my_devices);
    if(ret < 0){
        printf("scanning of the devices failed %d\n", ret);
        return ret;
    }
    for(int i = 0; i < num_devices; i++){
        printf("namespace: %s and zns %s \n", my_devices[i].ctrl_name, (my_devices[i].supports_zns ? "YES" : "NO"));
        if(my_devices[i].supports_zns) {
            // with this we will just pick the last ZNS device to work with
            zns_device = &my_devices[i];
        }
    }
    printf("Opening the device at %s \n", zns_device->ctrl_name);
    fd = nvme_open(zns_device->ctrl_name);
    if(fd < 0){
        printf("device %s opening failed %d errno %d \n", zns_device->ctrl_name, fd, errno);
        return -fd;
    }
    printf("device %s opened successfully %d \n", zns_device->ctrl_name, fd);
    // now try to retrieve the NVMe namespace details - step 1 get the id
    ret = nvme_get_nsid(fd, &nsid);
    if(ret != 0){
        printf("ERROR: failed to retrieve the nsid %d \n", ret);
        return ret;
    }
    // with the id now we can query the identify namespace - see figure 249, section 5.15.2 in the NVMe specification
    ret = nvme_identify_ns(fd, nsid, &ns);
    if(ret){
        printf("ERROR: failed to retrieve the nsid %d \n", ret);
        return ret;
    }
    ss_nvme_show_id_ns(&ns);
    printf("number of LBA formats? %d (a zero based value) \n", ns.nlbaf);
    // extract the in-use LBA size, it could be the case that the device supports multiple LBA size
    ztest.lba_size_in_use = 1 << ns.lbaf[(ns.flbas & 0xf)].ds;
    printf("the LBA size is %lu bytes \n", ztest.lba_size_in_use);
    // this function shows the zone status and then return the first empty zone to do experiments on in ztest
    ret = show_zns_zone_status(fd, nsid, &ztest);
    if ( ret != 0) {
        printf("failed to get a workable zone, ret %d \n", ret);
        return ret;
    }
    t1 = test1_lba_io_test(fd, nsid, &ztest);
    t2 = test2_zone0_full_io_test(fd, nsid, &ztest);
    printf("====================================================================\n");
    printf("Milestone 1 results \n");
    printf("Test 1 (read, write, append, reset) : %s \n", (t1 == 0 ? " Passed" : " Failed"));
    printf("Test 2 (Large zone read, write)     : %s \n", (t2 == 0 ? " Passed" : " Failed"));
    printf("====================================================================\n");
    for(int i = 0; i < num_devices; i++) {
        free(my_devices[i].ctrl_name);
    }
    free(my_devices);
    return 0;
}
}
