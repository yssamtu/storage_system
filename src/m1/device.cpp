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
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <libnvme.h>
#include <sys/mman.h>
#include <unistd.h>
#include "device.h"
#include "../common/nvmeprint.h"

// Examples lifted from, https://github.com/linux-nvme/libnvme/blob/667334ff8c53dbbefa51948bbe2e086624bf4d0d/test/cpp.cc
int count_and_show_all_nvme_devices()
{
    nvme_host_t h;
    nvme_subsystem_t s;
    nvme_ctrl_t c;
    nvme_path_t p;
    nvme_ns_t n;
    int count = 0;
    nvme_root_t r = nvme_scan(nullptr);
    if (!r)
        return -1;
    nvme_for_each_host(r, h) {
        nvme_for_each_subsystem(h, s) {
            std::cout <<  nvme_subsystem_get_name(s)
                      << " - NQN=" << nvme_subsystem_get_nqn(s)
                      << std::endl;
            nvme_subsystem_for_each_ctrl(s, c) {
                std::cout << " `- " << nvme_ctrl_get_name(c)
                          << " " << nvme_ctrl_get_transport(c)
                          << " " << nvme_ctrl_get_address(c)
                          << " " << nvme_ctrl_get_state(c)
                          << std::endl;
                nvme_ctrl_for_each_ns(c, n) {
                    std::cout << "   `- "
                              << nvme_ns_get_name(n)
                              << "lba size:"
                              << nvme_ns_get_lba_size(n)
                              << " lba max:"
                              << nvme_ns_get_lba_count(n)
                              << std::endl;
                }
                nvme_ctrl_for_each_path(c, p) {
                    std::cout << "   `- "
                              << nvme_path_get_name(p)
                              << " "
                              << nvme_path_get_ana_state(p)
                              << std::endl;
                }
                ++count;
            }
        }
    }
    std::cout << std::endl;
    nvme_free_tree(r);
    return count;
}

extern "C" {

int scan_and_identify_zns_devices(ss_nvme_ns *list)
{
    int ns_counter = 0;
    nvme_host_t h;
    nvme_subsystem_t subsystem;
    nvme_ctrl_t controller;
    nvme_ns_t nspace;
    nvme_id_ns ns;
    nvme_root_t root = nvme_scan(nullptr /* for now the config file is NULL */);
    if (!root) {
        std::cout << "nvme_scan call failed with errno "
                  << -errno
                  << " , null pointer returned in the scan call"
                  << std::endl;
        return -1;
    }
    nvme_for_each_host(root, h) {
        nvme_for_each_subsystem(h, subsystem) {
            std::cout << "root (" << ns_counter
                      << ") |- name: " << nvme_subsystem_get_name(subsystem)
                      << " sysfs_dir "
                      << nvme_subsystem_get_sysfs_dir(subsystem)
                      << " subsysqn " << nvme_subsystem_get_nqn(subsystem)
                      << std::endl;
            nvme_subsystem_for_each_ctrl(subsystem, controller) {
                std::cout << "\t|- controller : name "
                          << nvme_ctrl_get_name(controller)
                          << " (more to follow)" << std::endl;
                nvme_ctrl_for_each_ns(controller, nspace) {
                    std::cout << "\t\t|- namespace : name "
                              << nvme_ns_get_name(nspace)
                              << " and command set identifier (csi) is "
                              << nvme_ns_get_csi(nspace)
                              << " (= 0 NVMe, 2 = ZNS), more to follow)"
                              << std::endl;
                    list[ns_counter].ctrl_name = strdup(nvme_ns_get_name(nspace));
                    if (nvme_ns_get_csi(nspace) == NVME_CSI_ZNS)
                        list[ns_counter].supports_zns = true;
                    else
                        list[ns_counter].supports_zns = false;
                    // for convenience
                    nvme_get_nsid(nvme_ns_get_fd(nspace),
                                  &list[ns_counter].nsid);
                    int ret = nvme_ns_identify(nspace, &ns);
                    if (ret) {
                        std::cout << "ERROR : failed to identify the namespace with "
                                  << ret << " and errno " << errno << std::endl;
                        return ret;
                    }
                    ++ns_counter;
                }
            }
        }
    }
    nvme_free_tree(root);
    return 0;
}

int show_zns_zone_status(const int &fd, const unsigned &nsid, zone_to_test &ztest)
{
    // ZNS specific data structures as specified in the TP 4053
    // standard NVMe structures
    nvme_id_ns s_nsid;
    // lets first get the NVMe ns identify structure (again),
    // we need some information from it to complement the
    // information present in the ZNS ns identify structure
    int ret = nvme_identify_ns(fd, nsid, &s_nsid);
    if (ret) {
        std::cerr << "failed to identify NVMe namespace, ret "
                  << ret << std::endl;
        return ret;
    }
    // see figure 8, section 3.1.1 in the ZNS specification
    nvme_zns_id_ns s_zns_nsid;
    ret = nvme_zns_identify_ns(fd, nsid, &s_zns_nsid);
    if (ret) {
        std::cerr << "failed to identify ZNS namespace, ret "
                  << ret << std::endl;
        return -ret;
    }
    ss_nvme_show_zns_id_ns(&s_zns_nsid, &s_nsid);
    // 3.1.2, figure 10 in the ZNS specification
    nvme_zns_id_ctrl s_zns_ctrlid;
    ret = nvme_zns_identify_ctrl(fd, &s_zns_ctrlid);
    if (ret) {
        std::cerr << "failed to identify ZNS controller, ret "
                  << ret << std::endl;
        return ret;
    }
    ss_nvme_show_zns_id_ctrl(&s_zns_ctrlid);
    // now we send the management related commands - see section 4.3 and 4.4 in TP 4053
    // we are now trying to retrieve the number of zones with other information present in the zone report
    // the following function takes arguments that are required to filled the command structure as shown
    // in the figures 33-36
    //   * SLBA goes into CDW 10 and 11, as shown in Figure 34
    //   * zras is Zone Receive Action Specific Features, see figure 36 for details
    //   * NVME_ZNS_ZRA_REPORT_ZONES and NVME_ZNS_ZRAS_REPORT_ALL are shown in Figure 36 CDW 13

    // Pay attention what is being passed in the zns_report pointer and size, I am passing a structure
    // _WITHOUT_ its entries[] field initialized because we do not know how many zones does this namespace
    // hence we first get the number of zones, and then try again to get the full report
    nvme_zone_report zns_report;
    ret = nvme_zns_mgmt_recv(fd, nsid, 0ULL, NVME_ZNS_ZRA_REPORT_ZONES,
                             NVME_ZNS_ZRAS_REPORT_ALL, false,
                             sizeof(zns_report), &zns_report);
    if (ret) {
        std::cerr <<  "failed to report zones, ret " << ret << std::endl;
        return ret;
    }
    // see figures 37-38-39 in section 4.4.1
    uint64_t num_zones = le64_to_cpu(zns_report.nr_zones);
    printf("nr_zones:%" PRIu64"\n", num_zones);
    // lets get more information about the zones - the total metadata size would be
    // see the figure 37 in the ZNS description
    // so we allocated an structure with a flat memory and point the zone_reports to it
    // An alternate strategy would have been just allocate a 4kB page and get some numbers of zone reports whatever can
    // fit in that in a loop.
    uint64_t total_size = sizeof(zns_report) +
                          num_zones * sizeof(nvme_zns_desc);
    std::unique_ptr<char []> zone_reports(new char[total_size]());
    ret = nvme_zns_mgmt_recv(fd, nsid, 0ULL, NVME_ZNS_ZRA_REPORT_ZONES,
                             NVME_ZNS_ZRAS_REPORT_ALL, true,
                             total_size, zone_reports.get());
    if (ret) {
        std::cerr <<  "failed to report zones, ret " << ret << std::endl;
        return ret;
    }
    nvme_zns_desc *desc = ((nvme_zone_report *)zone_reports.get())->entries;
    num_zones = le64_to_cpu(((nvme_zone_report *)zone_reports.get())->nr_zones);
    // otherwise we got all our reports, check again
    std::cout << "With the reports we have num_zones " << num_zones
              << " (for which data transfer happened)" << std::endl;
    nvme_zns_desc *_ztest = nullptr;
    for (uint64_t i = 0; i < num_zones; ++i) {
        // see figure 39 for description of these fields
        std::cout << "\t SLBA: 0x%-8" << le64_to_cpu(desc->zslba)
                  << " WP: 0x%-8" << le64_to_cpu(desc->wp)
                  << " Cap: 0x%-8" << le64_to_cpu(desc->zcap)
                  << " State: " << std::setw(12) << std::setfill(' ')
                  << ss_zone_state_to_string(desc->zs >> 4)
                  << " Type: " << std::setw(14) << std::setfill(' ')
                  << ss_zone_type_to_string(desc->zt)
                  << " Attrs: 0x" << desc->za << std::endl;
        // pick the first zone which is empty to do I/O experiments
        if (!_ztest && desc->zs >> 4 == NVME_ZNS_ZS_EMPTY)
            _ztest = desc;
        ++desc;
    }
    // if could be the case we did not find any empty zone
    if (_ztest) {
        ret = 0;
        memcpy(&ztest.desc, _ztest, sizeof(*_ztest));
    } else {
        std::cout << "Error: I could not find a free empty zone to test, \
perhaps reset the zones with: sudo nvme zns reset-zone -a /dev/nvme0n1"
                  << std::endl;
        ret = -ENOENT;
    }
    // now we copy and return the zone values to do experiment on
    return ret;
}

int ss_nvme_device_io_with_mdts(const int &fd, const unsigned &nsid,
                                unsigned long long slba,
                                void *buffer, unsigned buf_size,
                                const uint32_t &lba_size,
                                const uint32_t &mdts_size, const bool &read)
{
    //FIXME:
    while (buf_size) {
        unsigned size = buf_size < mdts_size ? buf_size : mdts_size;
        unsigned short no_blocks = size / lba_size;
        if (read)
            ss_nvme_device_read(fd, nsid, slba, no_blocks, buffer, size);
        else
            ss_nvme_device_write(fd, nsid, slba, no_blocks, buffer, size);
        if (errno)
            return errno;
        slba += no_blocks;
        buffer = (char *)buffer + size;
        buf_size -= size;
    }
    return errno;
}

int ss_nvme_device_read(const int &fd, const unsigned &nsid,
                        const unsigned long long &slba,
                        const unsigned short &numbers,
                        void *buffer, const unsigned &buf_size)
{
    //FIXME:
    nvme_read(fd, nsid, slba, numbers - 1, 0U, 0U, 0U, 0U, 0U,
              buf_size, buffer, 0U, nullptr);
    ss_nvme_show_status(errno);
    return errno;
}

int ss_nvme_device_write(const int &fd, const unsigned &nsid,
                         const unsigned long long &slba,
                         const unsigned short &numbers,
                         void *buffer, const unsigned &buf_size)
{
    //FIXME:
    nvme_write(fd, nsid, slba, numbers - 1, 0U, 0U, 0U, 0U, 0U, 0U,
               buf_size, buffer, 0U, nullptr);
    ss_nvme_show_status(errno);
    return errno;
}

int ss_zns_device_zone_reset(const int &fd, const unsigned &nsid,
                             const unsigned long long &slba)
{
    //FIXME:
    nvme_zns_mgmt_send(fd, nsid, slba, true, NVME_ZNS_ZSA_RESET, 0U, nullptr);
    ss_nvme_show_status(errno);
    return errno;
}

// this does not take slba because it will return that
int ss_zns_device_zone_append(const int &fd, const unsigned &nsid,
                              const unsigned long long &zslba,
                              const unsigned short &numbers,
                              void *buffer, const unsigned &buf_size,
                              unsigned long long *written_slba)
{
    //FIXME:
    nvme_zns_append(fd, nsid, zslba, numbers - 1, 0U, 0U, 0U, 0U,
                    buf_size, buffer, 0U, nullptr, written_slba);
    ss_nvme_show_status(errno);
    return errno;
}

void update_lba(unsigned long long &write_lba, const int &count)
{
    //assert(false);
    write_lba += count;
}

// see 5.15.2.2 Identify Controller data structure (CNS 01h)
uint32_t get_mdts_size(const int &fd)
{
    //FIXME:
    nvme_id_ctrl ctrl;
    //Identify MDTS
    nvme_identify_ctrl(fd, &ctrl);
    //Identify MPSMIN
    void *regs = mmap(nullptr, getpagesize(), PROT_READ, MAP_SHARED,
                               fd, 0L);
    uint32_t mpsmin = NVME_CAP_MPSMIN(nvme_mmio_read64(regs)); 
    munmap(regs, getpagesize());
    uint32_t size = pow(2.0, mpsmin) * pow(2.0, ctrl.mdts);
    return size;
}

}
