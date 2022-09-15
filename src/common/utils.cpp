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

#include <cstdint>
#include <cstdio>
#include "utils.h"
#include <cassert>
#include <unistd.h>
#include <ios>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <chrono>

extern "C" {

void write_pattern_with_start(char *data, uint64_t len, uint64_t s){
    // 33 - 126 printable chars, 93
    for (uint64_t i = s, j = 0; i < len; j++, i++) {
        data[j] = ((char) 33 + (i % 93));
    }
}

void match_pattern_with_start(char *data, uint64_t len, uint64_t s){
    // 33 - 126 printable chars, 93
    for (uint64_t i = s, j = 0; i < len; i++, j++) {
        assert (data[j] == ((char) (33 + (i % 93))));
    }
}

void write_pattern(char *data, uint64_t len){
    write_pattern_with_start(data, len, 0);
}

void print_pattern(const char *data, uint64_t len, bool in_hex) {
    printf(" --- print_pattern --- \n");
    const char *fmt = in_hex ? " 0x%x " : " %c ";
    for (uint64_t i = 0; i < len; i++) {
        printf(fmt, data[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    printf("-----------------------\n");
}

void match_pattern(char *data, uint64_t len){
    match_pattern_with_start(data, len, 0);
}

}

uint64_t microseconds_since_epoch() {
    // https://stackoverflow.com/questions/16177295/get-time-since-epoch-in-milliseconds-preferably-using-c11-chrono
    return
            std::chrono::duration_cast<std::chrono::microseconds>
                    (std::chrono::system_clock::now().time_since_epoch()).count();
}

static void process_mem_usage_stat(double& vm_usage, double& resident_set)
{
    using std::ios_base;
    using std::ifstream;
    using std::string;
    vm_usage     = 0.0;
    resident_set = 0.0;
    ifstream stat_stream("/proc/self/stat",ios_base::in);
    string pid, comm, state, ppid, pgrp, session, tty_nr;
    string tpgid, flags, minflt, cminflt, majflt, cmajflt;
    string utime, stime, cutime, cstime, priority, nice;
    string O, itrealvalue, starttime;
    unsigned long vsize;
    long rss;

    stat_stream >> pid >> comm >> state >> ppid >> pgrp >> session >> tty_nr
                >> tpgid >> flags >> minflt >> cminflt >> majflt >> cmajflt
                >> utime >> stime >> cutime >> cstime >> priority >> nice
                >> O >> itrealvalue >> starttime >> vsize >> rss; // don't care about the rest

    stat_stream.close();

    long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
    vm_usage     = vsize / 1024.0;
    resident_set = rss * page_size_kb;
}

static std::string process_mem_usage_status()
{
    using std::ios_base;
    using std::ifstream;
    using std::string;
    // we need to get the 17th line
    int count = 17;
    ifstream stat_stream("/proc/self/status", ios_base::in);
    for( std::string line; getline( stat_stream, line ); )
    {
        //std::cout<<line<<std::endl;
        count--;
        if(count == 0){
            stat_stream.close();
            return line;
        }
    }
    stat_stream.close();
    return "N/A";
}

std::string get_vm_stats(){
    double vm, rss;
    process_mem_usage_stat(vm, rss);
    std::string peakvm = process_mem_usage_status();
    std::ostringstream ss;
    ss << "VM: " << vm << "; RSS: " << rss << "; peakVM: " << peakvm << std::endl;
    return ss.str();
}
