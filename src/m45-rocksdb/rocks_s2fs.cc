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

#include "S2FileSystem.h"
#include "DummyFSForward.h"

#include "rocksdb/utilities/object_registry.h"
#include <iostream>

using namespace std;

namespace ROCKSDB_NAMESPACE {

    extern "C" FactoryFunc <FileSystem> stosys_s2fs_reg;

    //FIXME: should move this registration code in its own unique file
    FactoryFunc <FileSystem> stosys_s2fs_reg =
            ObjectLibrary::Default()->Register<FileSystem>(
                    "s2fs:.*://.*", [](const std::string &uri, std::unique_ptr<FileSystem> *ret_fs,
                                     std::string *errmsg) {
                        cout<<"Initialization uri is " << uri << " and errmsg: " << (*errmsg) << endl;
                        // we have two setup - one - s2fs-rocksdb which is just forwarding, then the other that we can use to debug
                        if(false){
                            S2FileSystem *z = new S2FileSystem(uri, true);
                            ret_fs->reset(z);
                        } else {
                            //DummyFSForward is forwarding implementation - I should be left in peace
                            class DummyFSForward *m = new DummyFSForward();
                            ret_fs->reset(m);
                        }
                        return ret_fs->get();
                    });
}
