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

#ifndef STOSYS_PROJECT_STOSYS_DEBUG_H
#define STOSYS_PROJECT_STOSYS_DEBUG_H

#define DBG_ERR              0x00000001
#define DBG_FTL             0x00000002
#define DBG_FTL_LOG         0x00000004
#define DBG_FTL_DATA        0x00000008
#define DBG_XXX             0x00000010
#define DBG_FTL_L3          0x00000020
#define DBG_FTL_GC          0x00000040
#define DBG_FS_1            0x00000080
#define DBG_UZDEV_IO        0x00000100
#define DBG_FS_INODE_1      0x00000200
#define DBG_FS_ALLOCATOR    0x00000400
#define DBG_FS_FIO          0x00000800
#define DBG_WARN            0x00001000
#define DBG_FTL_PERSIST     0x00002000

#define DBG_ALL_XXX      (DBG_ERR|DBG_FTL|DBG_FTL_LOG|DBG_FTL_DATA|DBG_XXX)
//old one which no one use using
//#define DBG_ALL         (DBG_ON|DBG_FTL|DBG_FTL_LOG|DBG_FTL_DATA)
#define DBG_ALL         (DBG_ERR|DBG_FTL|DBG_FTL_LOG|DBG_FTL_DATA|DBG_FS_1|DBG_FS_INODE_1|DBG_FS_ALLOCATOR|DBG_FS_FIO)

#define DPRINT_MASK     (DBG_ERR)

#ifdef NODEBUG
#define ss_dprintf(dbgcat, fmt, args...) void(0)
#else
#define ss_dprintf(dbgcat, fmt, args...)\
        do {\
                if ((dbgcat) & DPRINT_MASK) {\
                    printf(fmt, args); \
                }\
        } while (0)
#endif

#endif //STOSYS_PROJECT_STOSYS_DEBUG_H