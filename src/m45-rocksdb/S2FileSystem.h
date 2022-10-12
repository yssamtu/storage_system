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

#ifndef STOSYS_PROJECT_S2FILESYSTEM_H
#define STOSYS_PROJECT_S2FILESYSTEM_H

#include "rocksdb/env.h"
#include "rocksdb/io_status.h"
#include "rocksdb/file_system.h"
#include "rocksdb/status.h"

#include <zns_device.h>
#include <iostream>

#define LOOKUP_MAP_SIZE 1000
#define MAX_INODE_COUNT 255
#define INODE_SIZE 4096
#define SUPER_BLOCK_SIZE 4096
#define STRINGENCODE 31
#define DATA_BLOCKS_OFFSET 256
namespace ROCKSDB_NAMESPACE
{

    struct Inode
    {
        uint32_t Inode_no;
        char EntityName[235];
        bool IsDir;
        uint64_t FileSize;
        uint64_t Indirect_ptr_lbas;
        uint64_t Direct_data_lbas[480];
    };

    struct mapEntries
    {
        std::string id;
        Inode *ptr;
        mapEntries *chain;
    };

    struct Indirect_ptr
    {
        uint64_t Current_addr;
        uint64_t Direct_data_lbas[510];
        uint64_t Indirect_ptr_lbas;
    };

    struct MYFS_DirData
    {
        char EntityName[252];
        uint32_t InodeNum;
    };

    struct MYFS_Dir
    {
        MYFS_DirData Entities[16];
    };

    struct MYFS
    {
        mapEntries *LookupCache[LOOKUP_MAP_SIZE]; // Map type to void ptrs;
        bool InodeBitMap[MAX_INODE_COUNT];
        bool *DataBitMap;
        uint32_t InodePtr;

        uint64_t DataBlockPtr;
        uint64_t DataBlockMax;

        uint64_t DataBlockCount;
        uint64_t FileSystemCapacity;
        uint32_t LogicalBlockSize;
        Inode *rootEntry;
        user_zns_device *zns;
    };

    /*
    int Load_From_NVM(MYFS *FSObj, uint64_t address, void *ptr, uint64_t size);
    int Store_To_NVM(MYFS *FSObj, uint64_t address, void *ptr, uint64_t size);
    void Get_ParentPath(std::string path, std::string &parent);
    void Get_EntityName(std::string path, std::string &entityName);
    //void Load_Childrens(Inode *ptr, std::string entityName, std::vector<std::string> *children, bool loadChildren);
    // int Get_Path_Inode(MYFS *FSObj, std::string path, Inode *ptr);
    int LookupMap_HashFunction(void *data);
    */
    
    
    class MYFS_File
    {
    private:
        struct Inode *ptr;
        MYFS *FSObj;
	    uint64_t curr_read_offset;

    public:
        MYFS_File(std::string filePath, MYFS *FSObj);
        ~MYFS_File(){};
        int Read(uint64_t size, char *data);
        int PRead(uint64_t offset, uint64_t size, char *data);
        int Seek(uint64_t offset);
        int Truncate(uint64_t size);
        int Append(uint64_t size, char *data);
        int PAppend(uint64_t offset, uint64_t size, char *data);
        uint64_t GetFileSize();
        int Close();
    };

    /*
     *Creates read only MYFS_File object
     */
    class MYFS_SequentialFile : public FSSequentialFile
    {
    private:
        MYFS_File *fp;

    public:
        MYFS_SequentialFile(std::string filePath, MYFS *FSObj);
        virtual ~MYFS_SequentialFile(){delete this->fp;}
        virtual IOStatus Read(size_t n, const IOOptions &opts, Slice *result,
                              char *scratch, IODebugContext *dbg)override;
       
        virtual IOStatus Skip(uint64_t n) override;
        // virtual IOStatus PositionedRead(uint64_t offset, size_t n,
        //                                 const IOOptions &opts, Slice *result,
        //                                 char *scratch, IODebugContext *dbg) override;
        // virtual IOStatus InvalidateCache(size_t offset, size_t length) override
        // {
        //     return IOStatus::OK();
        // };
        // virtual bool use_direct_io() const override { return true; }
        // virtual size_t GetRequiredBufferAlignment() const override { return 4096; }
    };

    class MYFS_RandomAccessFile : public FSRandomAccessFile
    {
    private:
        MYFS_File *fp;

    public:
        MYFS_RandomAccessFile(std::string fname, MYFS *FSObj);
        virtual ~MYFS_RandomAccessFile(){delete this->fp;}
        virtual IOStatus Read(uint64_t offset, size_t n, const IOOptions &opts,
                              Slice *result, char *scratch, IODebugContext *dbg) const override;
        /*
        virtual IOStatus MultiRead(FSReadRequest *reqs, size_t num_reqs,
                                   const IOOptions &options,
                                   IODebugContext *dbg) {std::cout<<"MULTIREAD"<<std::endl;return IOStatus::OK();}

        virtual IOStatus Prefetch(uint64_t offset, size_t n, const IOOptions &opts,
                                  IODebugContext *dbg) {std::cout<<"PRE-FETCH"<<std::endl;return IOStatus::OK();}

        virtual IOStatus InvalidateCache(size_t offset, size_t length) override { return IOStatus::OK(); };
        virtual bool use_direct_io() const override { return true; }
        virtual size_t GetRequiredBufferAlignment() const override { return 4096; }
        */
    };

    class MYFS_WritableFile : public FSWritableFile
    {
    private:
        MYFS_File *fp;

    public:
        MYFS_WritableFile(std::string fname, MYFS *FSObj);
        virtual ~MYFS_WritableFile(){delete this->fp;}
        virtual IOStatus Truncate(uint64_t size, const IOOptions &opts,
                                  IODebugContext *dbg) override;
        virtual IOStatus Close(const IOOptions &opts, IODebugContext *dbg) {return IOStatus::OK();};
        virtual IOStatus Append(const Slice &data, const IOOptions &opts,
                                IODebugContext *dbg) override;
        virtual IOStatus Flush(const IOOptions &opts, IODebugContext *dbg) override { return IOStatus::OK(); }
        virtual IOStatus Sync(const IOOptions &opts, IODebugContext *dbg) override { return IOStatus::OK(); }
        /*
        virtual IOStatus Append(const Slice &data, const IOOptions &opts,
                                const DataVerificationInfo & /* verification_info ,
                                IODebugContext *dbg) override
        {
            return Append(data, opts, dbg);
        }
        virtual IOStatus PositionedAppend(const Slice &data, uint64_t offset,
                                          const IOOptions &opts,
                                          IODebugContext *dbg) override;
        virtual IOStatus PositionedAppend(const Slice &data, uint64_t offset,
                                          const IOOptions &opts, const DataVerificationInfo & /* verification_info,
                                          IODebugContext *dbg) override
        {
            return PositionedAppend(data, offset, opts, dbg);
        }
        
        virtual IOStatus Fsync(const IOOptions &opts, IODebugContext *dbg) override { return IOStatus::OK(); }
        virtual bool IsSyncThreadSafe() const { return false; }
        virtual bool use_direct_io() const override { return true; }
        virtual void SetWriteLifeTimeHint(Env::WriteLifeTimeHint hint) override {}
        virtual uint64_t GetFileSize(const IOOptions &opts,
                                     IODebugContext *dbg) override {std::cout<<"Calling this module"<<std::endl;;return this->fp->GetFileSize();}
        virtual IOStatus InvalidateCache(size_t offset, size_t length) override { return IOStatus::OK(); }
        virtual size_t GetRequiredBufferAlignment() const override { return 4096; }
        */
    };

    class MYFS_Directory : public FSDirectory
    {
        /*
            public:
            virtual IOStatus Fsync(const IOOptions& opts, IODebugContext* dbg) override {
                return IOStatus::OK();
            }

                virtual IOStatus Close(const IOOptions& opts, IODebugContext* dbg) override {
                return IOStatus::OK();
            }

                virtual IOStatus FsyncWithDirOptions(const IOOptions&, IODebugContext*,
                                 const DirFsyncOptions& dir_fsync_options) override {
                return IOStatus::OK();
            }
        */
    };

    class S2FileSystem : public FileSystem
    {
    public:
        // No copying allowed
        S2FileSystem(std::string uri, bool debug);
        S2FileSystem(const S2FileSystem &) = delete;
        virtual ~S2FileSystem();

        IOStatus IsDirectory(const std::string &, const IOOptions &options, bool *is_dir, IODebugContext *) override;

        IOStatus
        NewSequentialFile(const std::string &fname, const FileOptions &file_opts,
                          std::unique_ptr<FSSequentialFile> *result,
                          IODebugContext *dbg);

        IOStatus
        NewRandomAccessFile(const std::string &fname, const FileOptions &file_opts,
                            std::unique_ptr<FSRandomAccessFile> *result,
                            IODebugContext *dbg);

        IOStatus
        NewWritableFile(const std::string &fname, const FileOptions &file_opts, std::unique_ptr<FSWritableFile> *result,
                        IODebugContext *dbg);

        IOStatus
        ReopenWritableFile(const std::string &, const FileOptions &, std::unique_ptr<FSWritableFile> *,
                           IODebugContext *);

        IOStatus
        NewRandomRWFile(const std::string &, const FileOptions &, std::unique_ptr<FSRandomRWFile> *, IODebugContext *);

        IOStatus NewMemoryMappedFileBuffer(const std::string &, std::unique_ptr<MemoryMappedFileBuffer> *);

        IOStatus NewDirectory(const std::string &name, const IOOptions &io_opts, std::unique_ptr<FSDirectory> *result,
                              IODebugContext *dbg);

        const char *Name() const;

        IOStatus GetFreeSpace(const std::string &, const IOOptions &, uint64_t *, IODebugContext *);

        IOStatus Truncate(const std::string &, size_t, const IOOptions &, IODebugContext *);

        IOStatus CreateDir(const std::string &dirname, const IOOptions &options, IODebugContext *dbg);

        IOStatus CreateDirIfMissing(const std::string &dirname, const IOOptions &options, IODebugContext *dbg);

        IOStatus
        GetFileSize(const std::string &fname, const IOOptions &options, uint64_t *file_size, IODebugContext *dbg);

        IOStatus DeleteDir(const std::string &dirname, const IOOptions &options, IODebugContext *dbg);

        IOStatus
        GetFileModificationTime(const std::string &fname, const IOOptions &options, uint64_t *file_mtime,
                                IODebugContext *dbg);

        IOStatus
        GetAbsolutePath(const std::string &db_path, const IOOptions &options, std::string *output_path,
                        IODebugContext *dbg);

        IOStatus DeleteFile(const std::string &fname,
                            const IOOptions &options,
                            IODebugContext *dbg);

        IOStatus
        NewLogger(const std::string &fname, const IOOptions &io_opts, std::shared_ptr<Logger> *result,
                  IODebugContext *dbg);

        IOStatus GetTestDirectory(const IOOptions &options, std::string *path, IODebugContext *dbg);

        IOStatus UnlockFile(FileLock *lock, const IOOptions &options, IODebugContext *dbg);

        IOStatus LockFile(const std::string &fname, const IOOptions &options, FileLock **lock, IODebugContext *dbg);

        IOStatus AreFilesSame(const std::string &, const std::string &, const IOOptions &, bool *, IODebugContext *);

        IOStatus NumFileLinks(const std::string &, const IOOptions &, uint64_t *, IODebugContext *);

        IOStatus LinkFile(const std::string &, const std::string &, const IOOptions &, IODebugContext *);

        IOStatus
        RenameFile(const std::string &src, const std::string &target, const IOOptions &options, IODebugContext *dbg);

        IOStatus
        GetChildrenFileAttributes(const std::string &dir, const IOOptions &options, std::vector<FileAttributes> *result,
                                  IODebugContext *dbg);

        IOStatus
        GetChildren(const std::string &dir, const IOOptions &options, std::vector<std::string> *result,
                    IODebugContext *dbg);

        IOStatus FileExists(const std::string &fname, const IOOptions &options, IODebugContext *dbg);

        IOStatus ReuseWritableFile(const std::string &fname, const std::string &old_fname, const FileOptions &file_opts,
                                   std::unique_ptr<FSWritableFile> *result, IODebugContext *dbg);

    private:
        struct user_zns_device *_zns_dev;
        std::string _uri;
        const std::string _fs_delimiter = "/";
        struct MYFS *FileSystemObj;
    };
}

#endif // STOSYS_PROJECT_S2FILESYSTEM_H
