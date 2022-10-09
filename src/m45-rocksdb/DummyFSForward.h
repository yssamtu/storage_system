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

#ifndef STOSYS_PROJECT_DUMMYFSFORWARD_H
#define STOSYS_PROJECT_DUMMYFSFORWARD_H

#include "rocksdb/env.h"
#include "rocksdb/io_status.h"
#include "rocksdb/file_system.h"
#include "rocksdb/status.h"
#include <zns_device.h>
/*
class MYFS_File : class FSSequentialFile {
	public:
                MYFS_File();
                ~MYFS_File();
                IOStatus Read();
                IOStatus Write();
                IOStatus Close();
	private:
                int fd;
                int inode;
                char *file;
};
*/

namespace ROCKSDB_NAMESPACE {
	/*
    
	class MYFS_SequentialFile : public FSSequentialFile{
        private:
                std::string filename_;
                FILE* file_;
                int fd_;
                bool use_direct_io_;
                size_t logical_sector_size_;

        public:
                MYFS_SequentialFile(const std::string& fname, int fd);
                virtual ~MYFS_SequentialFile();

  virtual IOStatus Read(size_t n, const IOOptions& opts, Slice* result,
                        char* scratch, IODebugContext* dbg) override;
  virtual IOStatus PositionedRead(uint64_t offset, size_t n,
                                  const IOOptions& opts, Slice* result,
                                  char* scratch, IODebugContext* dbg) override;
  virtual IOStatus Skip(uint64_t n) override;
  //virtual IOStatus InvalidateCache(size_t offset, size_t length) override;
  virtual bool use_direct_io() const override { return use_direct_io_; }
  virtual size_t GetRequiredBufferAlignment() const override {
    return logical_sector_size_;
  }
    };
*/
    class DummyFSForward : public FileSystem {
    public:
        // No copying allowed
        DummyFSForward();
        DummyFSForward(const DummyFSForward&) = delete;
        virtual ~DummyFSForward(){};

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

        const char *Name() const override;

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

        IOStatus DeleteFile(const std::string& fname,
                            const IOOptions& options,
                            IODebugContext* dbg);

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
	std::string get_seq_id();
        std::shared_ptr<FileSystem> _private_fs;
        std::atomic<int> _seq_id{};
        std::string _name;
        std::stringstream _ss;
    };
}

#endif //STOSYS_PROJECT_DUMMYFSFORWARD_H
