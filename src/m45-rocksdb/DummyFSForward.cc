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

#include "DummyFSForward.h"
#include "rocksdb/env.h"
#include "rocksdb/io_status.h"
#include "rocksdb/file_system.h"
#include "rocksdb/status.h"

#include <iostream>
#include <thread>

#include <unistd.h>

namespace ROCKSDB_NAMESPACE {
    IOStatus IOError(const std::string& context, const std::string& file_name,
                     int err_number);

    DummyFSForward::DummyFSForward() {
        this->_private_fs = FileSystem::Default();
        this->_seq_id = 0;
        this->_name = "DummyFSForward to ";
        this->_name = this->_name.append(this->_private_fs->Name());
        this->_ss.str("");
        this->_ss.clear();
    }

    const char *DummyFSForward::Name() const {
        return this->_name.c_str();
    };

    std::string DummyFSForward::get_seq_id() {
        this->_ss.str("");
        this->_ss.clear();
        this->_ss << " call_seq: " << this->_seq_id++ << " tid: " << std::hash<std::thread::id>{}(std::this_thread::get_id()) << " ";
        return this->_ss.str();
    }


// Create a brand new sequentially-readable file with the specified name.
// On success, stores a pointer to the new file in *result and returns OK.
// On failure stores nullptr in *result and returns non-OK.  If the file does
// not exist, returns a non-OK status.
//
// The returned file will only be accessed by one thread at a time.
    IOStatus DummyFSForward::NewSequentialFile(const std::string &fname,
                                               const FileOptions &file_opts,
                                               std::unique_ptr<FSSequentialFile> *result,
                                               IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NewSequentialFile(fname, file_opts, result, dbg);
    }
    
// Create a brand new random access read-only file with the
// specified name.  On success, stores a pointer to the new file in
// *result and returns OK.  On failure stores nullptr in *result and
// returns non-OK.  If the file does not exist, returns a non-OK
// status.
//
// The returned file may be concurrently accessed by multiple threads.
    IOStatus DummyFSForward::NewRandomAccessFile(
            const std::string &fname, const FileOptions &file_opts,
            std::unique_ptr<FSRandomAccessFile> *result,
            IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NewRandomAccessFile(fname, file_opts, result, dbg);
    }

// Create an object that writes to a new file with the specified
// name.  Deletes any existing file with the same name and creates a
// new file.  On success, stores a pointer to the new file in
// *result and returns OK.  On failure stores nullptr in *result and
// returns non-OK.
//
// The returned file will only be accessed by one thread at a time.
    IOStatus DummyFSForward::NewWritableFile(const std::string &fname,
                                             const FileOptions &file_opts,
                                             std::unique_ptr<FSWritableFile> *result,
                                             IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NewWritableFile(fname, file_opts, result, dbg);
    }

// Create an object that writes to a new file with the specified
// name.  Deletes any existing file with the same name and creates a
// new file.  On success, stores a pointer to the new file in
// *result and returns OK.  On failure stores nullptr in *result and
// returns non-OK.
//
// The returned file will only be accessed by one thread at a time.
    IOStatus DummyFSForward::ReopenWritableFile(
            const std::string & fname, const FileOptions & options,
            std::unique_ptr<FSWritableFile> *result, IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->ReopenWritableFile(fname, options, result, dbg);
    }

// Reuse an existing file by renaming it and opening it as writable.
    IOStatus DummyFSForward::ReuseWritableFile(const std::string &fname,
                                               const std::string &old_fname,
                                               const FileOptions &file_opts,
                                               std::unique_ptr<FSWritableFile> *result,
                                               IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->ReuseWritableFile(fname, old_fname, file_opts, result, dbg);
    }

// Open `fname` for random read and write, if file doesn't exist the file
// will be created.  On success, stores a pointer to the new file in
// *result and returns OK.  On failure returns non-OK.
//
// The returned file will only be accessed by one thread at a time.
    IOStatus DummyFSForward::NewRandomRWFile(const std::string & fname,
                                             const FileOptions &options,
                                             std::unique_ptr<FSRandomRWFile> *result,
                                             IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NewRandomRWFile(fname, options, result, dbg);
    }

// Opens `fname` as a memory-mapped file for read and write (in-place updates
// only, i.e., no appends). On success, stores a raw buffer covering the whole
// file in `*result`. The file must exist prior to this call.
    IOStatus DummyFSForward::NewMemoryMappedFileBuffer(
            const std::string &fname,
            std::unique_ptr<MemoryMappedFileBuffer> *result) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NewMemoryMappedFileBuffer(fname, result);
    }

// Create an object that represents a directory. Will fail if directory
// doesn't exist. If the directory exists, it will open the directory
// and create a new Directory object.
//
// On success, stores a pointer to the new Directory in
// *result and returns OK. On failure stores nullptr in *result and
// returns non-OK.
    IOStatus DummyFSForward::NewDirectory(const std::string &name,
                                          const IOOptions &io_opts,
                                          std::unique_ptr<FSDirectory> *result,
                                          IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NewDirectory(name, io_opts, result, dbg);
    }

// Returns OK if the named file exists.
//         NotFound if the named file does not exist,
//                  the calling process does not have permission to determine
//                  whether this file exists, or if the path is invalid.
//         IOError if an IO Error was encountered
    IOStatus DummyFSForward::FileExists(const std::string &fname,
                                        const IOOptions &options,
                                        IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->FileExists(fname, options, dbg);
    }

// Store in *result the names of the children of the specified directory.
// The names are relative to "dir".
// Original contents of *results are dropped.
// Returns OK if "dir" exists and "*result" contains its children.
//         NotFound if "dir" does not exist, the calling process does not have
//                  permission to access "dir", or if "dir" is invalid.
//         IOError if an IO Error was encountered
    IOStatus DummyFSForward::GetChildren(const std::string &dir, const IOOptions &options,
                                         std::vector<std::string> *result,
                                         IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->GetChildren(dir, options, result, dbg);
    }

// Store in *result the attributes of the children of the specified directory.
// In case the implementation lists the directory prior to iterating the files
// and files are concurrently deleted, the deleted files will be omitted from
// result.
// The name attributes are relative to "dir".
// Original contents of *results are dropped.
// Returns OK if "dir" exists and "*result" contains its children.
//         NotFound if "dir" does not exist, the calling process does not have
//                  permission to access "dir", or if "dir" is invalid.
//         IOError if an IO Error was encountered
    IOStatus DummyFSForward::GetChildrenFileAttributes(
            const std::string &dir, const IOOptions &options,
            std::vector<FileAttributes> *result, IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->GetChildrenFileAttributes(dir, options, result, dbg);
    }

// Delete the named file.
    IOStatus DummyFSForward::DeleteFile(const std::string &fname,
                                        const IOOptions &options,
                                        IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->DeleteFile(fname, options, dbg);
    }

// Truncate the named file to the specified size.
    IOStatus DummyFSForward::Truncate(const std::string &fname, size_t size,
                                      const IOOptions &options,
                                      IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->Truncate(fname, size, options, dbg);
    }

// Create the specified directory. Returns error if directory exists.
    IOStatus DummyFSForward::CreateDir(const std::string &dirname,
                                       const IOOptions &options, IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->CreateDir(dirname, options, dbg);
    }

// Creates directory if missing. Return Ok if it exists, or successful in
// Creating.
    IOStatus DummyFSForward::CreateDirIfMissing(const std::string &dirname,
                                                const IOOptions &options,
                                                IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->CreateDirIfMissing(dirname, options, dbg);
    }

// Delete the specified directory.
    IOStatus DummyFSForward::DeleteDir(const std::string &dirname,
                                       const IOOptions &options, IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->DeleteDir(dirname, options, dbg);
    }

// Store the size of fname in *file_size.
    IOStatus DummyFSForward::GetFileSize(const std::string &fname,
                                         const IOOptions &options, uint64_t *file_size,
                                         IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->GetFileSize(fname, options, file_size, dbg);
    }

// Store the last modification time of fname in *file_mtime.
    IOStatus DummyFSForward::GetFileModificationTime(const std::string &fname,
                                                     const IOOptions &options,
                                                     uint64_t *file_mtime,
                                                     IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->GetFileModificationTime(fname, options, file_mtime, dbg);
    }

// Rename file src to target.
    IOStatus DummyFSForward::RenameFile(const std::string &src, const std::string &target,
                                        const IOOptions &options,
                                        IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->RenameFile(src, target, options, dbg);
    }

// Hard Link file src to target.
    IOStatus DummyFSForward::LinkFile(const std::string &src,
                                      const std::string &target,
                                      const IOOptions &options,
                                      IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->LinkFile(src, target, options, dbg);
    }

    IOStatus DummyFSForward::NumFileLinks(const std::string &fname,
                                          const IOOptions &options,
                                          uint64_t *count, IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NumFileLinks(fname, options, count, dbg);
    }

    IOStatus DummyFSForward::AreFilesSame(const std::string &f,
                                          const std::string &s,
                                          const IOOptions &opt, bool *res,
                                          IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->AreFilesSame(f, s, opt, res, dbg);
    }

// Lock the specified file.  Used to prevent concurrent access to
// the same db by multiple processes.  On failure, stores nullptr in
// *lock and returns non-OK.
//
// On success, stores a pointer to the object that represents the
// acquired lock in *lock and returns OK.  The caller should call
// UnlockFile(*lock) to release the lock.  If the process exits,
// the lock will be automatically released.
//
// If somebody else already holds the lock, finishes immediately
// with a failure.  I.e., this call does not wait for existing locks
// to go away.
//
// May create the named file if it does not already exist.
    IOStatus DummyFSForward::LockFile(const std::string &fname, const IOOptions &options,
                                      FileLock **lock, IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->LockFile(fname, options, lock, dbg);
    }

// Release the lock acquired by a previous successful call to LockFile.
// REQUIRES: lock was returned by a successful LockFile() call
// REQUIRES: lock has not already been unlocked.
    IOStatus DummyFSForward::UnlockFile(FileLock *lock, const IOOptions &options,
                                        IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->UnlockFile(lock, options, dbg);
    }

// *path is set to a temporary directory that can be used for testing. It may
// or many not have just been created. The directory may or may not differ
// between runs of the same process, but subsequent calls will return the
// same directory.
    IOStatus DummyFSForward::GetTestDirectory(const IOOptions &options, std::string *path,
                                              IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->GetTestDirectory(options, path, dbg);
    }

// Create and returns a default logger (an instance of EnvLogger) for storing
// informational messages. Derived classes can overide to provide custom
// logger.
    IOStatus DummyFSForward::NewLogger(const std::string &fname, const IOOptions &io_opts,
                                       std::shared_ptr<Logger> *result,
                                       IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->NewLogger(fname, io_opts, result, dbg);
    }

// Get full directory name for this db.
    IOStatus DummyFSForward::GetAbsolutePath(const std::string &db_path,
                                             const IOOptions &options,
                                             std::string *output_path,
                                             IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->GetAbsolutePath(db_path,options, output_path, dbg);
    }

// Get the amount of free disk space
    IOStatus DummyFSForward::GetFreeSpace(const std::string &path,
                                          const IOOptions &options,
                                          uint64_t *diskfree,
                                          IODebugContext *dbg) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->GetFreeSpace(path, options, diskfree, dbg);
    }

    IOStatus DummyFSForward::IsDirectory(const std::string &path,
                                         const IOOptions &options, bool *is_dir,
                                         IODebugContext *dgb) {
        std::cout << get_seq_id() << " func: " << __FUNCTION__ << " line: " << __LINE__ << " " << std::endl;
        return this->_private_fs->IsDirectory(path, options, is_dir, dgb);
    }
}