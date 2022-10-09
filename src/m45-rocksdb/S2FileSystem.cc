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
#include <string>
#include <iostream>
#include <sys/mman.h>

#include <stosys_debug.h>
#include <utils.h>

namespace ROCKSDB_NAMESPACE {
    int LookupMap_HashFunction(void *data) {
         return *((int*) data) / LOOKUP_MAP_SIZE;
    }

    int LookupMap_Lookup(MYFS *FSObj, std::string id, void *ptr) {

    }

    int LookupMap_Insert(MYFS *FSObj, std::string id, void *ptr) {

    }

    int Load_From_NVM(uint64_t addr, void *buffer, uint64_t size) {
	return 0;
    }

    int Store_To_NVM(uint64_t addr, void *buffer, uint64_t size) {
        return 0;
    }

    uint32_t get_FreeInode(MYFS *FSObj) {
    
    }

    uint64_t get_FreeDataBlock(MYFS *FSObj) {
    
    }

    //Trim till /../path in /../path/name
    void Get_ParentPath(std::string path, std::string &parent) {
	int index;
	for(int i=path.size()-1; i>=0; i--) {
	    if (path[i]=='/') {
	        index = i;
	    	break;
	    }
	}
	parent = path.substr(0,index);
    }

    //Trim /../path/name to name
    void Get_EntityName(std::string path, std::string &entityName) {
	int index;
        for(int i=path.size()-1; i>=0; i--) {
            if (path[i]=='/') {
                index = i;
                break;
            }
        }
        parent = path.substr(index+1,path.size());
    }

    //Load_Childrent function reads DIR's data, either store children names in vector or return inode of asked child depending on bool
    //return value will be 0 if asked child is not present
    uint32_t Load_Children(Inode *ptr, std::string entitiyName, std::vector<std::string> *children, bool loadChildren) {
	//Check no of children and load it
	uint64_t childrens_count = ptr->FileSize;

    }

    //A recursive call to load inode of the given path to lookupmap
    //Stores the inode ptr as well, returns 0 in success	
    int Get_Path_Inode(MYFS *FSObj, std::string path, Inode *ptr) {
        if (path=="/tmp") {
	   ptr = FSObj->rootEntry;
	   return 0;
	}
	    
	//Check if path in lookupMap cache
	int isPresent = LookupMap_Lookup(FSObj, path, ptr);
	if(!isPresent)
	    return 0;

	//if not : Get_Path_Inode for parent dir
	std::string parent;
	Inode *parentInode;

	Get_ParentPath(path, parent);
	isPresent = Get_Path_Inode(FSObj, parent, parentInode);
	if(isPresent)
	    return -1;
	//Read parent dir and get asked inode number
	if(parentInode->FileSize == 0)
	    return -1;

	//Get Entity to search for
	std::string entityName;
	Get_EntityName(path, entityName);
	uint32_t index = Load_Children(parentInode, entityName, NULL, false);
	if (index)
	    return -1;

	//Load the children index inode from disk and store in lookupMap;
	uint64_t address = SUPER_BLOCK_SIZE + index * INODE_SIZE;
	ptr = (Inode *) calloc(1, sizeof(Inode));
	isPresent = Load_From_NVM(address, ptr, (uint64_t) INODE_SIZE);
	if (isPresent)
	    return -1;

	//Put it in lookup Map    	
    	LookupMap_Insert(FSObj, path, ptr);

	return 0;
    }


    int Update_Parent(MYFS *FSObj, std::string Ppath, std::string childName, uint32_t childInode) {
        Inode *ptr;
        int isPresent = Get_Path_Inode(FSObj, Ppath, ptr);
        ptr->FileSize += 1;
	//FIXME : Get the dir update logic here
	return 0;
    }


    int MYFS_CreateFile(MYFS *FSObj, std::string path) {
        uint32_t inode_no = get_FreeInode(FSObj);
        Inode *ptr = (Inode *) calloc(1, sizeof(Inode));
        //Fill the ptr
        std::string entityName;
        Get_EntityName(path, entityName);
        strcpy(ptr->EntityName,entityName.c_str());

        //Update parent
	std::string parent;
	Get_ParentPath(path, parent);
	int parentUpdated = Update_Parent(FSObj, parent, entityName, inode_no);
        if (parentUpdated)
	    return -1;

    	//Load to lookupmap
        LookupMap_Insert(FSObj, path, ptr);
        
	return 0;
    }

    int MYFS_CreateDir(MYFS *FSObj, std::string path) {
        uint32_t inode_no = get_FreeInode(FSObj);
        Inode *ptr = (Inode *) calloc(1, sizeof(Inode));

        //Fill the ptr
        std::string entityName;
        Get_EntityName(path, entityName);
        strcpy(ptr->EntityName,entityName.c_str());
        ptr->IsDir = true;

	//Update parent
        std::string parent;
        Get_ParentPath(path, parent);
        int parentUpdated = Update_Parent(FSObj, parent, entityName, inode_no);
        if (parentUpdated)
            return -1;

        //Load to lookupmap
        LookupMap_Insert(FSObj, path, ptr);
	
    	return 0;
    }


    S2FileSystem::S2FileSystem(std::string uri_db_path, bool debug) {
        FileSystem::Default();
        std::string sdelimiter = ":";
        std::string edelimiter = "://";
        this->_uri = uri_db_path;
        struct zdev_init_params params;
        std::string device = uri_db_path.substr(uri_db_path.find(sdelimiter) + sdelimiter.size(),
                                                uri_db_path.find(edelimiter) -
                                                (uri_db_path.find(sdelimiter) + sdelimiter.size()));
        //make sure to setup these parameters properly and check the forced reset flag for M5
        params.name = strdup(device.c_str());
        params.log_zones = 3;
        params.gc_wmark = 1;
        params.force_reset = true;
        int ret = init_ss_zns_device(&params, &this->_zns_dev);
        if(ret != 0){
            std::cout << "Error: " << uri_db_path << " failed to open the device " << device.c_str() << "\n";
            std::cout << "Error: ret " << ret << "\n";
        }
        assert (ret == 0);
        assert(this->_zns_dev->lba_size_bytes != 0);
        assert(this->_zns_dev->capacity_bytes != 0);
        ss_dprintf(DBG_FS_1, "device %s is opened and initialized, reported LBA size is %u and capacity %lu \n",
                   device.c_str(), this->_zns_dev->lba_size_bytes, this->_zns_dev->capacity_bytes);
    
    
    	//INIT File System
	//TODO: In case of persistency; Read following data from Super block
	//Init Bitmaps from disk
	if (debug)
	    std::cout<<"Init MYFS"<<std::endl;
	this->FileSystemObj = (MYFS *) calloc(1, sizeof(MYFS));
	this->FileSystemObj->FileSystemCapacity = this->_zns_dev->capacity_bytes;
	this->FileSystemObj->LogicalBlockSize = this->_zns_dev->lba_size_bytes;
	//We reserve a single block as super block and MAX_INODE_COUNT as 
	this->FileSystemObj->DataBlockCount = (this->FileSystemObj->FileSystemCapacity / this->FileSystemObj->LogicalBlockSize
					    - (MAX_INODE_COUNT + 1));
	if (debug)
	    std::cout<<"File System params : "<<this->FileSystemObj->FileSystemCapacity<<" "<<
		    this->FileSystemObj->LogicalBlockSize<<" "<<this->FileSystemObj->DataBlockCount<<std::endl;

	//Init Data blocks bitmap
	this->FileSystemObj->DataBitMap = (bool*) calloc(this->FileSystemObj->DataBlockCount, sizeof(bool));
	
	//Init root inode
	//TODO: In case of persistency check if already present in disk
	//FIXME: Get root dir name dynamically
	strcpy(this->FileSystemObj->rootEntry->EntityName,"tmp");
	this->FileSystemObj->rootEntry->IsDir = true;
	this->FileSystemObj->rootEntry->FileSize = 0;	
    }

    S2FileSystem::~S2FileSystem() {
    }

    // Create a brand new sequentially-readable file with the specified name.
    // On success, stores a pointer to the new file in *result and returns OK.
    // On failure stores nullptr in *result and returns non-OK.  If the file does
    // not exist, returns a non-OK status.
    //
    // The returned file will only be accessed by one thread at a time.
    IOStatus S2FileSystem::NewSequentialFile(const std::string &fname, const FileOptions &file_opts,
                                             std::unique_ptr<FSSequentialFile> *result, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::IsDirectory(const std::string &, const IOOptions &options, bool *is_dir, IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    // Create a brand new random access read-only file with the
    // specified name.  On success, stores a pointer to the new file in
    // *result and returns OK.  On failure stores nullptr in *result and
    // returns non-OK.  If the file does not exist, returns a non-OK
    // status.
    //
    // The returned file may be concurrently accessed by multiple threads.
    IOStatus S2FileSystem::NewRandomAccessFile(const std::string &fname, const FileOptions &file_opts,
                                               std::unique_ptr<FSRandomAccessFile> *result, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    const char *S2FileSystem::Name() const {
        return "S2FileSytem";
    }

    // Create an object that writes to a new file with the specified
    // name.  Deletes any existing file with the same name and creates a
    // new file.  On success, stores a pointer to the new file in
    // *result and returns OK.  On failure stores nullptr in *result and
    // returns non-OK.
    //
    // The returned file will only be accessed by one thread at a time.
    IOStatus S2FileSystem::NewWritableFile(const std::string &fname, const FileOptions &file_opts,
                                           std::unique_ptr<FSWritableFile> *result, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::ReopenWritableFile(const std::string &, const FileOptions &, std::unique_ptr<FSWritableFile> *,
                                              IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::NewRandomRWFile(const std::string &, const FileOptions &, std::unique_ptr<FSRandomRWFile> *,
                                           IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::NewMemoryMappedFileBuffer(const std::string &, std::unique_ptr<MemoryMappedFileBuffer> *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    // Create an object that represents a directory. Will fail if directory
    // doesn't exist. If the directory exists, it will open the directory
    // and create a new Directory object.
    //
    // On success, stores a pointer to the new Directory in
    // *result and returns OK. On failure stores nullptr in *result and
    // returns non-OK.
    IOStatus
    S2FileSystem::NewDirectory(const std::string &name, const IOOptions &io_opts, std::unique_ptr<FSDirectory> *result,
                               IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetFreeSpace(const std::string &, const IOOptions &, uint64_t *, IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::Truncate(const std::string &, size_t, const IOOptions &, IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    // Create the specified directory. Returns error if directory exists.
    IOStatus S2FileSystem::CreateDir(const std::string &dirname, const IOOptions &options, IODebugContext *dbg) {
        Inode *ptr;
        int isPresent = Get_Path_Inode(this->FileSystemObj, dirname, ptr);
	if (isPresent)
	    isPresent = MYFS_CreateDir(this->FileSystemObj, dirname);
	else
	    return IOStatus::IOError(__FUNCTION__);

	return IOStatus::OK();
    }

    // Creates directory if missing. Return Ok if it exists, or successful in
    // Creating.
    IOStatus S2FileSystem::CreateDirIfMissing(const std::string &dirname, const IOOptions &options, IODebugContext *dbg) {
	Inode *ptr;
	int isPresent = Get_Path_Inode(this->FileSystemObj, dirname, ptr);	
	if (isPresent)
		isPresent = MYFS_CreateDir(this->FileSystemObj, dirname);
	if (isPresent)
		return IOStatus::IOError(__FUNCTION__);
	return IOStatus::OK();
    }

    IOStatus
    S2FileSystem::GetFileSize(const std::string &fname, const IOOptions &options, uint64_t *file_size, IODebugContext *dbg) {
        Inode *ptr;
	int isPresent = Get_Path_Inode(this->FileSystemObj, fname, ptr);
	if (isPresent)
	    return IOStatus::IOError(__FUNCTION__);
	else
	    *file_size = ptr->FileSize;
	return IOStatus::OK();
    }

    IOStatus S2FileSystem::DeleteDir(const std::string &dirname, const IOOptions &options, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetFileModificationTime(const std::string &fname, const IOOptions &options, uint64_t *file_mtime,
                                                   IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetAbsolutePath(const std::string &db_path, const IOOptions &options, std::string *output_path,
                                           IODebugContext *dbg) {
        *output_path = db_path;
	return IOStatus::OK();
    }

    IOStatus S2FileSystem::DeleteFile(const std::string &fname, const IOOptions &options, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::NewLogger(const std::string &fname, const IOOptions &io_opts, std::shared_ptr<Logger> *result,
                                     IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetTestDirectory(const IOOptions &options, std::string *path, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    // Release the lock acquired by a previous successful call to LockFile.
    // REQUIRES: lock was returned by a successful LockFile() call
    // REQUIRES: lock has not already been unlocked.
    IOStatus S2FileSystem::UnlockFile(FileLock *lock, const IOOptions &options, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
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
    IOStatus S2FileSystem::LockFile(const std::string &fname, const IOOptions &options, FileLock **lock, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus
    S2FileSystem::AreFilesSame(const std::string &, const std::string &, const IOOptions &, bool *, IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::NumFileLinks(const std::string &, const IOOptions &, uint64_t *, IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::LinkFile(const std::string &, const std::string &, const IOOptions &, IODebugContext *) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::RenameFile(const std::string &src, const std::string &target, const IOOptions &options,
                                      IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetChildrenFileAttributes(const std::string &dir, const IOOptions &options,
                                                     std::vector<FileAttributes> *result, IODebugContext *dbg) {
        return FileSystem::GetChildrenFileAttributes(dir, options, result, dbg);
    }

    // Store in *result the names of the children of the specified directory.
    // The names are relative to "dir".
    // Original contents of *results are dropped.
    // Returns OK if "dir" exists and "*result" contains its children.
    //         NotFound if "dir" does not exist, the calling process does not have
    //                  permission to access "dir", or if "dir" is invalid.
    //         IOError if an IO Error was encountered
    IOStatus S2FileSystem::GetChildren(const std::string &dir, const IOOptions &options, std::vector<std::string> *result,
                                       IODebugContext *dbg) {
        Inode *ptr;
	int err = Get_Path_Inode(this->FileSystemObj, dir, ptr);
	if (err)
	    return IOStatus::IOError(__FUNCTION__);
	Load_Children(ptr, "", result, true);
        return IOStatus::OK();
    }

    // Returns OK if the named file exists.
    //         NotFound if the named file does not exist,
    //                  the calling process does not have permission to determine
    //                  whether this file exists, or if the path is invalid.
    //         IOError if an IO Error was encountered
    IOStatus S2FileSystem::FileExists(const std::string &fname, const IOOptions &options, IODebugContext *dbg) {
        Inode *ptr;
	int isPresent = Get_Path_Inode(this->FileSystemObj, fname, ptr);
        if (isPresent)
	    return IOStatus::IOError(__FUNCTION__);
    	return IOStatus::OK();
    }

    IOStatus
    S2FileSystem::ReuseWritableFile(const std::string &fname, const std::string &old_fname, const FileOptions &file_opts,
                                    std::unique_ptr<FSWritableFile> *result, IODebugContext *dbg) {
        return IOStatus::IOError(__FUNCTION__);
    }
}
