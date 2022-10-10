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

namespace ROCKSDB_NAMESPACE
{
    int LookupMap_HashFunction(std::string id)
    {
        unsigned hashindex;
        char *ptr = const_cast<char *>(id.c_str());
        for (hashindex = 0; *ptr != '\0'; ptr++)
            hashindex = *ptr + STRINGENCODE * hashindex;
        return hashindex % LOOKUP_MAP_SIZE;
    }

    int LookupMap_Insert(MYFS *FSObj, std::string id, Inode *ptr)
    {
        int index = LookupMap_HashFunction(id);

        mapEntries *map = (mapEntries *)calloc(1, sizeof(mapEntries));
        map->id = id;
        map->ptr = ptr;
        map->chain = NULL;

        if (FSObj->LookupCache[index] == NULL)
            FSObj->LookupCache[index] = map;
        else
        {
            struct mapEntries *head;
            head = FSObj->LookupCache[index];
            while (head->chain != NULL)
                head = head->chain;
            head->chain = map;
        }

        return 0;
    }

    int LookupMap_Delete(MYFS *FSObj, std::string id)
    {
        int index = LookupMap_HashFunction(id);
        struct mapEntries *head, *tmp;
        head = FSObj->LookupCache[index];

        while (head != NULL)
        {
            if (head->id == id)
            {
                if (tmp == NULL)
                    FSObj->LookupCache[index] = head->chain;
                else
                    tmp->chain = head->chain;
                free(head);
                break;
            }
            head = head->chain;
        }

        return 0;
    }

    int LookupMap_Lookup(MYFS *FSObj, std::string id, Inode **ptr)
    {
        int index = LookupMap_HashFunction(id);
        struct mapEntries *head;
        head = FSObj->LookupCache[index];

        while (head != NULL)
        {
            if (head->id == id)
                break;
            head = head->chain;
        }

        if (head == NULL)
            return -1;

        *ptr = head->ptr;
        return 0;
    }

    int Load_From_NVM(MYFS *FSObj, uint64_t addr, void *buffer, uint64_t size)
    {
        // Check the size if quantization of LBA
        int err = zns_udevice_read(FSObj->zns, addr, buffer, size);
        return err;
    }

    int Store_To_NVM(MYFS *FSObj, uint64_t addr, void *buffer, uint64_t size)
    {
        int err = zns_udevice_write(FSObj->zns, addr, buffer, size);
        return err;
    }

    uint32_t get_FreeInode(MYFS *FSObj)
    {
        uint32_t ptr = (FSObj->InodePtr + 1) % MAX_INODE_COUNT;
        while (ptr != FSObj->InodePtr)
        {
            if (!FSObj->InodeBitMap[ptr])
            {
                FSObj->InodePtr = ptr;
                return ptr;
            }
            ptr = (ptr + 1) % MAX_INODE_COUNT;
        }
        return 0;
    }

    uint64_t get_FreeDataBlock(MYFS *FSObj)
    {
        uint64_t ptr = (FSObj->DataBlockPtr + 1) % FSObj->DataBlockCount;
        while (ptr != FSObj->DataBlockPtr)
        {
            if (!FSObj->DataBitMap[ptr])
            {
                FSObj->DataBlockPtr = ptr;
                return (ptr + DATA_BLOCKS_OFFSET) * FSObj->LogicalBlockSize;
            }
            ptr = (ptr + 1) % FSObj->DataBlockCount;
        }
        return 0;
    }

    void free_DataBlock(MYFS *FSObj, uint64_t addr)
    {
        int index = (addr / FSObj->LogicalBlockSize) - DATA_BLOCKS_OFFSET;
        FSObj->DataBitMap[index] = false;
    }

    // Trim till /../path in /../path/name
    void Get_ParentPath(std::string path, std::string &parent)
    {
        int index;
        for (int i = path.size() - 1; i >= 0; i--)
        {
            if (path[i] == '/')
            {
                index = i;
                break;
            }
        }
        // Trim if additional slash is present
        if (path[index - 1] == '/')
            index--;

        parent = path.substr(0, index);
    }

    // Trim /../path/name to name
    void Get_EntityName(std::string path, std::string &entityName)
    {
        int index;
        for (int i = path.size() - 1; i >= 0; i--)
        {
            if (path[i] == '/')
            {
                index = i;
                break;
            }
        }
        entityName = path.substr(index + 1, path.size());
    }

    // Load_Childrent function reads DIR's data, either store children names in vector or return inode of asked child depending on bool
    // return value will be 0 if asked child is not present
    uint32_t Load_Children(MYFS *FSObj, Inode *ptr, std::string entityName, std::vector<std::string> *children, bool loadChildren)
    {
        // Check no of children and load it
        // FIXME: Logic for rename
        uint64_t children_count = ptr->FileSize;

        MYFS_Dir *dir_ptr = (MYFS_Dir *)calloc(1, sizeof(MYFS_Dir));
        for (int i = 0; i < children_count / 16; i++)
        {
            Load_From_NVM(FSObj, ptr->Direct_data_lbas[i], dir_ptr, 4096);
            for (int j = 0; j < 16; j++)
            {
                if (loadChildren)
                    children->push_back(dir_ptr->Entities[j].EntityName);
                else
                {
                    if (!strcmp(dir_ptr->Entities[j].EntityName, entityName.c_str()))
                    {
                        free(dir_ptr);
                        return dir_ptr->Entities[j].InodeNum;
                    }
                }
            }
        }

        Load_From_NVM(FSObj, ptr->Direct_data_lbas[children_count / 16], dir_ptr, 4096);
        for (int i = 0; i < children_count % 16; i++)
        {
            if (loadChildren)
                children->push_back(dir_ptr->Entities[i].EntityName);
            else
            {
                if (!strcmp(dir_ptr->Entities[i].EntityName, entityName.c_str()))
                {
                    free(dir_ptr);
                    return dir_ptr->Entities[i].InodeNum;
                }
            }
        }

        free(dir_ptr);
        return 0;
    }

    // A recursive call to load inode of the given path to lookupmap
    // Stores the inode ptr as well, returns 0 in success
    int Get_Path_Inode(MYFS *FSObj, std::string path, Inode **ptr)
    {
        if (path == "/tmp")
        {
            *ptr = FSObj->rootEntry;
            std::cout << (*ptr)->EntityName << std::endl;
            return 0;
        }

        std::cout << "Path to look for : " << path << std::endl;
        // Check if path in lookupMap cache
        int isPresent = LookupMap_Lookup(FSObj, path, ptr);
        if (!isPresent)
            return 0;

        // if not : Get_Path_Inode for parent dir
        std::string parent;
        Inode *parentInode;
        Get_ParentPath(path, parent);
        std::cout << "Parent path : " << parent << std::endl;
        isPresent = Get_Path_Inode(FSObj, parent, &parentInode);
        if (isPresent)
            return -1;
        // Read parent dir and get asked inode number
        if (parentInode->FileSize == 0)
            return -1;

        // Get Entity to search for
        std::string entityName;
        Get_EntityName(path, entityName);
        uint32_t index = Load_Children(FSObj, parentInode, entityName, NULL, false);
        if (index)
            return -1;

        // Load the children index inode from disk and store in lookupMap;
        uint64_t address = SUPER_BLOCK_SIZE + index * INODE_SIZE;
        ptr = (Inode **)calloc(1, sizeof(Inode));
        isPresent = Load_From_NVM(FSObj, address, ptr, (uint64_t)INODE_SIZE);
        if (isPresent)
            return -1;

        // Put it in lookup Map
        LookupMap_Insert(FSObj, path, *ptr);

        return 0;
    }

    int Update_Parent(MYFS *FSObj, std::string Ppath, std::string childName, uint32_t childInode, bool del = false)
    {
        // FIXME: Logic for deletion and rename

        Inode *ptr;
        int isPresent = Get_Path_Inode(FSObj, Ppath, &ptr);
        if (isPresent)
            return -1;

        MYFS_DirData dirDataptr;
        strcpy(dirDataptr.EntityName, childName.c_str());
        dirDataptr.InodeNum = childInode;

        MYFS_Dir *dirPtr;
        dirPtr = (MYFS_Dir *)calloc(1, sizeof(MYFS_Dir));
        int index = (++ptr->FileSize) / 16;
        uint64_t addr = ptr->Direct_data_lbas[index];

        if (!addr)
        {
            addr = get_FreeDataBlock(FSObj);
            ptr->Direct_data_lbas[index] = addr;
        }
        else
        {
            index = Load_From_NVM(FSObj, addr, dirPtr, 4096);
            if (index)
                return -1;
        }

        index = ptr->FileSize % 16;
        dirPtr->Entities[index - 1] = dirDataptr;
        Store_To_NVM(FSObj, addr, dirPtr, 4096);
        free(dirPtr);

        return 0;
    }

    void MYFS_DeletePath(MYFS *FSObj, std::string path)
    {
        Inode *ptr;
        int isPresent = Get_Path_Inode(FSObj, path, &ptr);
        if (isPresent)
            return;
        // TODO: Handle logic if dir
        // Free data block of inode as well!

        // Update Parent
        std::string ppath;
        Get_ParentPath(path, ppath);
        // Delete from lookup map
    }

    int MYFS_CreateFile(MYFS *FSObj, std::string path)
    {
        uint32_t inode_no = get_FreeInode(FSObj);
        Inode *ptr = (Inode *)calloc(1, sizeof(Inode));
        // Fill the ptr
        std::string entityName;
        Get_EntityName(path, entityName);
        strcpy(ptr->EntityName, entityName.c_str());

        // Update parent
        std::string parent;
        Get_ParentPath(path, parent);
        int parentUpdated = Update_Parent(FSObj, parent, entityName, inode_no);
        if (parentUpdated)
            return -1;

        // Load to lookupmap
        LookupMap_Insert(FSObj, path, ptr);

        return 0;
    }

    int MYFS_CreateDir(MYFS *FSObj, std::string path)
    {
        uint32_t inode_no = get_FreeInode(FSObj);
        Inode *ptr = (Inode *)calloc(1, sizeof(Inode));

        // Fill the ptr
        std::string entityName;
        Get_EntityName(path, entityName);
        strcpy(ptr->EntityName, entityName.c_str());
        ptr->IsDir = true;

        // Update parent
        std::string parent;
        Get_ParentPath(path, parent);
        int parentUpdated = Update_Parent(FSObj, parent, entityName, inode_no);
        if (parentUpdated)
            return -1;

        // Load to lookupmap
        LookupMap_Insert(FSObj, path, ptr);

        return 0;
    }

    S2FileSystem::S2FileSystem(std::string uri_db_path, bool debug)
    {
        FileSystem::Default();
        std::string sdelimiter = ":";
        std::string edelimiter = "://";
        this->_uri = uri_db_path;
        struct zdev_init_params params;
        std::string device = uri_db_path.substr(uri_db_path.find(sdelimiter) + sdelimiter.size(),
                                                uri_db_path.find(edelimiter) -
                                                    (uri_db_path.find(sdelimiter) + sdelimiter.size()));
        // make sure to setup these parameters properly and check the forced reset flag for M5
        params.name = strdup(device.c_str());
        params.log_zones = 3;
        params.gc_wmark = 1;
        params.force_reset = true;
        int ret = init_ss_zns_device(&params, &this->_zns_dev);
        if (ret != 0)
        {
            std::cout << "Error: " << uri_db_path << " failed to open the device " << device.c_str() << "\n";
            std::cout << "Error: ret " << ret << "\n";
        }
        assert(ret == 0);
        assert(this->_zns_dev->lba_size_bytes != 0);
        assert(this->_zns_dev->capacity_bytes != 0);
        ss_dprintf(DBG_FS_1, "device %s is opened and initialized, reported LBA size is %u and capacity %lu \n",
                   device.c_str(), this->_zns_dev->lba_size_bytes, this->_zns_dev->capacity_bytes);

        // INIT File System
        // TODO: In case of persistency; Read following data from Super block
        // Init Bitmaps from disk
        if (debug)
            std::cout << "Init MYFS" << std::endl;
        this->FileSystemObj = (MYFS *)calloc(1, sizeof(MYFS));
        this->FileSystemObj->zns = this->_zns_dev;
        this->FileSystemObj->FileSystemCapacity = this->_zns_dev->capacity_bytes;
        this->FileSystemObj->LogicalBlockSize = this->_zns_dev->lba_size_bytes;
        // We reserve a single block as super block and MAX_INODE_COUNT as
        this->FileSystemObj->DataBlockCount = (this->FileSystemObj->FileSystemCapacity / this->FileSystemObj->LogicalBlockSize - (MAX_INODE_COUNT + 1));
        if (debug)
            std::cout << "File System params : " << this->FileSystemObj->FileSystemCapacity << " " << this->FileSystemObj->LogicalBlockSize << " " << this->FileSystemObj->DataBlockCount << std::endl;

        // Init Data blocks bitmap
        // this->FileSystemObj->LookupCache = (mapEntries *) calloc(LOOKUP_MAP_SIZE, sizeof(mapEntries));
        this->FileSystemObj->DataBitMap = (bool *)calloc(this->FileSystemObj->DataBlockCount, sizeof(bool));

        // Init root inode
        // TODO: In case of persistency check if already present in disk
        // FIXME: Get root dir name dynamically
        this->FileSystemObj->DataBlockPtr = 0; // Reserved for Root Node
        this->FileSystemObj->InodePtr = 0;
        this->FileSystemObj->InodeBitMap[0] = true;
        this->FileSystemObj->rootEntry = (Inode *)calloc(1, sizeof(Inode));
        strcpy(this->FileSystemObj->rootEntry->EntityName, "tmp");
        this->FileSystemObj->rootEntry->IsDir = true;
        this->FileSystemObj->rootEntry->FileSize = 0;
        this->FileSystemObj->rootEntry->Direct_data_lbas[0] = DATA_BLOCKS_OFFSET * this->FileSystemObj->LogicalBlockSize;
    }

    S2FileSystem::~S2FileSystem()
    {
    }

    // Create a brand new sequentially-readable file with the specified name.
    // On success, stores a pointer to the new file in *result and returns OK.
    // On failure stores nullptr in *result and returns non-OK.  If the file does
    // not exist, returns a non-OK status.
    //
    // The returned file will only be accessed by one thread at a time.
    IOStatus S2FileSystem::NewSequentialFile(const std::string &fname, const FileOptions &file_opts,
                                             std::unique_ptr<FSSequentialFile> *result, IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::IsDirectory(const std::string &, const IOOptions &options, bool *is_dir, IODebugContext *)
    {
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
                                               std::unique_ptr<FSRandomAccessFile> *result, IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    const char *S2FileSystem::Name() const
    {
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
                                           std::unique_ptr<FSWritableFile> *result, IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::ReopenWritableFile(const std::string &, const FileOptions &, std::unique_ptr<FSWritableFile> *,
                                              IODebugContext *)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::NewRandomRWFile(const std::string &, const FileOptions &, std::unique_ptr<FSRandomRWFile> *,
                                           IODebugContext *)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::NewMemoryMappedFileBuffer(const std::string &, std::unique_ptr<MemoryMappedFileBuffer> *)
    {
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
                               IODebugContext *dbg)
    {
        std::cout<<"New Directory "<<name<<std::endl;
        return IOStatus::OK();
    }

    IOStatus S2FileSystem::GetFreeSpace(const std::string &, const IOOptions &, uint64_t *, IODebugContext *)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::Truncate(const std::string &, size_t, const IOOptions &, IODebugContext *)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    // Create the specified directory. Returns error if directory exists.
    IOStatus S2FileSystem::CreateDir(const std::string &dirname, const IOOptions &options, IODebugContext *dbg)
    {
        Inode *ptr;
        int isPresent = Get_Path_Inode(this->FileSystemObj, dirname, &ptr);
        if (isPresent)
            isPresent = MYFS_CreateDir(this->FileSystemObj, dirname);
        else
            return IOStatus::IOError(__FUNCTION__);

        return IOStatus::OK();
    }

    // Creates directory if missing. Return Ok if it exists, or successful in
    // Creating.
    IOStatus S2FileSystem::CreateDirIfMissing(const std::string &dirname, const IOOptions &options, IODebugContext *dbg)
    {
        Inode *ptr;
        std::cout << "If dir missing : " << dirname << std::endl;
        std::string dir = dirname.substr(0, dirname.size() - 1);
        int isPresent = Get_Path_Inode(this->FileSystemObj, dir, &ptr);
        std::cout << "After check : " << std::endl;
        if (isPresent)
            isPresent = MYFS_CreateDir(this->FileSystemObj, dir);
        if (isPresent)
            return IOStatus::IOError(__FUNCTION__);
        return IOStatus::OK();
    }

    IOStatus
    S2FileSystem::GetFileSize(const std::string &fname, const IOOptions &options, uint64_t *file_size, IODebugContext *dbg)
    {
        Inode *ptr;
        int isPresent = Get_Path_Inode(this->FileSystemObj, fname, &ptr);
        if (isPresent)
            return IOStatus::IOError(__FUNCTION__);
        else
            *file_size = ptr->FileSize;
        return IOStatus::OK();
    }

    IOStatus S2FileSystem::DeleteDir(const std::string &dirname, const IOOptions &options, IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetFileModificationTime(const std::string &fname, const IOOptions &options, uint64_t *file_mtime,
                                                   IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetAbsolutePath(const std::string &db_path, const IOOptions &options, std::string *output_path,
                                           IODebugContext *dbg)
    {
        *output_path = db_path;
        std::cout << "Get Abs path" << std::endl;
        return IOStatus::OK();
    }

    IOStatus S2FileSystem::DeleteFile(const std::string &fname, const IOOptions &options, IODebugContext *dbg)
    {
        MYFS_DeletePath(this->FileSystemObj, fname);
        return IOStatus::OK();
    }

    IOStatus S2FileSystem::NewLogger(const std::string &fname, const IOOptions &io_opts, std::shared_ptr<Logger> *result,
                                     IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetTestDirectory(const IOOptions &options, std::string *path, IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    // Release the lock acquired by a previous successful call to LockFile.
    // REQUIRES: lock was returned by a successful LockFile() call
    // REQUIRES: lock has not already been unlocked.
    IOStatus S2FileSystem::UnlockFile(FileLock *lock, const IOOptions &options, IODebugContext *dbg)
    {
        return IOStatus::OK();
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
    IOStatus S2FileSystem::LockFile(const std::string &fname, const IOOptions &options, FileLock **lock, IODebugContext *dbg)
    {
        return IOStatus::OK();
    }

    IOStatus
    S2FileSystem::AreFilesSame(const std::string &, const std::string &, const IOOptions &, bool *, IODebugContext *)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::NumFileLinks(const std::string &, const IOOptions &, uint64_t *, IODebugContext *)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::LinkFile(const std::string &, const std::string &, const IOOptions &, IODebugContext *)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::RenameFile(const std::string &src, const std::string &target, const IOOptions &options,
                                      IODebugContext *dbg)
    {
        // MYFS_DeletePath(this->FileSystemObj, target);
        // FIXME: Logic for rename
        // Change name in Inode
        // Change in parent
        return IOStatus::IOError(__FUNCTION__);
    }

    IOStatus S2FileSystem::GetChildrenFileAttributes(const std::string &dir, const IOOptions &options,
                                                     std::vector<FileAttributes> *result, IODebugContext *dbg)
    {
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
                                       IODebugContext *dbg)
    {
        Inode *ptr;
        int isPresent = Get_Path_Inode(this->FileSystemObj, dir, &ptr);
        if (isPresent)
            return IOStatus::IOError(__FUNCTION__);
        uint32_t err = Load_Children(this->FileSystemObj, ptr, "", result, true);
        if (!err)
            return IOStatus::IOError(__FUNCTION__);
        return IOStatus::OK();
    }

    // Returns OK if the named file exists.
    //         NotFound if the named file does not exist,
    //                  the calling process does not have permission to determine
    //                  whether this file exists, or if the path is invalid.
    //         IOError if an IO Error was encountered
    IOStatus S2FileSystem::FileExists(const std::string &fname, const IOOptions &options, IODebugContext *dbg)
    {
        Inode *ptr;
        std::cout << "File Exists : " << fname << std::endl;
        int isPresent = Get_Path_Inode(this->FileSystemObj, fname, &ptr);
        if (isPresent)
            return IOStatus::IOError(__FUNCTION__);
        return IOStatus::OK();
    }

    IOStatus
    S2FileSystem::ReuseWritableFile(const std::string &fname, const std::string &old_fname, const FileOptions &file_opts,
                                    std::unique_ptr<FSWritableFile> *result, IODebugContext *dbg)
    {
        return IOStatus::IOError(__FUNCTION__);
    }

    // MYFS File
    // class MYFS_File
    // {
    // private:
    //     struct Inode *ptr;
    //     uint64_t curr_offset;
    //     MYFS *FSObj;

    // public:
    //     MYFS_File(std::string filePath)
    //     {
    //     }
    //     ~MYFS_File();
    //     int Read(uint64_t size, char *data);
    //     int PRead(uint64_t offset, uint64_t size, char *data);
    //     int Seek(uint64_t offset);
    //     int Truncate(uint64_t size);
    //     int Append(uint64_t size, char *data);
    //     int PAppend(uint64_t offset, uint64_t size, char *data);
    // };
}
