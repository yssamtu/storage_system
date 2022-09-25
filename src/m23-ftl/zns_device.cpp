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
#include <cstdint>
#include <cstdbool>
#include <cstring>
#include <pthread.h>
#include <cerrno>
#include <libnvme.h>
#include "zns_device.h"

extern "C" {

// enum {BUF_SIZE = 128 * 4096};
// static uint32_t used_buf_size = 0;


//Structure for zone in zns
struct zone_info {
    pthread_mutex_t page_counter_lock;
    uint32_t num_valid_pages; // counter
    unsigned long long physical_zone_saddr;
    zone_info *chain; //Chained in free_zones and used_log_zones_list
};

//Structure for pagemap in log
struct logpage_map {
    uint64_t logical_addr;
    unsigned long long physical_addr;
    zone_info *log_ptr;
    logpage_map *next; //Logpage map for each logical block
};


//Structure for logical block [contains page map and block map]
struct logical_block_map {
    uint64_t logical_block_saddr;
    logpage_map *log_head; //Log page mapping for this logical block
    zone_info *block_ptr; //Point to zone_info
    //TODO: LOCK the access
    pthread_mutex_t logical_block_lock;
};

struct zns_info {
    // Values from init parameters
    uint32_t no_log_zones;
    int gc_trigger;
    char device_name;
    pthread_t gc_thread_id;
    bool run_gc;

    // Query the nisd for following info
    int fd;
    unsigned nsid; 
    uint32_t zns_page_size;
    uint32_t zns_pages_per_zone;
    uint32_t zns_zones_count;
    uint32_t data_zones_count;
    pthread_mutex_t zones_list_lock;

    // Log zone maintainance
    uint32_t no_of_used_log_zones;
    zone_info *used_log_zones_list; // let the new log zone at the end of the array
    zone_info *curr_log_zone; // the index of used_log_zones_list, which is equal to curr_log_zone_saddr / zns_zone_capacity
    
    
    //Logical to Physical mapping page and block
    logical_block_map **map; // Page mapped hashmap for log zone


    //Free zones array
    zone_info *free_zones_list;
};


static int read_from_nvme(zns_info *info, unsigned long long physical_addr,
                          void *buffer, uint32_t size)
{
    unsigned short number_of_pages = size / info->zns_page_size - 1;
    nvme_read(info->fd, info->nsid, physical_addr, number_of_pages,
              0, 0, 0, 0, 0, size, buffer, 0, NULL);
    //ss_nvme_show_status(errno);
    return errno;
}

static int append_to_zone(zns_info *info, unsigned long long saddr, unsigned long long *physical_addr,
                              void *buffer, uint32_t size)
{
    unsigned short number_of_pages = size / info->zns_page_size - 1; //calc from size and page_size 
    //TODO: Later make provision to include meta data containing lba and write size. For persistent log storage.
    nvme_zns_append(info->fd, info->nsid, saddr, number_of_pages,
                    0, 0, 0, 0, size, buffer, 0, NULL, physical_addr);
    //ss_nvme_show_status(errno);
    return errno;
}


static inline int hash_function(uint64_t key, uint32_t base)
{
    return key / base;
}

static inline int offset_function(uint64_t key, uint32_t base) 
{
    return key % base;
}


int count(zone_info *ptr) {
    int count =0;
    while(ptr) {
       count++;
       ptr=ptr->chain;
    }
    return count;
}

void increment_zone_valid_page_counter(zone_info *log) {
    pthread_mutex_lock(&log->page_counter_lock);
    log->num_valid_pages++;
    pthread_mutex_unlock(&log->page_counter_lock);
}

void decrement_zone_valid_page_counter(zone_info *log) {
    pthread_mutex_lock(&log->page_counter_lock);
    log->num_valid_pages--;
    pthread_mutex_unlock(&log->page_counter_lock);
}

//Change this func
static void check_to_change_log_zone(zns_info *info, unsigned long long last_append_addr)
{
    //TODO: Add a check on no of log zone used, trigger gc if it reaches the condition
    //Check if current log zone is ended, then change to next free log zone; FIXME
    if (last_append_addr - info->curr_log_zone->physical_zone_saddr < info->zns_pages_per_zone - 1)
	    return;
    pthread_mutex_lock(&info->zones_list_lock); //Lock for changing used_log_zones_list and accessing free zones list;
	    if(!info->used_log_zones_list)
                info->used_log_zones_list = info->curr_log_zone;
	    else {
	        zone_info *head = info->used_log_zones_list;
		while(head->chain)
                    head = head->chain;
                head->chain = info->curr_log_zone;
	    }
	    info->no_of_used_log_zones++;
    pthread_mutex_unlock(&info->zones_list_lock);
	
      //FIXME: Change the busy wait
    //printf("Wait here %d\n",info->no_of_used_log_zones);  
    while(info->no_of_used_log_zones == info->no_log_zones) {
           continue;
      }
    //printf("Done here\n");


       //Dequeue from free_zone to curr_log_zone;
       pthread_mutex_lock(&info->zones_list_lock);
       info->curr_log_zone = info->free_zones_list;
       info->free_zones_list = info->free_zones_list->chain;
       info->curr_log_zone->chain = NULL;
       pthread_mutex_unlock(&info->zones_list_lock);
    
}


void merge(zns_info *info, logical_block_map *map, zone_info *new_zone) {
    for(uint32_t offset = 0; offset < info->zns_pages_per_zone; offset++) {
    	logpage_map *ptr = map->log_head;
	bool flag = false;
	uint64_t paddr;
	//printf("Logical block saddr : %ld\n",map->logical_block_saddr);
	while(ptr) {
	    if(ptr->logical_addr == map->logical_block_saddr + offset) {
	        paddr = ptr->physical_addr;
		//printf("\tDecrement for %ld %d : ", ptr->log_ptr->physical_zone_saddr, ptr->log_ptr->num_valid_pages);
		decrement_zone_valid_page_counter(ptr->log_ptr);
		flag = true;
		break;
	    }
	    ptr = ptr->next;
	}
	
	//Get block
	if((!flag)&&(map->block_ptr)){
	    flag = true;
	    paddr = map->block_ptr->physical_zone_saddr + offset;
	}

	void *buffer;
	buffer = (void *)calloc(1,info->zns_page_size);
	//Do nvme read on paddr
	if(flag) {
            read_from_nvme(info, paddr, buffer, info->zns_page_size);
	    //Do nvme append new_zone->saddr
            append_to_zone(info, new_zone->physical_zone_saddr, NULL, buffer, info->zns_page_size);
	}
	free(buffer);
	increment_zone_valid_page_counter(new_zone);
    }    
    logpage_map *ptr = map->log_head;
    while(ptr) {
       logpage_map *tmp = ptr;
       ptr = ptr->next;
       free(tmp);
    }
    map->log_head = NULL;
    map->block_ptr = new_zone;
}

void *gc_thread(void *info_ptr) {
    zns_info *info = (zns_info*) info_ptr;
    uint32_t index = 0;
    while(info->run_gc) {
        //Check condition
        while(info->no_of_used_log_zones < info->gc_trigger)
            continue;
 
	logical_block_map *ptr = info->map[index];	
        while(ptr->log_head == NULL) {
	    index = (index + 1) % info->data_zones_count;
	    ptr = info->map[index];
            continue;
	}

	zone_info *free_zone, *old_zone;
	pthread_mutex_lock(&info->zones_list_lock);
	//Get free zone and nullify the chain
            free_zone = info->free_zones_list;
            info->free_zones_list = info->free_zones_list->chain;
            free_zone->chain = NULL;
	pthread_mutex_unlock(&info->zones_list_lock);
			
	
	pthread_mutex_lock(&ptr->logical_block_lock);
	//Merge the logical block to data zone
	    old_zone = ptr->block_ptr;
	    merge(info, ptr, free_zone);
	    ptr->log_head = NULL;
	    ptr->block_ptr = free_zone;
	pthread_mutex_unlock(&ptr->logical_block_lock);

	if(old_zone)
	    old_zone->num_valid_pages = 0;
	pthread_mutex_lock(&info->zones_list_lock);
	//Check used log zone valid counter if zero reset and add to free zone list
	//Append old data zone to free zones list
	zone_info *head = info->free_zones_list;
	if(old_zone) {
	    if(head) {
	        while(head->chain)
                    head = head->chain;
	        head->chain = old_zone;
	    } else {
	        head = old_zone;
	    }
        }

	//FIXME: Remove zone from used_log_zones_list if valid_page is zero and add that zone to free_zones_list
	//Reset if used log zone : if valid pages is reference is zero
	zone_info *tmp = info->used_log_zones_list, *prev = NULL, *sup;
	while(tmp) {
	    bool flag = false;
	    if(tmp->num_valid_pages == 0) {
	    	//reset zone
		nvme_zns_mgmt_send(info->fd, info->nsid, tmp->physical_zone_saddr, false,
                                 NVME_ZNS_ZSA_RESET, 0, NULL);
	
		//Remove from used_log_zones
		info->no_of_used_log_zones--;
		flag = true;
		sup = tmp; //Mark tmp to sup
		tmp = tmp->chain; //Move tmp to next
		sup->chain = NULL; //Disconnect ptr chain
		//Disconnect ptr from used log zone list
		if(prev == NULL)
		    info->used_log_zones_list = tmp;
		else
		    prev->chain = tmp;
		
		//Append sup to free zones	
	    	zone_info *itr = info->free_zones_list;
	        if(itr) {
		    while(itr->chain)
		        itr = itr->chain;
		    itr->chain = sup;
		} else {
		    itr = sup;
		}
			
	    }
	    if(!flag) {
	        prev = tmp;
	        tmp = tmp->chain;
	    }
	}
	pthread_mutex_unlock(&info->zones_list_lock);
	index = (index + 1) % info->data_zones_count;
    }
    return NULL;
}


static int lookup_map(zns_info *info,
                      uint64_t logical_addr, unsigned long long *physical_addr)
{
    int index = hash_function(logical_addr, info->zns_pages_per_zone);
    
   
    //Lock the logical block
    pthread_mutex_lock(&info->map[index]->logical_block_lock);
    
    //Search in log
    logpage_map *head = info->map[index]->log_head;
    while (head) {
        if (head->logical_addr == logical_addr) {
            *physical_addr = head->physical_addr;
	    pthread_mutex_unlock(&info->map[index]->logical_block_lock);
            return 0;
        }
        head = head->next;
    }

    //If not present provide data block addr
    uint32_t offset = offset_function(logical_addr, info->zns_pages_per_zone);
    *physical_addr = info->map[index]->block_ptr->physical_zone_saddr + offset;
    pthread_mutex_unlock(&info->map[index]->logical_block_lock);

    return 0;
}



static void update_map(zns_info *info,
                       uint64_t logical_addr, unsigned long long physical_addr)
{
    int index = hash_function(logical_addr, info->zns_pages_per_zone);
    logical_block_map **map = info->map;
    //Fill in hashmap
    
    //Lock for the update in log
    pthread_mutex_lock(&info->map[index]->logical_block_lock);
    if (map[index]->log_head == NULL) {
    	map[index]->log_head = (logpage_map *)calloc(1, sizeof(logpage_map));
        increment_zone_valid_page_counter(info->curr_log_zone);
        map[index]->log_head->log_ptr = info->curr_log_zone;
        map[index]->log_head->logical_addr = logical_addr;
        map[index]->log_head->physical_addr = physical_addr;
        map[index]->log_head->next = NULL;
	pthread_mutex_unlock(&info->map[index]->logical_block_lock);
        return;
    }
    
    if (map[index]->log_head->logical_addr == logical_addr) {
	//Update log counter
	decrement_zone_valid_page_counter(map[index]->log_head->log_ptr);
	increment_zone_valid_page_counter(info->curr_log_zone);
	map[index]->log_head->log_ptr = info->curr_log_zone;
        map[index]->log_head->physical_addr = physical_addr;
	map[index]->log_head->next = NULL;
        pthread_mutex_unlock(&info->map[index]->logical_block_lock);
	return;
    }

    logpage_map *ptr = map[index]->log_head;
    while (ptr->next) {
        if (ptr->next->logical_addr == logical_addr) {
	    //Update log counter
	    decrement_zone_valid_page_counter(map[index]->log_head->log_ptr);
            increment_zone_valid_page_counter(info->curr_log_zone);
            ptr->next->log_ptr = info->curr_log_zone;
	    ptr->next->physical_addr = physical_addr;
            ptr->next->next = NULL;
	    pthread_mutex_unlock(&info->map[index]->logical_block_lock);
	    return;
        }
        ptr = ptr->next;
    }
    ptr->next = (logpage_map *)calloc(1, sizeof(logpage_map));
    increment_zone_valid_page_counter(info->curr_log_zone);
    ptr->next->log_ptr = info->curr_log_zone;
    ptr->next->logical_addr = logical_addr;
    ptr->next->physical_addr = physical_addr;
    ptr->next->next = NULL;
    pthread_mutex_unlock(&info->map[index]->logical_block_lock);
    return;
}

static int append_to_log_zone(zns_info *info, unsigned long long *physical_addr,
                              void *buffer, uint32_t size)
{
    unsigned short number_of_pages = size / info->zns_page_size - 1; //calc from size and page_size 
    //TODO: Later make provision to include meta data containing lba and write size. For persistent log storage.
    nvme_zns_append(info->fd, info->nsid, info->curr_log_zone->physical_zone_saddr, number_of_pages,
                    0, 0, 0, 0, size, buffer, 0, NULL, physical_addr);
    //ss_nvme_show_status(errno);
    return errno;
}

int init_ss_zns_device(struct zdev_init_params *params, struct user_zns_device **my_dev)
{
    //Assign the private ptr to zns_info
    *my_dev = (user_zns_device *)calloc(1, sizeof(user_zns_device));
    (*my_dev)->_private = calloc(1, sizeof(zns_info));
    zns_info *info = (zns_info *)(*my_dev)->_private;
    
    // set num_log_zones
    info->no_log_zones = params->log_zones;
    // set gc_trigger
    info->gc_trigger = params->gc_wmark;
    
    
    // set fd
    info->fd = nvme_open(params->name);
    if (info->fd < 0) {
        printf("Dev %s opened failed %d\n", params->name, info->fd);
        return errno;
    }

    // set nsid
    int ret = nvme_get_nsid(info->fd, &info->nsid);
    if (ret) {
        printf("Error: failed to retrieve the namespace id %d\n", ret);
        return ret;
    }
    // reset device
    if (params->force_reset) {
        ret = nvme_zns_mgmt_send(info->fd, info->nsid, 0, true,
                                 NVME_ZNS_ZSA_RESET, 0, NULL);
        if (ret) {
            printf("Zone reset failed %d\n", ret);
            return ret;
        }
    }

    // set zns_lba_size(or)zns_page_size : Its same for now!
    nvme_id_ns ns;
    ret = nvme_identify_ns(info->fd, info->nsid, &ns);
    if (ret) {
        printf("Failed to retrieve the nvme identify namespace %d\n", ret);
        return ret;
    }
    (*my_dev)->tparams.zns_lba_size = 1 << ns.lbaf[ns.flbas & 0xF].ds;
    (*my_dev)->lba_size_bytes = (*my_dev)->tparams.zns_lba_size;
    info->zns_page_size = (*my_dev)->tparams.zns_lba_size;

    // set zns_num_zones
    nvme_zone_report zns_report;
    ret = nvme_zns_mgmt_recv(info->fd, info->nsid, 0,
                             NVME_ZNS_ZRA_REPORT_ZONES, NVME_ZNS_ZRAS_REPORT_ALL, false,
                             sizeof(zns_report), &zns_report);
    if (ret) {
        printf("Failed to report zones, ret %d\n", ret);
        return ret;
    }
    (*my_dev)->tparams.zns_num_zones = le64_to_cpu(zns_report.nr_zones);
    info->zns_zones_count = (*my_dev)->tparams.zns_num_zones;    

    // set num_data_zones = zns_num_zones - num_log_zones
    info->data_zones_count = info->zns_zones_count - info->no_log_zones;

    // set zone_num_pages
    nvme_zns_id_ns data;
    nvme_zns_identify_ns(info->fd, info->nsid, &data);
    info->zns_pages_per_zone = data.lbafe[ns.flbas & 0xF].zsze;
    
    // set zns_zone_capacity = #page_per_zone * zone_size
    (*my_dev)->tparams.zns_zone_capacity = info->zns_pages_per_zone *
                                           (*my_dev)->tparams.zns_lba_size;

    // set user capacity bytes = #data_zones * zone_capacity
    (*my_dev)->capacity_bytes = info->data_zones_count * (*my_dev)->tparams.zns_zone_capacity;

    // set log zone page mapped hashmap size to num_data_zones
    info->map = (logical_block_map **)calloc(info->data_zones_count, sizeof(logical_block_map *));

    // set all zone index to free_zones_list
    zone_info *head = (zone_info *)calloc(1, sizeof(zone_info));
    head->physical_zone_saddr = 0;
    head->num_valid_pages = 0;
    zone_info *tmp = head;
    for (uint32_t i = 1; i < info->zns_zones_count; i++) {
	tmp->chain = (zone_info *)calloc(1, sizeof(zone_info));
	tmp->chain->physical_zone_saddr = i * info->zns_pages_per_zone;
	tmp->chain->num_valid_pages = 0;
	tmp = tmp->chain;	
    }
    info->free_zones_list = head;
    printf("Free zones count %d\n", count(info->free_zones_list));  
    //Set current log zone to 0th zone
    info->curr_log_zone = info->free_zones_list;
    info->free_zones_list = info->free_zones_list->chain;
    info->curr_log_zone->chain = NULL;
    printf("Free zones count %d\n", count(info->free_zones_list));

    for (uint32_t i = 0; i < info->data_zones_count; i++) {
        info->map[i] = (logical_block_map *)calloc(1, sizeof(logical_block_map)); 
    	info->map[i]->block_ptr = NULL;
	info->map[i]->log_head = NULL;
	info->map[i]->logical_block_saddr = i * info->zns_pages_per_zone;
    }

    //Start GC
    info->run_gc = true;
    pthread_create(&info->gc_thread_id, NULL, &gc_thread, (void *)info);
    return 0;
}

int zns_udevice_read(struct user_zns_device *my_dev, uint64_t address,
                     void *buffer, uint32_t size)
{
    unsigned long long physical_addr = 0;
    zns_info *info = (zns_info *)my_dev->_private;
    
    //FIXME: Proision for contiguos block read, but not written contiguous
    int ret = lookup_map(info, address/info->zns_page_size, &physical_addr);
    if (ret)
       return ret;
    // if (!get)
    read_from_nvme(info, physical_addr, buffer, size);
    return errno;
}

int zns_udevice_write(struct user_zns_device *my_dev, uint64_t address,
                      void *buffer, uint32_t size)
{
    unsigned long long physical_addr = 0;
    zns_info *info = (zns_info *)my_dev->_private;
    int ret = append_to_log_zone(info, &physical_addr, buffer, size);
    if (ret)
        return ret;
    //printf("Wait1\n");    
    update_map(info, address/info->zns_page_size, physical_addr);
    //printf("Wait2\n %d",info->no_of_used_log_zones);
    check_to_change_log_zone(info, physical_addr);
    //printf("Wait3\n");
    return 0;
}

int deinit_ss_zns_device(struct user_zns_device *my_dev)
{

    zns_info *info = (zns_info *)my_dev->_private;
    
    //Kill gc
    info->run_gc = false;
    pthread_join(info->gc_thread_id, NULL);

    logical_block_map **map = info->map;
    //free hashmap
    for (uint32_t i = 0; i < info->data_zones_count; i++) {
	if (map[i]==NULL)
	 continue;

	//Clear all log heads for a logical block
        logpage_map *head = map[i]->log_head;
        while (head) {
            logpage_map *tmp = head->next;
            free(head);
	    head = tmp;
        }
        
	free(map[i]->block_ptr);

	//Clear map[i]
	free(map[i]);
    }
    free(map);
    
    zone_info *head = info->used_log_zones_list;
    while(head) {
      zone_info *tmp = head->chain;
      free(head);
      head = tmp;
    }
    
    head = info->free_zones_list;
    while(head) {
      zone_info *tmp = head->chain;
      free(head);
      head = tmp;
    }
    free(info->curr_log_zone);
    free(my_dev->_private);
    free(my_dev);
    return 0;
}

}
