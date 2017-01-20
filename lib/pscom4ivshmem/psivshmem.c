/*
 * Author: Jonas Baude
 */


#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/resource.h> // getrlimit
#include "pscom_priv.h"
#include "pscom_util.h"
#include "perf.h"
#include "psivshmem.h"
#include <semaphore.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>


int psivshmem_debug = 2;
FILE *psivshmem_debug_stream = NULL;

#define psivshmem_dprint(level,fmt,arg... )                                 	\
    do {                                                                	\
        if ((level) <= psivshmem_debug) {                                   	\
            fprintf(psivshmem_debug_stream ? psivshmem_debug_stream : stderr,   \
                    "ivshmem:" fmt "\n",##arg);                              	\
        }                                                               	\
    } while(0);



static
int psreadline_from_file(char *fname, char *lbuf) //(filename, linebufer) 
{
	char *s;
	int i;
	memset(lbuf, 0, UIO_MAX_NAME_SIZE);
	FILE* file = fopen(fname,"r");
	if (!file) return -1;
	s = fgets(lbuf,UIO_MAX_NAME_SIZE,file);
	if (!s) return -2;
	for (i=0; (*s)&&(i<UIO_MAX_NAME_SIZE); i++) {
		if (*s == '\n') *s = 0;
		s++;
	}
	return 0;
}


int psivshmem_init_uio_device(ivshmem_pci_dev_t *dev) // init the device 
{   

    int n;
    struct dirent **namelist;
    int dev_fd;
    FILE* fd;
    char file_path[UIO_MAX_NAME_SIZE];

    n = scandir("/sys/class/uio", &namelist, 0, alphasort);
    if (n<0) goto no_device;

    while(n--) {
	
	sprintf(file_path, "/sys/class/uio/%s/name", namelist[n]->d_name);

    	psreadline_from_file(file_path,dev->name);	// check name
	if (strncmp(dev->name, DEVICE_NAME,7))  
	{	
		free(namelist[n]);
		continue; // wrong device name -> try next
	}
    
	//if name suits try to open char_dev file and read dev_specs:

	sprintf(file_path, "/dev/%s", namelist[n]->d_name);
     	
	dev_fd = open(file_path, O_RDWR);
	if (dev_fd == -1) goto device_error;

   	sprintf(file_path, "/sys/class/uio/%s/maps/map1/size", namelist[n]->d_name);
    	psreadline_from_file(file_path, dev->str_mem_size_hex);
   	dev->mem_size_byte = strtol(dev->str_mem_size_hex, NULL, 0);
	DPRINT(3, "Mapped Memory Size: %lu",dev->mem_size_byte);
	dev->mem_size_mib = dev->mem_size_byte / (float)1024 / (float)1024; // Byte -> KiB -> MiB

    	sprintf(file_path, "/sys/class/uio/%s/version", namelist[n]->d_name);
	psreadline_from_file(file_path, dev->version);
	if (strncmp(dev->version, DEVICE_VERSION,5)) goto version_mismatch;
        void *map_addr = mmap(NULL,dev->mem_size_byte, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd,1 * getpagesize());  // last param. overloaded for ivshmem -> 2 memorysegments available; Reg.= 0;  Data = 1;
	
	dev->ivshmem_base = (char*) map_addr; 
 	
	psivshmem_init_device_handle(dev);	
	
     	close(dev_fd); //keep dev_fd alive? --> no, mmap() saves required data internally, c.f.man pages
	free(namelist);
	return 0;

    }

not_initialised:
    DPRINT(1,"Unable to initialize metadata!\n");
    return -1;
no_device:
    DPRINT(1,"No suitable pci dev found!\n");
    return -1;
device_error:
    DPRINT(1,"Device errror!\n");
    return -1;
version_mismatch:
    DPRINT(1,"Version mismatch! Current device version: %s - expected version: %s\n",dev->version, DEVICE_VERSION);
    sleep(1);
    return -1;

}

 
void psivshmem_init_device_handle(ivshmem_pci_dev_t *dev){
/*
 * This function initiates all required parameters to handle the shared memory access.
 * The first byte of the shared memory is used as a simple mutex to let the verry first
 * process initialize a pthread spinlock which is inter-vm thread safe.
 */
    dev->first_byte = dev->ivshmem_base;
    dev->spinlock = dev->ivshmem_base + sizeof(char);
    dev->uuid = dev->ivshmem_base + sizeof(char) + sizeof(pthread_spinlock_t);
    dev->bitmap = dev->ivshmem_base + sizeof(char) + sizeof(pthread_spinlock_t) + sizeof(uuid_t);
    dev->frame_size = IVSHMEM_FRAME_SIZE;
    dev->num_of_frames = dev->mem_size_byte / IVSHMEM_FRAME_SIZE;
    dev->bitmap_length = dev->num_of_frames / (sizeof(char)*CHAR_BIT);
    dev->meta_data_size = (dev->bitmap - dev->ivshmem_base) + dev->bitmap_length * sizeof (char);
    long long n;

    // Assumption: unused device contains only zeros
    if (uuid_is_null(*(dev->uuid)) && psivshmem_atomic_TestAndSet(dev->first_byte)){
    	pthread_spin_init(dev->spinlock, PTHREAD_PROCESS_SHARED);
        uuid_generate(*(dev->uuid));
	for(n =0; n< dev->bitmap_length; n++) SET_BIT(dev->bitmap,n); //mark used frames
    } 
    uuid_unparse_lower(dev->uuid, dev->uuid_str);
}


int psivshmem_atomic_TestAndSet(unsigned char volatile* lock_byte){
/*
 *  This function provides atomic test-and-set 
 */
        return  __sync_bool_compare_and_swap(lock_byte,0,1);
}


unsigned long test_alloc(ivshmem_pci_dev_t *dev, size_t size){
/*
 * first implementation: First Fit
 *
 * param: size = # of needed _frames_
 *
 * returns index of first free frame 
 * returns -1 if memory is filled
 *
 * */	
    long n;
    unsigned long cnt = 0;

    for(n=0; n< dev->num_of_frames; n++)
    {
	if (!CHECK_BIT(dev->bitmap,n))
	{
	    cnt++;
	} else
	{
	    cnt = 0;
	}
		
	// return index of first free frame belonging to a block of at least N free frames! 
	if (cnt >= size) {
	return (n - cnt + 1); // return index of first free frame belonging to a block of at least N free frames! 
	}
    }
    return -1; //not enough memory
}

int psivhmem_free_frame(ivshmem_pci_dev_t *dev, char * frame_ptr)
{
/*
 * first implementation: just clear corresponding bit in bitmap -> frame is available again
 *
 */
    long n; 
    long index;

    index = (frame_ptr - dev->ivshmem_base) / dev->frame_size;
 
    pthread_spin_lock(dev->spinlock);
 
	CLR_BIT(dev->bitmap,index);

    pthread_spin_unlock(dev->spinlock);
   
    return 0;

}


int psivshmem_free_mem(ivshmem_pci_dev_t *dev, char * frame_ptr, size_t size)
{
/*
 * first implementation: just clear corresponding bit in bitmap -> frame is available
 *
 * "a = b/c"  int division round up
 * int a = (b + (c - 1)) / c  <- rounds up for positiv int, e.g. frameIndices
 *
 *
 */
    long n; 
    long index_low, index_high;

    index_low = (frame_ptr - dev->ivshmem_base) / dev->frame_size; //has to be a multiple of it!
    index_high = (frame_ptr - dev->ivshmem_base + size + (dev->frame_size - 1)) / dev->frame_size;
 
    pthread_spin_lock(dev->spinlock);

        for(n = index_low; n<=index_high;n++) {  //'unlock' all N used frames 	   
	    CLR_BIT(dev->bitmap, n);
	}
   
    pthread_spin_unlock(dev->spinlock);

return 0;

}


void *psivshmem_alloc_mem(ivshmem_pci_dev_t *dev, size_t sizeByte)
{
   long n;
   long index;
   long frame_qnt = 0;
   void *ptr = NULL;

    frame_qnt = (sizeByte + (dev->frame_size - 1)) / dev->frame_size;

    pthread_spin_lock(dev->spinlock);
    
    	index = test_alloc(dev ,frame_qnt);

	DPRINT(5,"psivshmem_alloc_memory: index= %ld\n",index);

	if(index == -1) return ptr;  // error! not enough memory


    	for (n = index; n<index + frame_qnt; n++)
    	{
		SET_BIT(dev->bitmap,n);  //ToDo: maybe possible: macro to set more bits "at once"
		DPRINT(5,"psivshmem_alloc_memory:  <SET_BIT no %ld>\n",n);
	}
    
    pthread_spin_unlock(dev->spinlock);
   
    ptr = (void*)(dev->ivshmem_base + (long long)(index * dev->frame_size));

    return ptr;
}

int psivshmem_unmap_device(ivshmem_pci_dev_t *dev)
{

/*
 * ToDO: implement functionallity to unmap the device memory from process user space!
 *
 */

    return -1;
}

