/*
 * Author: Jonas Baude
 *
 */

#ifndef _PSIVSHMEM_H_
#define _PSIVSHMEM_H_

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <pthread.h>

#include "metadata.h" // include metadata struct && keep it synced with 

#define UIO_MAX_NAME_SIZE 65
#define UUID_STRG_LENGTH 37
#define IVSHMEM_FRAME_SIZE 4096
#define DEVICE_NAME "ivshmem"
#define DEVICE_VERSION "0.0.1"

//some bitmanipulation stuff:
#define WORD_SIZE (CHAR_BIT * sizeof(unsigned char))
#define SET_BIT(b,n) ((b)[(n)/WORD_SIZE] |= (1 << ((n) % WORD_SIZE)))
#define CLR_BIT(b,n)  ((b)[(n)/WORD_SIZE] &= ~(1 << ((n) % WORD_SIZE)))
#define CHECK_BIT(b,n) ((b)[(n)/WORD_SIZE] & (1 << ((n) % WORD_SIZE)))

//structs

typedef struct ivshmem_pci_dev_s {
	// shared - these variables are located inside the pci device
        volatile unsigned char *first_byte;	// serves as lock byte
	volatile pthread_spinlock_t *spinlock;	// protects bitmap
 	volatile uuid_t* uuid;

	// local - these variables are not shared
	int uio_index;
	char name[UIO_MAX_NAME_SIZE];
	char version[UIO_MAX_NAME_SIZE];
	char str_mem_size_hex[UIO_MAX_NAME_SIZE];
	float  mem_size_mib;
        char uuid_str[UUID_STRG_LENGTH];
	unsigned long long mem_size_byte;
	unsigned long long num_of_frames;
	unsigned long long frame_size;
	unsigned long long bitmap_length;
	unsigned long long meta_data_size; // in bytes
	// adresses
	char* ivshmem_base;
	char* bitmap;
	
} ivshmem_pci_dev_t;





//prototypes:

int psivshmem_init_uio_device(ivshmem_pci_dev_t*); // init the device 
void psivshmem_init_device_handle(ivshmem_pci_dev_t*);
int psivshmem_atomic_TestAndSet(unsigned char volatile*);
int psivshmem_find_uio_device(ivshmem_pci_dev_t*);
unsigned long long test_alloc(ivshmem_pci_dev_t*, size_t);
int free_frame(ivshmem_pci_dev_t*, char*);
void *alloc_frame(ivshmem_pci_dev_t*);
void *psivshmem_alloc_mem(ivshmem_pci_dev_t*, size_t);
int psivshmem_free_mem(ivshmem_pci_dev_t*, char*, size_t);
int unmap_device(ivshmem_pci_dev_t*);

//externs:


extern int psivshmem_debug;
extern FILE *psivshmem_debug_stream; /* Stream to use for debug output */

#endif /* _PSIVSHMEM_H_ */
