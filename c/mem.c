/** mem.c : memory manager
 * This file contains functions that provide ability to:
 * - initialize a memory address space
 * - dynamically allocate memory
 * - free allocated memory
 *
 * Functions used outside this file:
 * =================================
 * 	kmalloc(size):
 * 		Allocate memory of the given size. See function docstring for more
 * 		details.
 * 	kfree(pointer):
 *		Free the memory pointed to by the given pointer. See function
 *		docstring for more details.
*/

#include <xeroskernel.h>
#include <i386.h>
#include <test.h>

#define SANITY_CHECK (char*) 0x12

extern long freemem;
static mem_header *free_list;

static int is_valid_address(void *ptr);
static void *find_left_coalesce(unsigned long header_address);
static void *find_right_coalesce(unsigned long header_address);
static void insert_into_free_list(unsigned long header_address);
static void remove_from_free_list(mem_header *header);
static void reset_memory_manager(void);

int get_length(mem_header *free_list);


/**
 * Sets up the free list. 
 **/
extern void kmeminit(void) {
	reset_memory_manager();
}


/**
 * Resets the memory manager back to its initial state. 
 * Initializes the free list to contain two free chunks. 
 **/
void reset_memory_manager(void) {
	// Make sure freemem is 16 byte aligned
	freemem = 16 * (freemem/16 + freemem%16 ? 1:0);

	// Setup free chunk that comes before the HOLE
	free_list = (mem_header*) freemem;
	free_list->prev = NULL;
	free_list->next = (mem_header *) HOLEEND;
	free_list->sanity_check = (char *) SANITY_CHECK;
	// Size includes size of header
	free_list->size = HOLESTART - freemem;

	// Setup free chunk that comes after the HOLE
	free_list->next->prev = free_list;
	free_list->next->sanity_check = (char *) SANITY_CHECK;
	free_list->next->next = NULL;
	free_list->next->size = END_OF_MEMORY - HOLEEND;
}


/**
 * Allocate the requested size of memory. The size of the mem_header struct is
 * added to the requested size because the free memory list includes the
 * header size in its blocks of free memory.
 *
 * Returns a pointer to the beginning of the allocated memory block. Return
 * NULL if requested size can't fit into memory.
 */
extern void *kmalloc( size_t size ) {

    // Calculate number of 16-byte chunks needed
    size_t chunks_needed = (size/16) + ((size % 16) ? 1:0);
    size_t requested_size = chunks_needed * 16 + sizeof(mem_header);

    // Search through free list looking for a big enough chunk
    mem_header *free_header = free_list;
    while (free_header != NULL) {
        // Find a big enough node in free list
        if (free_header->size - sizeof(mem_header) >= (chunks_needed * 16)){
            break;
        }
        free_header = free_header->next;
    }

    // This means we didn't find a chunk big enough in free list
    if (free_header == NULL) {
    	return NULL;
    }

	// Add the requested memory chunk to the end of the free memory
	// chunk. Compute the starting address of the allocated header.
	mem_header *allocated_header =
			(mem_header *) ((char *) free_header + free_header->size -
							requested_size);
	allocated_header->size = requested_size;
	allocated_header->sanity_check = SANITY_CHECK;

	if (free_header == allocated_header) {
		remove_from_free_list(free_header);
	} else {
		free_header->size -= allocated_header->size;
	}

	// Return pointer to data
	return &(allocated_header->mem_start);
}


/**
* Frees the allocated chunk of memory at the given address.
* Checks address to ensure validity prior to freeing.
* When possible, attempts to coalesce chunks together. 
*   
* Upon success, returns 1. If address is not valid, returns 0. 
*/
extern int kfree( void *ptr ) {

	int valid = is_valid_address(ptr);
	if (valid == -1) return 0;

	// Calculate address of header by subtracting header size
	unsigned long header_address = (unsigned long) ptr - sizeof(mem_header);
	mem_header *to_free = (mem_header*) header_address;

	// Search for a possible member(s) of free list to coalesce with
	mem_header *left = (mem_header*) find_left_coalesce(header_address);
	mem_header *right = (mem_header*) find_right_coalesce(header_address);

	// Double coalesce
	if (right != NULL && left != NULL) {
		// Add all three sizes
		left->size = left->size + to_free->size + right->size;
		left->next = right->next;
		right->next->prev = left;
	} 
	// Left coalesce
	else if (left != NULL) {
		left->size = left->size + to_free->size;
	} 
	// Right coalesce
	else if (right != NULL) {
		to_free->prev = right->prev;
		to_free->next = right->next;
		right->next->prev = to_free;
		right->prev->next = to_free;
		to_free->size = to_free->size + right->size;
	}
	// No coalescence, just insert
	else {
		insert_into_free_list(header_address);
	}

   // Success.
   return 1;
}


/**
 * Remove a chunk of memory from the free memory list.
 */
static void remove_from_free_list(mem_header *header) {

	if (header == free_list) {
		if (header->next != NULL) {
			free_list = header->next;
			free_list->prev = NULL;
		} else {
			free_list = NULL;
		}
	} else {
		if (header->next != NULL) {
			header->next->prev = header->prev;
			header->prev->next = header->next;
		} else {
			header->prev->next = NULL;
		}
	}
}


/**
* Helper function called when reassembling free list.
* Inserts given chunk back into the free list.
*/
void insert_into_free_list(unsigned long header_address) {

	mem_header *chunk_inserting = (mem_header*) header_address;
	mem_header *prior_chunk = free_list; 
	// changed cur != NULL to cur->next != NULL
	while (prior_chunk->next != NULL) {
		if ((unsigned long) prior_chunk->next > header_address) {
			break;
		}
		prior_chunk = prior_chunk->next;
	}

	// Special case for head
	if (prior_chunk == free_list && chunk_inserting > free_list) {
		mem_header *temp = prior_chunk->next;
		prior_chunk->next = chunk_inserting;
		chunk_inserting->next = temp;
		temp->prev = chunk_inserting;
		chunk_inserting->prev = prior_chunk;
	} 
	else if (prior_chunk == free_list && chunk_inserting < free_list) {
		free_list->prev = prior_chunk;
		prior_chunk->next = free_list;
		prior_chunk->prev = NULL;
		free_list = prior_chunk;
	} 
	else {
		mem_header *temp = prior_chunk->next;
		prior_chunk->next = chunk_inserting;
		chunk_inserting->prev = prior_chunk;
		chunk_inserting->next = temp;
		if (temp != NULL) temp->prev = chunk_inserting;
	}
	
} 


// Checks for left adjacent chunks 
void* find_left_coalesce(unsigned long header_address) {

	mem_header *cur = free_list;
	while(cur != NULL) {
		// Check right coalesce
		if ((void *) cur + cur->size == (void *) header_address) {
			return cur;
		}
		cur = cur->next;
	}

	return NULL;

}


// Checks for right adjacent chunks
void* find_right_coalesce(unsigned long header_address) {

	mem_header *header_to_free = (mem_header*) header_address;

	mem_header *cur = free_list;
	while(cur != NULL) {
		// Check left coalesce
		if (((void*) header_to_free) + header_to_free->size == cur)  {
			return cur;
		}
		cur = cur->next;
	}

	return NULL;
}


/**
 * Return 1 if the address is in the hole.
 * Return 0 otherwise.
 **/
int in_hole(unsigned long address) {
	return address >= HOLESTART && address <= HOLEEND;
}


/**
 * Return 1 if the address is within valid memory addresses.
 * Return 0 otherwise.
 **/
int within_memory_bounds(unsigned long address) {
	// First, ensure ptr does not exceed memory bounds
	if (address == NULL || address < freemem || address > END_OF_MEMORY) {
		return 0;
	}
	return !in_hole(address);
}


/**
* Helper function called by kfree()
* Determines if a given address is valid. 
*
* An address is valid if it:
* - is not located in the hole/reserved memory space
* - is not already in free list
* - has a valid mem_header
* - is not out of range of memory
*
* Returns 0 if address is valid, -1 if invalid
*/
int is_valid_address(void *ptr) {
	unsigned long address = (unsigned long) ptr;

    if (!within_memory_bounds(address)) return -1;

	// Check that address is not in free list
	mem_header *to_free = (mem_header*) (ptr - sizeof(mem_header));
	mem_header *cur = free_list;
	while (cur != NULL) {
		// Already in the free list
		if (cur == to_free) {
			return -1;
		}
		cur = cur->next;
	}

	// Check for valid mem_header (SANITY_CHECK)
	// Subtract size of header to obtain mem_header
	address = address - sizeof(mem_header);
	mem_header *node_to_free = (mem_header*) address;
	if (node_to_free->sanity_check != (char*) SANITY_CHECK) {
		return -1;
	}

	return 0;
}


/**
 * Returns the length of the free list.
 **/
int get_length(mem_header *free_list) {

	int length = 0;
	mem_header *cur = free_list;
	while (cur != NULL) {
		length++;
		cur = cur->next;
	}
	return length;
}


/**
 * Return the sum total of all free memory.
 **/
unsigned long total_free_memory(void) {

	unsigned long total_free_memory = 0;
	mem_header *cur = free_list;
	while (cur != NULL) {
		total_free_memory += cur->size;
		cur = cur->next;
	}
	return total_free_memory;
}


// When testing mode is off, this function won't be used. Suppress the warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
/**
 * This test is meant to run immediately after the memory manager is
 * initialized. I.e., after the free_list has been set up.
 *
 * The state of the free list will be returned to normal when the test is
 * finished.
 */
void test_memory_manager(void) {

	size_t orig_free_size_1 = free_list->size;
	size_t orig_free_size_2 = free_list->next->size;

	// Case 0: make sure the two free chunks are 16 byte aligned
	// =========================================================
	char msg[100] = "Free chunks must be 16 byte aligned";
	ASSERT((size_t) free_list % 16 == 0, msg);
	ASSERT(free_list->size % 16 == 0, msg);
	ASSERT((size_t) free_list->next % 16 == 0, msg);
	ASSERT(free_list->next->size % 16 == 0, msg);

	size_t largest_chunk_size = free_list->size > free_list->next->size ?
								free_list->size : free_list->next->size;

	void *ptr;
	int kfree_result;
	// Case 1: malloc chunk larger than any free block.
	// ================================================
	ptr = kmalloc(largest_chunk_size + 1);
	ASSERT(ptr == NULL, "TEST 1: malloc should've failed here.");
	ASSERT(get_length(free_list) == 2, "TEST 1: Still expect two free chunks.");
	reset_memory_manager();

	// Case 2: request chunk same size as largest free chunk
	// ========================================================================
	ptr = kmalloc(largest_chunk_size);
	ASSERT(ptr == NULL, "TEST 2: fail b/c chunk size doesn't consider header");
	ASSERT(get_length(free_list) == 2, "TEST 2: Still expect two free chunks.");
	reset_memory_manager();

	// Case 3: request chunk 16 bytes less than largest free chunk
	// ===========================================================
	ASSERT(free_list->size == orig_free_size_1, "sanity check");
	ASSERT(free_list->next->size == orig_free_size_2, "sanity check");

	ptr = kmalloc(largest_chunk_size - sizeof(mem_header));
	ASSERT(ptr != NULL, "TEST 3: Succeed b/c fits exactly into largest free chunk");
	ASSERT(get_length(free_list) == 1, "TEST 3: Free list should've lost 1 chunk.");
	ASSERT(free_list->size == orig_free_size_1,
		   "Second free chunk removed, size should same as first free chunk");
	kfree_result = kfree(ptr);
	ASSERT(get_length(free_list) == 2, "length should be 2 again");
	ASSERT(free_list->size == orig_free_size_1,
		   "first free list chunk should be back to normal");
	ASSERT(free_list->next->size == orig_free_size_2,
		   "second free list chunk should be back to normal");


	// NEW TEST CASES - added by Will
	// Case 4: malloc a 'regular sized' chunk.
	/*
	* Ensure that:
	* - new block in free list is correct size
	* - entire free list can still be traversed (forwards and backwards)
	* - values in mem_header of new chunk are set correctly (size, SANITY_CHECK)
	*/
	// ========================================================================
	reset_memory_manager();
	size_t chunk = 10;
	ptr = kmalloc(chunk);
	mem_header *chunk_header = (mem_header*) (ptr - sizeof(mem_header));
	// Check size
	ASSERT(chunk_header->size == 16 + sizeof(mem_header),
		   "TEST 4: Size set incorrectly");
	// Check sanity_check is set correctly
	ASSERT(chunk_header->sanity_check == SANITY_CHECK,
		   "TEST 4: Sanity check wrong");
	ASSERT(get_length(free_list) == 2, "TEST 4: Wrong number of chunks");
	mem_header *cur = free_list;
	int list_count = 0;

	// Traverse forwards
	while(cur->next != NULL) {
		cur = cur->next;
		list_count++;
	}

	// Traverse backwards
	while(cur->prev != NULL) {
		cur = cur->prev;
		list_count++;
	}

	ASSERT(list_count == 2, "TEST 4: Links aren't set correctly");

	// Case 5: allocate a chunk, and then free it.
	// Make sure that headers coalesce (count number of items in free list)
	// Check size of coalesced mem_header (ensure struct members correct)
	// ========================================================================
	reset_memory_manager();
	ptr = kmalloc(10);
	ASSERT(get_length(free_list) == 2, "Free list length incorrect.");
	mem_header *allocated_header = (mem_header*) (ptr - sizeof(mem_header));
	ASSERT(allocated_header->size == 32, "Size not set correctly.");
	kfree_result = kfree(ptr);
	ASSERT(kfree_result == 1, "TEST 5: kfree unsuccessful.");
	// Ensure chunks coalesce
	ASSERT(get_length(free_list) == 2, "TEST 5: Chunks did not coalesce!");
	// Make sure struct members are set correctly
	ASSERT(free_list->size == HOLESTART - freemem,
		   "TEST 5: Size not set correctly.");
	ASSERT(free_list->sanity_check == SANITY_CHECK,
		   "TEST 5: Sanity check wrong");
	ASSERT(free_list->prev == NULL, "TEST 5: List integrity compromised");
	ASSERT(free_list->next != NULL, "TEST 5: List integrity compromised");

	// Case 6: Make sure that address handed back by kmalloc is correct.
	// ========================================================================
	reset_memory_manager();
	ptr = kmalloc(chunk);
	ASSERT((int) ptr == HOLESTART - 16,
		   "TEST 6: Address handed back incorrect.");

	// Case 7: Allocate a single byte. Make sure 16 bytes get allocated.
	// ========================================================================
	reset_memory_manager();
	size_t one_byte = 1;
	ptr = kmalloc(one_byte);
	chunk_header = ptr - sizeof(mem_header);
	ASSERT(chunk_header->size == 16 + sizeof(mem_header),
		   "TEST 8: Allocation must be 16-byte aligned!");

	// Case 8: Allocate-allocate-allocate-free (check size of free list)
	// ========================================================================
	reset_memory_manager();
	void *ptr1 = kmalloc(10);
	void *ptr2 = kmalloc(10);
	void *ptr3 = kmalloc(10);
	ASSERT(get_length(free_list) == 2, "1 - Free list length incorrect\n");
	kfree_result = kfree(ptr2);
	ASSERT(get_length(free_list) == 3, "2 - Free list length incorrect\n");
	ptr2 = kmalloc(10);
	ASSERT(get_length(free_list) == 3, "3 - Free list length incorrect\n");


	// Case 9: Allocate a bunch of contiguous chunks
	// ========================================================================
	reset_memory_manager();
	size_t chunk_size = 18;
	void *c1 = kmalloc(chunk_size);
	void *c2 = kmalloc(chunk_size);
	void *c3 = kmalloc(chunk_size);
	void *c4 = kmalloc(chunk_size);
	mem_header *c1_header = (mem_header*) (c1 - sizeof(mem_header));
	mem_header *c2_header = (mem_header*) (c2 - sizeof(mem_header));
	mem_header *c3_header = (mem_header*) (c3 - sizeof(mem_header));
	mem_header *c4_header = (mem_header*) (c4 - sizeof(mem_header));
	ASSERT(c1_header->size == 32 + sizeof(mem_header), "Incorrect Size 1");
	ASSERT(c2_header->size == 32 + sizeof(mem_header), "Incorrect Size 2");
	ASSERT(c3_header->size == 32 + sizeof(mem_header), "Incorrect Size 3");
	ASSERT(c4_header->size == 32 + sizeof(mem_header), "Incorrect Size 4");

	// First, ensure all chunks have correct size, including free_list
	// Each kmalloc should be 32 + sizeof(mem_header) in size
	ASSERT(free_list->size == (orig_free_size_1 - (4* (32 + sizeof(mem_header)))),
		   "Size is set incorrectly");


	// Case 10: Try allocating to illegal address spaces
	// ========================================================================
	reset_memory_manager();
	ptr = kmalloc(orig_free_size_2 + 20);
	ASSERT(ptr == NULL, "Shouldn't have malloc'd successfully!");


	// ========================================================================
	// ===========================kfree tests==================================

	// kfree test variables:
	long negative = -100;
	unsigned long out_of_range = 0x500000;
	unsigned long in_hole = 0xA0010;
	unsigned long free_mem_region = HOLEEND + 50;

	// Case 0: Attempt to free invalid addresses (out of range, in HOLE)
	// ========================================================================
	reset_memory_manager();
	ptr = (void*) negative;
	kfree_result = kfree(ptr);
	ASSERT(kfree_result == 0,
		   "KFREE TEST 0: Cannot free a negative address.");
	ptr = (void*) out_of_range;
	kfree_result = kfree(ptr);
	ASSERT(kfree_result == 0,
		   "KFREE TEST 0: Cannot free address out of range.");
	ptr = (void*) in_hole;
	kfree_result = kfree(ptr);
	ASSERT(kfree_result == 0,
		   "KFREE TEST 0: Cannot free an address in HOLE.");


	// Case 1: Free a 'free memory region' address with no mem_header
	// ========================================================================
	reset_memory_manager();
	ptr = (void*) free_mem_region;
	kfree_result = kfree(ptr);
	ASSERT(kfree_result == 0,
		   "KFREE TEST 1: Freed address without a mem_header.");


	// Case 2: Double coalesce
	// ========================================================================
	reset_memory_manager();
	ptr1 = kmalloc(40);
	ptr2 = kmalloc(50);
	ptr3 = kmalloc(60);
	void *ptr4 = kmalloc(30);
	kfree_result = kfree(ptr1);
	ASSERT(get_length(free_list) == 3, "Length of list wrong.");
	kfree_result = kfree(ptr3);
	ASSERT(get_length(free_list) == 4, "Wrong length.");
	kfree_result = kfree(ptr2);
	ASSERT(get_length(free_list) == 3, "Did not double coalesce!");
	ASSERT(ptr4 != NULL, "ptr4 should've allocated successfully");


	// Case 3: Left Coalesce
	// ========================================================================
	reset_memory_manager();
	ptr1 = kmalloc(40);
	ptr2 = kmalloc(50);
	ptr3 = kmalloc(60);
	kfree_result = kfree(ptr3);
	ASSERT(get_length(free_list) == 2, "Left coalesce unsuccessful.");


	// Case 4: Right coalesce
	// ========================================================================
	reset_memory_manager();
	ptr1 = kmalloc(40);
	ptr2 = kmalloc(50);
	ptr3 = kmalloc(60);
	kfree_result = kfree(ptr1);
	ASSERT(get_length(free_list) == 3, "Length of list wrong.");
	kfree_result = kfree(ptr2);
	ASSERT(get_length(free_list) == 3, "Right coalesce unsuccessful.");

}
#pragma GCC diagnostic pop
