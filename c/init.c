/**
 * initialize.c - initproc
 *
 * Setup the kernel! Initialize the memory manager and context switcher, and
 * start the root process.
 **/

#include <i386.h>
#include <xeroskernel.h>
#include <xeroslib.h>
#include <test.h>

extern	int	entry( void );  /* start of kernel image, use &start    */
extern	int	end( void );    /* end of kernel image, use &end        */
extern  long	freemem; 	/* start of free memory (set in i386.c) */
extern char	*maxaddr;	/* max memory address (set in i386.c)	*/

device_t device_table[MAX_DEVICES]; // Initialize the device table.

/************************************************************************/
/***				NOTE:				      ***/
/***								      ***/
/***   This is where the system begins after the C environment has    ***/
/***   been established.  Interrupts are initially DISABLED.  The     ***/
/***   interrupt table has been initialized with a default handler    ***/
/***								      ***/
/***								      ***/
/************************************************************************/

/*------------------------------------------------------------------------
 *  The init process, this is where it all begins...
 *------------------------------------------------------------------------
 */
void initproc(void) {

    kprintf("\n\nCPSC 415, 2018W2 \n32 Bit Xeros -21.0.0 - "
            "even before beta \nLocated at: %x to %x\n",
             &entry, &end);

    // Initialize memory layout
    kmeminit();
    RUN_TEST(test_memory_manager);

    // Initialize PCB array
    pcb_init();
    RUN_TEST(test_dispatcher);

    // Test sleep functionality
    //test_sleep();
    // Test time slicing functionality
    //test_time_slice();

    // Set entry point for ISR
    contextinit();
    kprintf("context inited\n");

    init_ipc();

    create_idle_process();
    // Test IPC functionality
    create(test_ipc, DEFAULT_STACK_SIZE);
//    kprintf("\n");
//    kprintf("==========================\n");
//    kprintf("Extended producer-consumer\n");
//    kprintf("==========================\n");
//    create(root, DEFAULT_STACK_SIZE);

    // Call dispatcher to start running
    dispatch();

    kprintf("\n\nWhen your  kernel is working properly ");
    kprintf("this line should never be printed!\n");
    for(;;); /* loop forever */
}
