/**
 * initialize.c - initproc
 *
 * Setup the kernel! Initialize the memory manager and context switcher, and
 * start the root process.
 **/

#include <i386.h>
#include <kbd.h>
#include <test.h>
#include <xeroskernel.h>
#include <xeroslib.h>

extern	int	entry( void );  /* start of kernel image, use &start    */
extern	int	end( void );    /* end of kernel image, use &end        */
extern  long	freemem; 	/* start of free memory (set in i386.c) */
extern char	*maxaddr;	/* max memory address (set in i386.c)	*/

device_t device_table[MAX_DEVICES]; // Initialize the device table.

static void init_device_table(void);

/************************************************************************/
/***				             NOTE:				                  ***/
/***								                                  ***/
/***   This is where the system begins after the C environment has    ***/
/***   been established.  Interrupts are initially DISABLED.  The     ***/
/***   interrupt table has been initialized with a default handler    ***/
/***								                                  ***/
/***								                                  ***/
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
    RUN_TEST(test_sleep);

    contextinit();
    init_ipc();
    init_device_table();

    create_idle_process();
    create(root, DEFAULT_STACK_SIZE);

    // Start scheduling processes!
    dispatch();
    FAIL("Should never reach this! Dispatcher should never return.");
}


/**
 * Populate the device table with our two keyboard devices.
 */
static void init_device_table(void) {
    init_quiet_keyboard(device_table, 0);
    init_echo_keyboard(device_table, 1);
}
