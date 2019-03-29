/**
 * kbd.c: Keyboard device driver
 *
 * The keyboard can only be opened by one process at a time and only one type
 * of keyboard can be open.
 *
 * Also, since our kernel doesn't support async reads, we can have only one
 * pending read request to the keyboard driver at a time.
 *
 * This simplifies the design a lot, because we don't have to track the state
 * of multiple read requests. Thus a lot of state can be stored in simple global
 * variables.
 */

#include <i386.h>
#include <kbd.h>
#include <test.h>


// Buffer belonging to the process that's currently executing a sysread.
// If no pending sysread, this is NULL;
static char *user_buff;
static char user_bufflen;

// Buffer belonging to the kernel. Data from keyboard is stuffed into here.
// If there's a pending sysread, upper half will remove data from here.
// Otherwise, data will pile up.
static char kernel_buff[KEYBOARD_BUFFLEN];

// Flag indicating whether the keyboard device is currently open.
// TODO: Could probably get rid of this
static int is_open;

static void init_generic_keyboard(device_t *device);
static char get_char(void);


/**
 * Enable interrupts from the keyboard.
 *
 * Return 0 if failed to open keyboard.
 * Return 1 otherwise.
 */
int keyboard_open(void) {

    if (is_open) {
        LOG("Keyboard is already open!");
        return 0;
    }

    enable_irq(KEYBOARD_IRQ, 0);
    is_open = 1;
    return 1;
}


/**
 * Disable interrupts from the keyboard.
 *
 * TODO: Fail if keyboard is already closed? (return 0)
 */
int keyboard_close(void) {
    enable_irq(KEYBOARD_IRQ, 1);
    is_open = 0;
    LOG("Keyboard closed!");
    return 1;
}


/**
 * Writing to keyboard is not supported so return -1.
 */
int keyboard_write(void *void_buff, int bufflen) {
    return -1;
}


/**
 * Read from the keyboard. This function is referenced in the keyboard device
 * structure and constitutes the upper half of the keyboard driver.
 *
 * TODO: We *might* need two upper halves for the two types of keyboard drivers.
 * TODO: I feel like the device driver doesn't need to know about processes.
 *       It should just know about buffers?
 */
int keyboard_read(void *void_buff, int bufflen) {
    // Read from the lower half buffer to see if we have already received
    // some chars
    char *buff = (char *) void_buff;
    char c;
    int i = 0;
    while ((c = get_char()) && i < bufflen) {
        buff[i++] = c;
    }

    if (i < bufflen - 1) {
        // Weren't enough chars available so return something indicating that
        // the process should be blocked.
    }
    return 0; // TODO
}


/**
 * Interface for non-standard interactions with the keyboard device.
 */
int keyboard_ioctl(int command, ...) {
    return 0; // TODO
}


/**
 * Initialize the given device structure with attributes of the quiet
 * keyboard (the keyboard that doesn't echo).
 */
void init_quiet_keyboard(device_t device_table[], int index) {
    init_generic_keyboard(&device_table[index]);
}


/**
 * Initialize the given device structure with attributes of the echo keyboard.
 */
void init_echo_keyboard(device_t device_table[], int index) {
    init_generic_keyboard(&device_table[index]);
}


/**
 * Initialize functionality that's shared between both types of keyboards.
 */
static void init_generic_keyboard(device_t *device) {
    device->open  = keyboard_open;
    device->close = keyboard_close;
    device->write = keyboard_write;
    device->read  = keyboard_read;
    device->ioctl = keyboard_ioctl;
}


/**
 * Grab a character from the lower half buffer.
 * Called from the upper half.
 */
static char get_char(void) {
    return 0; // TODO
}


/* ========================================================
 *                        Lower half
 * ======================================================== */


int data_available(void) {
    return inb(KEYBOARD_COMMAND_PORT) & 1;
}


/**
 * Read a char from the keyboard device.
 */
char read_char(void) {
    // TODO: Need to convert byte to appropriate character using translation
    //  lookup table like defined in scancodesToAscii.txt
    return inb(KEYBOARD_DATA_PORT);
}


/* ========================================================
 *                        Tests
 * ======================================================== */

/**
 * Run some tests for the keyboard.
 */
void _test_keyboard(void) {
    // TODO: Multiple attempts to open keyboard should fail
    // TODO: Attempt to open both keyboard devices should fail
    // TODO: Multiple processes opening keyboard, only one should succeed
}
