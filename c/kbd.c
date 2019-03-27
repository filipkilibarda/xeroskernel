/**
 * kbd.c: Keyboard device driver
 *
 * TODO docs
 */

#include <kbd.h>


// TODO: The keyboard can only be opened by one process at a time?
//       This is really important b/c the architecture changes completely
//       depending on the answer.


/**
 * Writing to keyboard is not supported so return -1.
 */
int keyboard_write() {
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
int keyboard_read(pcb *process, void *buff, int bufflen) {
    // Read from the lower half buffer to see if we have already received
    // some chars
    char c;
    int i = 0;
    while ((c = get_char()) && i < bufflen) {
        buff[i++] = c;
    }

    if (i < bufflen - 1) {
        // Weren't enough chars available so block current process
        process->state = PROC_BLOCKED;
        // TODO: Not sure what to do here.
    }

    enqueue_in_ready
}


/**
 * Interface for non-standard interactions with the keyboard device.
 */
int keyboard_ioctl(int command, ...) {
    return 0; // TODO
}
