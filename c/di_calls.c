/**
 * di_calls.c: device independent functions
 *
 * Implements various device independent kernel functions for handling system
 * calls interacting with device.
 *
 * Public functions below are all called from the dispatcher.
 */

#include <xeroskernel.h>
#include <test.h>


static int       get_free_fd(fdt_entry_t fdt[]);
static int       is_free(fdt_entry_t *fdt_entry);
static void      close_fd(fdt_entry_t *fdt_entry);
static int       is_valid_fd(pcb *process, int fd);
static device_t *get_device(int device_no);


/**
 * Return opened file descriptor on success.
 * Return -1 on failure, e.g., if device number is invalid.
 */
int di_open(pcb *process, int device_no) {

    int fd = get_free_fd(process->fdt);
    if (fd == -1)
        return -1;

    device_t *device = get_device(device_no);
    if (!device)
        return -1;

    if (!device->open(process->pid))
        return -1;

    process->fdt[fd].device = device;
    LOG("Opened device %d on fd %d", device_no, fd);
    return fd;
}


/**
 * TODO
 */
int di_close(pcb *process, int fd) {
    return 0; // TODO
}


/**
 * Return the number of bytes that were read into the buffer.
 * Return -1 if some other error occurs.
 *
 * If fewer than bufflen bytes are read, then the dispatcher should handle
 * blocking the process. Process would then be unblocked after receiving a
 * notification from the device driver when the pending read is satisfied.
 */
int di_read(pcb *process, int fd, char *buff, unsigned int bufflen) {
    if (!is_valid_fd(process, fd) || buff == NULL)
        return -1;
    return process->fdt[fd].device->read(buff, bufflen);
}


/**
 * TODO
 */
int di_write(pcb *process, int fd, char *buff, unsigned int bufflen) {
    return 0; // TODO
}


/**
 * TODO
 */
int di_ioctl(pcb *process, int fd, ...) {
    return 0; // TODO
}


/* =========================================================================
 *                              Helpers
 * ========================================================================= */


/**
 * Close the given file descriptor table entry.
 */
static void close_fd(fdt_entry_t *fdt_entry) {
    fdt_entry->device = NULL;
}


/**
 * Return 1 if file descriptor is valid, corresponds to entry in the process
 * fdt that is actually open (a call to sysopen returned it).
 *
 * Return 0 otherwise
 */
static int is_valid_fd(pcb *process, int fd) {
    if (fd < 0 || fd >= MAX_OPEN_FILES)
        return 0;
    if (is_free(&process->fdt[fd]))
        return 0;
    return 1;
}


/**
 * Return 1 if file descriptor entry is closed (free for use)
 * Return 0 otherwise
 */
static int is_free(fdt_entry_t *fdt_entry) {
    return fdt_entry->device == NULL;
}


/**
 * Return any available file descriptor from the given file descriptor
 * table.
 *
 * Return -1 if nothing is free.
 *
 * TODO: Could maintain a queue of closed fds for faster lookup.. but.. whatever
 */
static int get_free_fd(fdt_entry_t fdt[]) {
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (is_free(&fdt[i]))
            return i;
    }
    return -1;
}


/**
 * Given a device number, return the corresponding entry in the device table.
 *
 * Return NULL if invalid device number.
 */
static device_t *get_device(int device_no) {
    if (device_no < 0 || device_no >= MAX_DEVICES)
        return NULL;
    return &device_table[device_no];
}
