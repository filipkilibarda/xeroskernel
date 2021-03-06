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
#include <stdarg.h>


static int       get_free_fd(fdt_entry_t fdt[]);
static int       is_free(fdt_entry_t *fdt_entry);
// TODO: See close_fd() (commented out)
//static void      close_fd(fdt_entry_t *fdt_entry);
static int       file_is_open(pcb *process, int fd);
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
    //LOG("Opened device %d on fd %d", device_no, fd);
    return fd;
}


/**
 * Closes the device with the specified fd, if it exists. 
 * Returns 0 on success, -1 on failure.
 */
int di_close(pcb *process, int fd) {
    if (!file_is_open(process, fd)) return -1;
    
    device_t *device = process->fdt[fd].device;
    // TODO: Can simplify this a bit
    int result = device->close(fd);
    if (result == -1) return -1;
    
    // Remove entry from process FDT
    process->fdt[fd].device = NULL;

    return 0; 
}


/**
 * No return value. This function handles setting the return value of the
 * process and scheduling it.
 */
void di_read(pcb *process, int fd, char *buff, unsigned int bufflen) {
    if (!file_is_open(process, fd) || buff == NULL || bufflen <= 0) {
        process->ret_value = -1;
        enqueue_in_ready(process);
        return;
    }
    process->fdt[fd].device->read(buff, bufflen);
}


/**
 * Writes to the device specified by fd, if it is valid. 
 */
int di_write(pcb *process, int fd, char *buff, unsigned int bufflen) {
    if (!file_is_open(process, fd) || buff == NULL || bufflen <= 0)
        return -1;
    return process->fdt[fd].device->write(buff, bufflen); 
}


/**
 * Performs device specific control function
 */
int di_ioctl(pcb *process, int fd, int command, va_list ap) {
    if (!file_is_open(process, fd))
        return -1;
    return process->fdt[fd].device->ioctl(command, ap);
}


/* =========================================================================
 *                              Helpers
 * ========================================================================= */


/**
 * Close the given file descriptor table entry.
 */
 // TODO: Would be nice if all instances of closing a file descriptor went
 //  through this in case we change the fields in the a file descriptor or
 //  something.
//static void close_fd(fdt_entry_t *fdt_entry) {
//    fdt_entry->device = NULL;
//}


/**
 * Return 1 if file descriptor is valid, corresponds to entry in the process
 * fdt that is actually open (a call to sysopen returned it).
 *
 * Return 0 otherwise
 */
static int file_is_open(pcb *process, int fd) {
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
