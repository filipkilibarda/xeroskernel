/** di_calls.c: device independent functions
 *
 * Implements various device independent kernel functions for handling system
 * calls interacting with device.
 *
 * TODO more docs
 */


/**
 * Guessing this will be called from dispatcher. Probably return -1 on
 * failure, e.g., if device number is invalid. TODO verify
 */
int di_open(int device_no) {
    return 0; // TODO
}


int di_generic(int fd, )


/**
 * TODO
 */
int di_close(int fd) {
    return 0; // TODO
}


/**
 * TODO
 */
int di_read(int fd) {
    return 0; // TODO
}


/**
 * TODO
 */
int di_write(int fd) {
    return 0; // TODO
}


/**
 * TODO
 */
int di_ioctl(int fd) {
    return 0; // TODO
}
