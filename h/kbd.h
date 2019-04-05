/**
 * kbd.h: Keyboard device driver
 */

#ifndef KBD_H
#define KBD_H

#include <xeroskernel.h>

#define KEYBOARD_CHANGE_EOF 53
#define KEYBOARD_ECHO_OFF   55
#define KEYBOARD_ECHO_ON    56

#define KEYBOARD_DATA_PORT    0x60 // Read keyboard data from this port
#define KEYBOARD_COMMAND_PORT 0x64 // Read/write keyboard command data

#define KEYBOARD_IRQ 1  // Keyboard IRQ line on the APIC

// How much data is the keyboard lower half willing to buffer?
#define KEYBOARD_BUFFLEN 4

void init_quiet_keyboard(device_t device_table[], int index);
void init_echo_keyboard(device_t device_table[], int index);
void read_from_keyboard(void);
int  blocked_on_keyboard(PID_t pid);
int  get_num_chars_read(void);
void stop_read(void);

typedef struct reader_metadata reader_metadata_t;
struct reader_metadata {
    pcb *process;
    char *buff;
    unsigned long bufflen;
    unsigned long num_read;
};

// Buffer belonging to the kernel. Data from keyboard is stuffed into here.
// If there's a pending sysread, upper half will remove data from here.
// Otherwise, data will pile up.
// Circular array
typedef struct kb_data {
    char buff[KEYBOARD_BUFFLEN]; // Buffer holding the chars
    unsigned long num_chars; // The number of chars currently in the buffer
    int start;     // The index where the data begins
} kb_data_t;


#endif
