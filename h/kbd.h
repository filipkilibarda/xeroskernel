/**
 * kbd.h: Keyboard device driver
 *
 * TODO docs
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
unsigned int convert_to_ascii(unsigned char code);
void notify_upper_half(void);
void read_char(void);

struct reader_metadata {
    pcb *process;
    char *buff;
    unsigned long bufflen;
    unsigned long num_read; 
};

typedef struct reader_metadata reader_metadata_t;

#endif
