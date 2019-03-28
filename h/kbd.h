/**
 * kbd.h: Keyboard device driver
 *
 * TODO docs
 */

#ifndef KBD_H
#define KBD_H

#define KEYBOARD_CHANGE_EOF 53
#define KEYBOARD_ECHO_OFF   55
#define KEYBOARD_ECHO_ON    56

#define KEYBOARD_DATA_PORT    0x60 // Read keyboard data from this port
#define KEYBOARD_COMMAND_PORT 0x64 // Read/write keyboard command data

#define KEYBOARD_IRQ 1  // Keyboard IRQ line on the APIC

#endif
