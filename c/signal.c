/* signal.c - support for signal handling
   This file is not used until Assignment 3
 */

#include <xeroskernel.h>
#include <xeroslib.h>


// Signal masks, used for updating sig_mask
// each mask is indexed to turn off a single bit 
// starting from the rightmost bit
extern unsigned long sig_masks[5] =
{0x0000001E, 0x0000001D, 0x0000001B, 0x00000017, 0x0000000F};

/**
 * Signals the specified process, either doing one of the following:
 * - If the current signal priority is higher than the priority of 
 * the signal being delivered, only update the signal mask. The signal
 * is not delivered yet. 
 * - If the current signal priority if lower than the priority of the
 * signal being delivered, add a signal context on top of the current 
 * process stack and update the signal mask.
 * - If there is a pending signal that has a higher priority than the 
 * signal currently being sent, add signal context for that signal 
 * to the stack, and update the mask with the sending signal.
 * 
 * 
 **/ 
int signal(PID_t pid, int signalNumber) {

    // Stub 
    return 0;
}

/**
 * Signal trampoline placed on process stack as EIP when 
 * signal stack is set up. Calls the specified handler 
 * and performs a sigreturn. Does not return control to 
 * function after calling sigreturn. 
 **/ 
extern void sigtramp(void (*handler)(void *), void *context) {
    // TODO: Should we call handler with the context frame?
    handler(context);
    syssigreturn(context);
}
