/* signal.c - support for signal handling
   This file is not used until Assignment 3
 */

#include <xeroskernel.h>
#include <xeroslib.h>

#pragma GCC diagnostic push 
#pragma GCC diagnostic ignored "-Wunused-variable"
static unsigned long EFLAGS = 0x00003200;
static unsigned long GP_REGISTER = 0x00000000;
static unsigned long OLD_RV;
static void *EIP = &sigtramp;
static void *kern_stack;
static void *proc_stack;
static unsigned long CS;
static int signal_code;
#pragma GCC diagnostic pop

int get_highest_signal_number(unsigned long sig_mask);
void init_signal_context(pcb *process_to_signal);

// Signal masks, used for updating sig_mask
// each mask is indexed to turn on/off a single bit 
// starting from the rightmost bit (signal 0) to 
// leftmost bit (signal 31)
unsigned long sig_masks[32] =
{0x00000001, 0x00000002, 0x00000004, 0x00000008, 
0x00000010, 0x00000020, 0x00000040, 0x00000080, 
0x00000100, 0x00000200, 0x00000400, 0x00000800, 
0x00001000, 0x00002000, 0x00004000, 0x00008000, 
0x00010000, 0x00020000, 0x00040000, 0x00080000, 
0x00100000, 0x00200000, 0x00400000, 0x00800000, 
0x01000000, 0x02000000, 0x04000000, 0x08000000, 
0x10000000, 0x20000000, 0x40000000, 0x80000000};


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

    pcb *process_to_signal = get_pcb(pid);
    
    // Check if there's already a signal pending
    int pending_signal = 
    get_highest_signal_number(process_to_signal->sig_mask);

    // Update signal mask (should be done no matter what) 
    process_to_signal->sig_mask = 
    process_to_signal->sig_mask ^ sig_masks[signalNumber];

    proc_stack = process_to_signal->stack_ptr;
    CS = getCS();
    OLD_RV = process_to_signal->ret_value;

    // If there's a pending signal with higher priority,
    // set up its signal context.
    if (pending_signal > signalNumber) {
        signal_code = pending_signal;
        init_signal_context(process_to_signal);
    }

    // Otherwise, check current signal priority to 
    // determine whether to send the signal 
    else if (process_to_signal->sig_prio < signalNumber) {
        signal_code = signalNumber;
        init_signal_context(process_to_signal);
    }

    // Stub (TODO: Is there something meaningful that this should return?)
    return 0;
}

/**
 * Signal trampoline placed on process stack as EIP when 
 * signal stack is set up. Calls the specified handler 
 * and performs a sigreturn. Does not return control to 
 * function after calling sigreturn. 
 **/ 
extern void sigtramp(void (*handler)(void *), void *context) {
    handler(context);
    // Rewind stack to point to old context, and 
    // restore previous return value.
    syssigreturn(context);
}


/**
 * Initializes signal context on process stack
 */
void init_signal_context(pcb *process_to_signal) {
    process_to_signal->sig_prio = signal_code;
        // Put old return value on signal context
        __asm __volatile( " \
            movl %%esp, kern_stack \n\
            movl proc_stack, %%esp \n\
            push EFLAGS \n\
            push CS \n\
            push EIP \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
            push signal_code \n\
            push proc_stack \n\
            push OLD_RV \n\
            movl %%esp, proc_stack \n\
            movl kern_stack, %%esp \n\
        "
        :
        :
        :
        );

        process_to_signal->stack_ptr = proc_stack;
}

/**
 * Returns the highest signal number that exists in the mask.
 * If there is no signal pending in mask, returns -1.
 */
int get_highest_signal_number(unsigned long sig_mask) {
    int highest_so_far = 0;
    for (int i = 0; i < 32; i ++) {
        int mask = sig_mask;
        mask = mask & sig_masks[i];
        if (mask > highest_so_far) {
            highest_so_far = mask;
        }    
    }

    // because I made the mask values go from 1 - 32, 
    // subtract 1 to get the actual signal number
    return highest_so_far - 1;
}
