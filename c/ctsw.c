/** ctsw.c : context switcher
 *
 * Handles switching between kernel and user mode through the use of interrupts.
 *
 *  contextswitch(process):
 *      Given a pointer to a process pcb, this function will save the
 *      kernel's state on the kernel stack, load the process's state from its
 *      stack, then change the instruction pointer to where the process left
 *      off.
 *  contextinit():
 *      Called from initproc() in init.c. Sets up the IDT so that system
 *      calls from user space get redirected to the context switcher routine
 *      that was mentioned above.
 **/

#include <xeroskernel.h>
#include <i386.h>
#include <test.h>
#include <kbd.h>

// A magic number that we initialize the process's return value to at the
// start of every system call. This is useful for testing to ensure we're
// updating the return value appropriately.
#define EMPTY_RETURN_VALUE -1337


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static void *kern_stack;
#pragma GCC diagnostic pop

void _syscall_entry(void);
void _timer_entry(void);
void _keyboard_entry(void);
static void *ESP;
static void *eip_ptr;
static unsigned long req_id;
static unsigned long retval;
static unsigned long hardware_interrupt_num;


/**
 * Top half handles context switch into process,
 * bottom half handles context switch into kernel.
 *
 * Returns the requested service code to the dispatcher.
 */
int contextswitch(pcb *process) {

    // TODO: Reset any pending signal mask bit
    ESP = process->stack_ptr;
    retval = process->ret_value;
    __asm __volatile(
            "pushf;"                  // Save kernel context
            "pusha;"
            "movl %%esp, kern_stack;"
            "movl ESP, %%esp;"        // Load process context
            "popa;"
            "movl retval, %%eax;"
            "iret;"                   // Jump into process

        "_keyboard_entry:"            // Keyboard interrupt entry
            "cli;"
            "movl %%esp, eip_ptr;"
            "pusha;"
            "movl %[keyboard], %%ecx;"
            "jmp _common_entry;"

        "_timer_entry:"               // Timer interrupt entry
            "cli;"
            "movl %%esp, eip_ptr;"
            "pusha;"
            "movl %[timer], %%ecx;"
            "jmp _common_entry;"

        "_syscall_entry:"             // All system calls enter here
            "cli;"
            "movl %%esp, eip_ptr;"
            "pusha;"
            "movl $0, %%ecx;"

        "_common_entry:"
            "movl %%ecx, hardware_interrupt_num;"
            "movl %%esp, ESP;"
            "movl %%eax, req_id;"
            "movl kern_stack, %%esp;"
            "popa;"
            "movl req_id, %%eax;"
            "popf;"
        :
        : [keyboard] "i" (KEYBOARD_INT), [timer] "i" (TIMER_INT)
        : "%eax", "%ecx");

    // Check if an interrupt occurred
    if (hardware_interrupt_num) {
        // Want return value to be the same as original eax
        // TODO: Maybe we should call req_id "old_eax" or something b/c we're
        //  effectively saving the eax value of the process
        process->ret_value = req_id;
        req_id = hardware_interrupt_num;
    } else {
        // See docs for EMPTY_RETURN_VALUE above
        process->ret_value = EMPTY_RETURN_VALUE;
    }

    process->stack_ptr = ESP;
    process->eip_ptr = eip_ptr;
    return req_id;
}

/**
 * Set up IDT entry points and timer quantum
 */
void contextinit() {
    set_evec(SYSCALL_IDT_INDEX,  (unsigned long) _syscall_entry);
    set_evec(TIMER_IDT_INDEX,    (unsigned long) _timer_entry);
    set_evec(KEYBOARD_IDT_INDEX, (unsigned long) _keyboard_entry);
    // TODO: This is right. This is saying timer interrupt every 1/100 of
    //  second
    initPIT(100);
}
