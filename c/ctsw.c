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
#include "i386.h"
#include "test.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static void *kern_stack;
#pragma GCC diagnostic pop

void _ISREntryPoint(void);
void _TimerEntryPoint(void);
static void *ESP;
static void *eip_ptr;
static unsigned long req_id;
static unsigned long retval;
static unsigned long interrupt_type;

/**
 * Top half handles context switch into process,
 * bottom half handles context switch into kernel.
 *
 * Returns the requested service code to the dispatcher.
 */
int contextswitch(pcb *process) {

    ESP = process->stack_ptr;
    retval = process->ret_value;
    __asm __volatile( " \
        pushf \n\
        pusha \n\
        movl %%esp, kern_stack \n\
        movl ESP, %%esp \n\
        popa \n\
        movl retval, %%eax \n\
        iret \n\
    _TimerEntryPoint: \n\
        cli \n\
        movl %%esp, eip_ptr \n\
        pusha \n\
        movl $10, %%ecx \n\
        jmp _CommonEntry \n\
    _ISREntryPoint: \n\
        cli \n\
        movl %%esp, eip_ptr \n\
        pusha \n\
        movl $0, %%ecx \n\
    _CommonEntry: \n\
        movl %%ecx, interrupt_type \n\
        movl %%esp, ESP \n\
        movl %%eax, req_id \n\
        movl kern_stack, %%esp \n\
        popa \n\
        movl req_id, %%eax \n\
        popf \n\
            "
        :
        :
        : "%eax", "%ecx"
        );

        // Check if an interrupt occurred
        if (interrupt_type) {
            // Want return value to be the same as original eax
            process->ret_value = req_id;
            req_id = interrupt_type;
        }

        process->stack_ptr = ESP;
        process->eip_ptr = eip_ptr;
        return req_id;
}

// Set up IDT entry points and timer quantum
extern void contextinit() {
    set_evec(60, (unsigned long) _ISREntryPoint);
    set_evec(32, (unsigned long) _TimerEntryPoint);
    // TODO: How do we choose which index in the IDT to put the keyboard ISR?
    //  Guessing it'll be 33, but what's the reason for that?
//    set_evec(KEYBOARD_INT_NUM, (unsigned long) _KeyboardEntryPoint);
    initPIT(100);
}
