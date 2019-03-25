/** syscall.c : syscalls
 *
 * This file defines a few functions that user processes use to make
 * requests to the kernel. The functions are:
 *
 *  syscreate(func, stack_size):
 *      Create a new user process that start from the instruction pointed to
 *      by func with the given stack size.
 *  sysstop():
 *      Stops the current running process.
 *  sysyield():
 *      Yield the current running process (give up the cpu and wait to be
 *      scheduled again).
 *
 *  TODO document the rest
 **/

#include <xeroskernel.h>
#include <stdarg.h>
#include "i386.h"
#include "test.h"

extern int end;
static int return_value;
static int req_id;
// TODO: Maybe this should go in signal.c?
// Signal masks, used for updating sig_mask
const unsigned long sig_masks[5] =
{0x0000001E, 0x0000001D, 0x0000001B, 0x00000017, 0x0000000F};

/**
 * Generic system call function.
 * Not meant to be called directly by user process. 
 * Requires a call type identifier, as well as
 * any other arguments needed to service that request type.
 * 
 * Returns the result of the system call.
 * */
extern int syscall(int call, ...) {

    req_id = call;
    // Save call type into eax and
    // Execute interrupt to switch into kernel 
    __asm __volatile( " \
        movl req_id, %%eax \n\
        int $0x3c \n\
        movl %%eax, return_value \n\
            "
        :
        :
        :
        );
    
    
    return return_value;
}

/**
 * Creates a new process.
 * Requires a pointer to the routine for the process to run, 
 * as well as a size to allocate for the process stack. 
 * 
 * Returns the process ID of the created process.
 * */
extern unsigned int syscreate(void (*func)(void), int stack_size) {
    // Ensure function pointer is within legal bounds
    if ((int *) func > &end) {
        return -1;
    }
    return syscall(SYSCALL_CREATE, func, stack_size);
}

/**
 * Yields the calling process. 
 * */
extern void sysyield(void) {
    syscall(SYSCALL_YIELD, 0);
}

/**
 * Stops the calling process.
 * */
extern void sysstop(void) {
    syscall(SYSCALL_STOP, 0);
}


// Returns the PID of the current process
extern PID_t sysgetpid(void) {
    return syscall(SYSCALL_GET_PID, 0);
}

// Performs output to the screen.
// Takes a null-terminated string as input.
extern void sysputs(char *str) {
    syscall(SYSCALL_PUTS, str);
}

/**
 * Sends a signal (signalNumber) to the specified process
 *
 * Returns 0 on success, -514 is PID does not exist,
 * -583 if signal number is invalid.
 * It is OK for a process to kill itself.
 */
extern int syskill(PID_t pid, int signalNumber) {
    // TODO: These checks should be done on the kernel side.
    //  (If this were a real system)
    //  Since these functions all live in user space, a malicious
    //  could simply bypass these checks by executing an int instrcution
    //  themselves and trapping into the kernel with invalid arguments.
    pcb *process_pcb = get_pcb(pid);
    if (!process_pcb) return -514;

    // Determine if signalNumber is valid
    if (signalNumber < 0 || signalNumber > 31) return -583;

    return syscall(SYSCALL_KILL, pid, signalNumber);
}

/** Sets the priority to a value between 0 and 3, inclusive
 * Note: lower number implies higher priority
 * -1 may be passed as the priority to obtain the current process priority.
 *
 * Returns the priority prior to the call, or the current priority (if -1)
 */
extern int syssetprio(int priority) {
    return syscall(SYSCALL_SET_PRIO, priority);
}

/**
 * Attempts to send given number to the process specified by dest_pid
 *
 * Returns:
 * - If destination process terminates before matching recieve is performed, -1
 * - If the process does not exist, -2
 * - If the process tries to send a message to itself, it returns −3
 * - Returns −100 if any other problem is detected
 * - On success, 0
 **/
extern int syssend(PID_t dest_pid, unsigned long num) {
    return syscall(SYSCALL_SEND, dest_pid, num);
}


/**
 * Attempts to receive message from process given by from_pid
 *
 * Returns:
 * - If process to receive from terminates, -1
 * - If process to receive from does not exist, -2
 * - If process tries to receive from self, -3
 * - If address of num is invalid, -4
 * - If invalid from_pid address, -5
 * - If receiving process is only process in system, - 10
 * - Other issues, -100
 * - On success, 0
 **/
extern int sysrecv(PID_t *from_pid, unsigned long *num) {
    return syscall(SYSCALL_RECV, from_pid, num);
}

/**
 * Sleeps for (a minimum of) milliseconds time.
 *
 * Returns the amount of time remaining to sleep when process was restored.
 */
extern unsigned int syssleep(unsigned int milliseconds) {
    return syscall(SYSCALL_SLEEP, milliseconds);
}

/**
 * Registers the specified handler (newHandler) as the signal
 * handler for the specified signal, updating oldHandler to
 * point to the address of the previously registered handler.
 *
 * Returns one of the following:
 * - if signal number provided is invalid, -1
 * - if trying to register signal 31, -1
 * - if newHandler is located at invalid address, -2
 * - if oldHandler points to illegal memory location, -3
 * - on success, return 0
 */
int syssighandler(int signal, void (*newHandler)(void *), void (**oldHandler)(void *)) {

    // Check that signal number is valid
    if (signal < 0 || signal > 30) return -1;

    // Check that newHandler is in valid memory space
    if ((int*) newHandler < &end
    || ((int) newHandler > HOLESTART && (int) newHandler < HOLEEND)
    || (int) newHandler > END_OF_MEMORY) return -2;

    // Check that oldHandler is in valid memory space
    if ((int*) oldHandler < &end
    || ((int) oldHandler > HOLESTART && (int) oldHandler < HOLEEND)
    || (int) oldHandler > END_OF_MEMORY) return -3;

    // At this point we're good, register new handler
    PID_t current_process = sysgetpid();
    pcb *current_pcb = get_pcb(current_process);
    void (*old_func)(void *) = current_pcb->sig_handlers[signal];
    *oldHandler = old_func;
    current_pcb->sig_handlers[signal] = newHandler;

    return 0;
}

/**
 * Performs a return from the signal trampoline code
 * Will only ever be called by the signal trampoline code
 * Updates the PCB's stack pointer field, and retrieves
 * any saved return value. Updates the PCB's sig_mask
 * field to indicate that the current signal being finished
 * can be delivered again.
 */
void syssigreturn(void *old_sp) {

    PID_t current_process = sysgetpid();
    pcb *current_pcb = get_pcb(current_process);

    // TODO: Ensure this is the right approach to store/restore old ret value
    current_pcb->ret_value = current_pcb->old_ret_value;

    // Determine which signal was just sent and reset its bit in mask
    //int *signal = value on signal stack frame depending on how it's set up
    //unsigned long mask = sig_masks[*signal];
    //pcb->sig_mask = pcb->sig_mask & mask;

    // Update stack pointer
    current_pcb->stack_ptr = old_sp;

    // Call context switcher, I think?
    contextswitch(current_pcb);
}


/**
 * Causes the calling process to wait for the specified
 * process to terminate.
 *
 * Returns:
 * - if call terminates normally, 0
 * - if process specified does not exist, -1
 * - if interrupted by signal, returns value indicating so
 */
int syswait(PID_t pid) {

    // TODO: Block calling process, and return it to ready
    // queue once the process it's waiting on is dead

    // Stub
    return 0;
}


/**
 * Populate the given structure with cpu time and state information about all
 * the active processes in the system.
 */
extern int sysgetcputimes(process_statuses *proc_stats) {
    return syscall(SYSCALL_GET_CPU_TIMES, proc_stats);
}

