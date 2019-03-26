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
    return syscall(SYSCALL_SIG_HANDLER, signal, newHandler, oldHandler);
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
    syscall(SYSCALL_SIG_RETURN, old_sp);
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
    return syscall(SYSCALL_WAIT, pid);
}


/**
 * Populate the given structure with cpu time and state information about all
 * the active processes in the system.
 */
extern int sysgetcputimes(process_statuses *proc_stats) {
    return syscall(SYSCALL_GET_CPU_TIMES, proc_stats);
}

