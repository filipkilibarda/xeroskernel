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
int syscall(int call, ...) {

    req_id = call;
    // Save call type into eax and
    // Execute interrupt to switch into kernel
    __asm __volatile(
        "movl req_id, %%eax;"        // Specify which syscall
        "int %0;"                    // Trap into kernel
        "movl %%eax, return_value;"  // Copy syscall ret val into global var
        :: "i" (SYSCALL_IDT_INDEX));

    return return_value;
}

/**
 * Creates a new process.
 * Requires a pointer to the routine for the process to run, 
 * as well as a size to allocate for the process stack. 
 * 
 * Returns the process ID of the created process.
 * */
unsigned int syscreate(void (*func)(void), int stack_size) {
    return syscall(SYSCALL_CREATE, func, stack_size);
}

/**
 * Yields the calling process. 
 * */
void sysyield(void) {
    syscall(SYSCALL_YIELD, 0);
}

/**
 * Stops the calling process.
 * */
void sysstop(void) {
    syscall(SYSCALL_STOP, 0);
}


// Returns the PID of the current process
PID_t sysgetpid(void) {
    return syscall(SYSCALL_GET_PID, 0);
}

// Performs output to the screen.
// Takes a null-terminated string as input.
void sysputs(char *str) {
    syscall(SYSCALL_PUTS, str);
}


/**
 * Sends a signal (signal_num) to the specified process
 *
 * Returns 0 on success, -514 is PID does not exist,
 * -583 if signal number is invalid.
 * It is OK for a process to kill itself.
 */
int syskill(PID_t pid, int signal_num) {
    return syscall(SYSCALL_KILL, pid, signal_num);
}


/** Sets the priority to a value between 0 and 3, inclusive
 * Note: lower number implies higher priority
 * -1 may be passed as the priority to obtain the current process priority.
 *
 * Returns the priority prior to the call, or the current priority (if -1)
 */
int syssetprio(int priority) {
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
int syssend(PID_t dest_pid, unsigned long num) {
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
int sysrecv(PID_t *from_pid, unsigned long *num) {
    return syscall(SYSCALL_RECV, from_pid, num);
}

/**
 * Sleeps for (a minimum of) milliseconds time.
 *
 * Returns the amount of time remaining to sleep when process was restored.
 */
unsigned int syssleep(unsigned int milliseconds) {
    return syscall(SYSCALL_SLEEP, milliseconds);
}

/**
 * Registers the specified handler (new_handler) as the signal
 * handler for the specified signal, updating old_handler to
 * point to the address of the previously registered handler.
 *
 * Returns one of the following:
 * - if signal number provided is invalid, -1
 * - if trying to register signal 31, -1
 * - if new_handler is located at invalid address, -2
 * - if old_handler points to illegal memory location, -3
 * - on success, return 0
 */
int syssighandler(int signal, void (*new_handler)(void *), void (**old_handler)(void *)) {
    return syscall(SYSCALL_SIG_HANDLER, signal, new_handler, old_handler);
}

/**
 * Performs a return from the signal trampoline code
 * Will only ever be called by the signal trampoline code
 * Updates the PCB's stack pointer field, and retrieves
 * any saved return value. Updates the PCB's pending_sig_mask
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
int sysgetcputimes(process_statuses *proc_stats) {
    return syscall(SYSCALL_GET_CPU_TIMES, proc_stats);
}


/**
 * Open a device. Return the file descriptor on success.
 * 
 * Returns:
 * - on failure, -1
 * - file descriptor in range 0-3 (inclusive) on success
 */
int sysopen(int device_no) {
    return syscall(SYSCALL_OPEN, device_no);
}


/**
 * Close a device.
 * 
 * Returns:
 * - on success, 0
 * - on failure, -1
 */
int sysclose(int fd) {
    return syscall(SYSCALL_CLOSE, fd);
}


/**
 * Write to a device.
 * 
 * Returns: 
 * - on success, # of bytes written
 * - on failure, -1 
 */
int syswrite(int fd, void *buff, unsigned int bufflen) {
    return syscall(SYSCALL_WRITE, fd, buff, bufflen);
}


/**
 * Read from a device.
 * 
 * Returns:
 * - 0 to indicate an EOF
 * - on error, -1
 * - otherwise, # of bytes read
 */
int sysread(int fd, void *buff, unsigned int bufflen) {
    return syscall(SYSCALL_READ, fd, buff, bufflen);
}


/**
 * Read from a device.
 * 
 * Returns: 
 * - on success, 0
 * - on error, -1
 */
int sysioctl(int fd, unsigned long command, ...) {
    va_list ap; 
    va_start(ap, command);
    int result = syscall(SYSCALL_IOCTL, fd, command, ap);
    va_end(ap);
    return result;
}


/* ==========================================================================
 *           Kernel side implementations of some system calls
 * ========================================================================== */

/**
 * Implementation of syswait.
 *
 * Blocks the given process until the process with given PID dies.
 *
 * Otherwise, enqueues the given process back into the ready queue.
 */
void wait(pcb *process, PID_t pid) {
    // The process we're waiting on
    pcb *other_process = get_active_pcb(pid);

    if (!other_process) {
        process->ret_value = -1;
        enqueue_in_ready(process);

    } else if (process->pid == pid) {
        // This is how they do it in Linux so we're gonna too
        LOG("Waiting on self is not allowed");
        process->ret_value = -1;
        enqueue_in_ready(process);

    } else {
        LOG("Blocking %d waiting on %d", process->pid, pid);
        // Block process
        process->state = PROC_BLOCKED;
        process->ret_value = 0;
        process->waiting_for_pid = pid;
        // Add to queue of waiters
        enqueue_in_waiters(process, other_process);
    }
}


/**
 * Kernel side implementation of the syssetprio system call.
 *
 * Should be called from the dispatcher.
 *
 * Return value corresponds exactly to what should be returned to the calling
 * process.
 */
int setprio(pcb *process, int priority) {
    // Check for valid priority
    // TODO: Is this check duplicated anywhere else?
    // TODO: Pretty sure we have a MAX PRIORITIES thing somewhere?
    if (priority < -1 || priority > 3)
        return -1;

    if (priority == -1)
        return process->priority;

    int old_priority = process->priority;
    process->priority = priority;
    return old_priority;
}
