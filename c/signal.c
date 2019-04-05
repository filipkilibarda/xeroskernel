/* signal.c - support for signal handling
   This file is not used until Assignment 3
 */

#include <xeroskernel.h>
#include <xeroslib.h>
#include <i386.h>
#include <test.h>

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
static void *handler;
#pragma GCC diagnostic pop

int get_highest_signal_number(unsigned long sig_mask);
void init_signal_context(pcb *process_to_signal);

// Signal masks, used for updating sig_mask
// each mask is indexed to turn on/off a single bit 
// starting from the rightmost bit (signal 0) to 
// leftmost bit (signal 31)
unsigned long sig_masks[MAX_SIGNALS] =
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
 *
 * - If the current signal priority is higher than the priority of
 *   the signal being delivered, only update the signal mask. The signal
 *   is not delivered yet.
 *
 * - If the current signal priority if lower than the priority of the
 *   signal being delivered, add a signal context on top of the current
 *   process stack and update the signal mask.
 *
 * - If there is a pending signal that has a higher priority than the 
 *   signal currently being sent, add signal context for that signal
 *   to the stack, and update the mask with the sending signal.
 **/
int signal(PID_t pid, int signal_num) {

    pcb *process_to_signal = get_active_pcb(pid);

    // Check if the process we want to signal is blocked
    if (process_to_signal->state == PROC_BLOCKED) {
        process_to_signal->state = PROC_READY;
        process_to_signal->ret_value = -666;
    }

    // Get the handler
    handler = process_to_signal->sig_handlers[signal_num];

    // Check if there's already a signal pending
    int pending_signal = 
    get_highest_signal_number(process_to_signal->sig_mask);

    // Update signal mask (should be done no matter what) 
    process_to_signal->sig_mask = 
    process_to_signal->sig_mask | sig_masks[signal_num];

    proc_stack = process_to_signal->stack_ptr;
    CS = getCS();
    OLD_RV = process_to_signal->ret_value;

    // If there's a pending signal with higher priority,
    // set up its signal context.
    if (pending_signal > signal_num) {
        signal_code = pending_signal;
        init_signal_context(process_to_signal);
    }
    // Otherwise, check current signal priority to 
    // determine whether to send the signal 
    else if (process_to_signal->sig_prio < signal_num) {
        signal_code = signal_num;
        init_signal_context(process_to_signal);
    }

    // Stub (TODO: Is there something meaningful that this should return?)
    return 0;
}

/**
 * Signal trampoline placed on process stack as EIP when 
 * signal stack is set up. Calls the specified handler 
 * and performs a sigreturn. Does not return control to 
 * function after calling syssigreturn. 
 **/ 
extern void sigtramp(void (*handler)(void *), void *context) {
    if (handler != NULL) {
        //kprintf("SIGTRAMP: Calling handler\n");
        handler(context);
    } else kprintf("Handler is null\n");
    // Rewind stack to point to old context, and 
    // restore previous return value.
    //kprintf("SIGTRAMP: Calling syssigreturn\n");
    kprintf("Doing syssigreturn\n");
    syssigreturn(context);
}


/**
 * Initializes signal context on process stack. 
 * Pushes process context (stack pointer) and handler
 * in argument position for sigtramp() to use. 
 * Pushes signal code to be recovered when resetting bitmask. 
 * Pushes current return value of process to be recovered
 * by syssigreturn()
 */
void init_signal_context(pcb *process_to_signal) {
    process_to_signal->sig_prio = signal_code;
    
        __asm __volatile( " \
            movl %%esp, kern_stack \n\
            movl proc_stack, %%esp \n\
            push proc_stack \n\
            push handler \n\
            push GP_REGISTER \n\
            push EFLAGS \n\
            push CS \n\
            push EIP \n\
            push signal_code \n\
            push proc_stack \n\
            push OLD_RV \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
            push GP_REGISTER \n\
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
 * If there is no signal pending in mask, returns -2.
 */
int get_highest_signal_number(unsigned long sig_mask) {
    int highest_so_far = 0;
    for (int i = 0; i < MAX_SIGNALS; i ++) {
        int mask = sig_mask;
        mask = mask & sig_masks[i];
        if (mask > highest_so_far) {
            highest_so_far = i + 1;
        }    
    }

    // because I made the mask values go from 1 - 32, 
    // subtract 1 to get the actual signal number
    if (highest_so_far == 0) return -2;
    return highest_so_far - 1;
}


/**
 * Returns the signal mask for a specified signal number
 */
unsigned long get_sig_mask(int signal_num) {
    return sig_masks[signal_num];
}


/**
 * Return 1 if the given signal number is valid.
 * Return 0 otherwise
 */
int is_valid_signal_num(int signal_num) {
    return 0 <= signal_num && signal_num < MAX_SIGNALS;
}


/**
 * Kernel side implementation of the syskill system call.
 *
 * Sends a signal to a process (doesn't necessarily kill it).
 */
int kill(PID_t pid, int signal_num) {

    // Make sure pid to send to exists
    pcb *receiving_process = get_active_pcb(pid);

    if (!receiving_process)
        return -514;

    // If process to signal is blocked, set its return value to -666, unless it
    // is sleeping
    if (is_blocked(receiving_process)) {

        if (!on_sleeper_queue(receiving_process))
            receiving_process->ret_value = -666;

        // Clear all IPC state from this process because we're cancelling any
        // system call it was making (including IPC system calls)
        clear_ipc_state(receiving_process);

        LOG("Pulling from sleep list");
        // TODO: The return value here needs to be the amount of time that's
        //  left to sleep.
        pull_from_sleep_list(receiving_process);
        enqueue_in_ready(receiving_process);

        signal(pid, signal_num);
        return 0;

    } else if (!is_valid_signal_num(signal_num)) {
        return -583;

    } else {
        signal(pid, signal_num);
        return 0;
    }
}


/**
 * Kernel side implementation of the system call syssigreturn.
 */
int sigreturn(pcb *process, void *old_sp) {
    // Determine which signal was just sent and reset its bit in mask
    // TODO: We should reset the bit mask when we start hanlding the signal,
    //  not when we finish
    // TODO: Would be great if -4 were not hardcoded
    int signal_num = *((int *) (process->eip_ptr - 4));
    unsigned long mask = get_sig_mask(signal_num);
    process->sig_mask = process->sig_mask ^ mask;

    // TODO: 
    // Reset current signal priority in PCB
    // If signalstack != 0 
    // Grab signal off stack below

    // else check mask for a signal 

    // Else set to -1
    process->sig_prio = -1;

    // Update stack pointer
    process->stack_ptr = old_sp;

    // Restore old return value
    // TODO: Would be great if 36 were not hardcoded
    return *((int *) (old_sp + 36));
}


/**
 * Kernel side implementation of the system call syssighandler.
 *
 * Should be called from the dispatcher and the return value should be directly
 * passed to calling process.
 *
 * Thus, the return codes here are exactly this same as syssighandler.
 */
int sighandler(pcb *process, int signal_num, funcptr_t newHandler,
               funcptr_t *oldHandler)
{
    if (!is_valid_signal_num(signal_num) || signal_num == 31) {
        LOG("Invalid signal %d; can't change handler", signal_num);
        return -1;

    // TODO: This logic already exists in mem.c
    } else if (((int) newHandler > HOLESTART && (int) newHandler < HOLEEND)
               || (int) newHandler > END_OF_MEMORY) {
        return -2;

    // TODO: This logic already exists in mem.c
    } else if (((int) oldHandler > HOLESTART && (int) oldHandler < HOLEEND)
               || (int) oldHandler > END_OF_MEMORY || oldHandler == NULL) {
        return -3;

    } else {
        *oldHandler = process->sig_handlers[signal_num];
        process->sig_handlers[signal_num] = newHandler;
        LOG("Registered handler %d for proc %d", signal_num, process->pid);
        return 0;
    }
}


// =============================================================================
// Testing
// =============================================================================

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static void _test_signal(void);
void test_handler(void *);

static PID_t proc;

/**
 * Wrapper function for test routine. 
 */
void test_signal(void) {
    RUN_TEST(_test_signal);
}


void test_process(void) {
    // Does nothing.
    for(int i = 0; i < 10000000; i++) sysyield();
}

void test_process_prints(void) {
    for (int i = 0; i < 10; i++) {
        sysputs("Testing 1-2-3\n");
    }
}

void register_handler_loop(void) {
    funcptr_t newHandler = &test_handler;
    funcptr_t *oldHandler = (funcptr_t *) kmalloc(16);
    int result = syssighandler(2, newHandler, oldHandler);
    ASSERT_INT_EQ(0, result);
    result = syssleep(10000); 
    ASSERT(result > 0, "Result should have been > 0\n");
    kfree(oldHandler);
}

void test_handler(void *param) {
    kprintf("Running the specified handler!\n");
}

void send_signal_int(void) {
    int result = syssend(proc, 3);
    ASSERT_INT_EQ(-666, result);
}

void proc_killer(void) {
    syssleep(200);
    syskill(proc, 31);
}


void sleep_a_while(void) {
    int result = syssleep(20000);
    LOG("Sleep result: %d", result);
    ASSERT(result > 0, "Result should have been > 0\n");
}

void sig_high_priority(void *param) {
    sysputs("I'm a higher priority\n");
}

void sig_low_priority(void *param) {
    syswait(2000);
    sysputs("I'm a lower priority\n");
}

/**
 * Test the signal functionality
 */
void _test_signal(void) {
    int initial_num_stopped = get_num_stopped_processes();

    // A basic test of syssigkill() functionality 
    // TEST 1: Ensure that one process can signal another 
    PID_t p1 = syscreate(test_process, DEFAULT_STACK_SIZE);
    pcb *p1_pcb = get_active_pcb(p1);

    syssleep(200);
    ASSERT_INT_EQ(0, syskill(p1, 31));
    ASSERT_INT_EQ(PROC_STOPPED, p1_pcb->state);
    ASSERT_INT_EQ(initial_num_stopped, get_num_stopped_processes());

    // ======================================================
    // BEGIN SYSSIGHANDLER TESTS
    // ======================================================
    funcptr_t newHandler; 
    funcptr_t* oldHandler;

    // TEST 2: attempt to register handler for invalid signals
    newHandler = (funcptr_t) kmalloc(16);
    oldHandler = (funcptr_t *) kmalloc(16);
    int result = syssighandler(-3, newHandler, oldHandler);
    ASSERT_INT_EQ(result, -1);
    result = syssighandler(32, newHandler, oldHandler);
    ASSERT_INT_EQ(result, -1);

    // TEST 3: attempt to register handler for signal 31
    result = syssighandler(31, newHandler, oldHandler);
    ASSERT_INT_EQ(-1, result);

    // TEST 4: attempt to register newHandler at invalid addresses
    kfree(newHandler);
    newHandler = (funcptr_t) (HOLESTART + 10);
    result = syssighandler(10, newHandler, oldHandler);
    ASSERT_INT_EQ(-2, result);
    newHandler = (funcptr_t) (END_OF_MEMORY + 10);
    result = syssighandler(4, newHandler, oldHandler);
    ASSERT_INT_EQ(-2, result);
    // TODO: test NULL newHandler (expect 0)

    // TEST 5: attempt to pass in oldHandler pointer at invalid addresses
    newHandler = kmalloc(16);
    kfree(oldHandler);
    oldHandler = (funcptr_t *) (HOLESTART + 10);
    result = syssighandler(5, newHandler, oldHandler);
    ASSERT_INT_EQ(-3, result);
    oldHandler = (funcptr_t *) (END_OF_MEMORY + 10);
    result = syssighandler(6, newHandler, oldHandler);
    ASSERT_INT_EQ(-3, result);
    // TODO: test NULL oldHandler (expect -3)

    // TEST 6: successfully install a 'handler' 
    oldHandler = kmalloc(16);
    result = syssighandler(4, newHandler, oldHandler);
    ASSERT_INT_EQ(0, result);
    // Since the signal table was empty, there shouldn't be anything here
    ASSERT(*oldHandler == NULL, "oldHandler should be NULL\n");

    // TEST 7: attempt to signal default behavior ('ignore' signal)
    p1 = syscreate(test_process_prints, DEFAULT_STACK_SIZE);
    // We never defined a signal handler so it should just ignore this.
    // We will see it print 10 times. 
    sysputs("Calling syskill\n");
    ASSERT_INT_EQ(0, syskill(p1, 2));
    
    // TEST 8: attempt to signal while a process is blocked sleeping
    LOG("Handler is %x", &test_handler);
    PID_t p2 = syscreate(register_handler_loop, DEFAULT_STACK_SIZE);
    LOG("PID is %d", p2);
    syssleep(1000);
    LOG("Signaling p2: %d with signal 2", p2);
    ASSERT_INT_EQ(0, syskill(p2, 2));

    syssleep(1000);
    // TEST 9: attempt to signal a process blocked on a send
    proc = syscreate(test_process, DEFAULT_STACK_SIZE);
    PID_t p3 = syscreate(send_signal_int, DEFAULT_STACK_SIZE);
    ASSERT_INT_EQ(0, syskill(p3, 4));
    
    // TEST 10: Illegal syskill signal
    result = syskill(proc, 50);
    ASSERT_INT_EQ(-583, result);

    // TEST 11: Illegal syskill PID
    result = syskill(1000, 3);
    ASSERT_INT_EQ(-514, result);

    // TEST 12: syswait on a process, then kill that process it's 
    // ting on. 
    // Expect that this will cause us to return control back to next line
    proc = syscreate(test_process, DEFAULT_STACK_SIZE);
    syscreate(proc_killer, DEFAULT_STACK_SIZE);
    syswait(proc);
    LOG("RETURNED TO TEST", NULL);

    // TEST 13: Interrupt a process sleeping for a while with a signal
    // Expect that its return value will not be 0.
    PID_t sleeper = syscreate(sleep_a_while, DEFAULT_STACK_SIZE);
    syssleep(1000);
    LOG("Calling syskill on sleeper");
    ASSERT_INT_EQ(0, syskill(sleeper, 5));

    // TODO:
    // TEST 14: Signal a non-blocking system call
    // Expect that ssysigreturn will retrieve the old return 
    // value of the non-blocking system call, and thus
    // the value will be returned as normal.

    // TEST 15: prioritization and signals interrupting each other
    // Expect that higher priority signal handler will run first
    int handler_one = syssighandler(3, sig_low_priority, oldHandler);
    int handler_two = syssighandler(5, sig_high_priority, oldHandler);
    ASSERT_INT_EQ(0, handler_one);
    ASSERT_INT_EQ(0, handler_two);
    syskill(sysgetpid(), 3);
    syskill(sysgetpid(), 5);

    // TEST 16: attempt to do a syswait() on a non-existent process
    int syswait_result = syswait(10000);
    ASSERT_INT_EQ(-1, syswait_result);

    // 

}