/* signal.c - support for signal handling
   This file is not used until Assignment 3
 */

#include <xeroskernel.h>
#include <xeroslib.h>
#include <i386.h>
#include <test.h>

int get_highest_signal_number(unsigned long pending_sig_mask);
void init_sig_context(pcb *process_to_signal);

// Signal masks, used for updating pending_sig_mask
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
 * Function that automatically tells you if your program is broken.
 * It's amazing.
 */
void somethings_broken_function(void) {
    FAIL("Your code is broken!");
}


int has_pending_signals(pcb* process) {
    if (!process->sig_context)
        return process->pending_sig_mask > 0;
    return (process->pending_sig_mask /
            (1 << process->sig_context->signal_num)) > 0;
}


/**
 * TODO
 */
 // TODO: write simple test for this
int get_pending_sig_num(pcb *process) {

    int pending_sig_mask = process->pending_sig_mask;

    if (!has_pending_signals(process))
        return -1;

    int signal_num = -1;
    for (int i = 0; i < MAX_SIGNALS; i++) {
        if (pending_sig_mask == 0)
            break;
        pending_sig_mask >>= 1;
        signal_num++;
    }
    return signal_num;
}


int get_current_sig_num(pcb *process) {
    if (!process->sig_context)
        return -1;
    return process->sig_context->signal_num;
}


int is_signal_pending(pcb *process, int signal_num) {
    return (process->pending_sig_mask & (1 << signal_num)) > 0;
}


void set_signal(pcb *process, int signal_num) {
    process->pending_sig_mask |= 1 << signal_num;
}


void clear_signal(pcb *process, int signal_num) {
    process->pending_sig_mask &= ~(1 << signal_num);
}


funcptr_t get_sig_handler(pcb *process, int signal_num) {
    return process->sig_handlers[signal_num];
}


/**
 * Setup the signal context for the current highest priority pending signal.
 */
void setup_sig_context(pcb *process, int signal_num) {

    if (get_current_sig_num(process) >= signal_num)
        FAIL("Bug should not end up here.");

    if (!is_signal_pending(process, signal_num))
        FAIL("Bug. Shouldn't be setting a signal if it's not pending.");

    LOG("Setting up sig %d for pid %d", signal_num, process->pid);

    // Overlay the signal context over the process' stack
    sig_context_t *sig_context = process->stack_ptr - sizeof(sig_context_t);
    memset(sig_context->empty_registers, 0, NUM_GP_REGISTERS*sizeof(void *));
    // TODO: Make sure this pointer this is right... wtf
    sig_context->eip = (unsigned long) sigtramp;
    sig_context->cs = getCS();
    sig_context->eflags = PROCESS_EFLAGS;
    sig_context->empty_return_address = somethings_broken_function;
    sig_context->handler = get_sig_handler(process, signal_num);
    sig_context->process_context = process->stack_ptr;
    sig_context->signal_num = signal_num;
    sig_context->old_ret_value = process->ret_value;

    // Setup the linked list of signal contexts on the stack
    sig_context->prev_sig_context = process->sig_context;
    process->sig_context = sig_context;

    process->stack_ptr = sig_context;

    clear_signal(process, signal_num);
}



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

    if (!process_to_signal)                                  return -514;
    if (!is_valid_signal_num(signal_num))                    return -583;
    if (process_to_signal->sig_handlers[signal_num] == NULL) return 0;

    set_signal(process_to_signal, signal_num);

    if (is_blocked(process_to_signal)) {
        if (!on_sleeper_queue(process_to_signal)) {
            process_to_signal->ret_value = INTERRUPTED_SYSCALL;
        } else {
            // The process is sleeping in this case, so the return value
            // should already be how much time is left to sleep.
        }
        unblock(process_to_signal);
        return 0;
    }
    return 0;
}


/**
 * Signal trampoline placed on process stack as EIP when 
 * signal stack is set up. Calls the specified handler 
 * and performs a sigreturn. Does not return control to 
 * function after calling syssigreturn. 
 **/ 
void sigtramp(void (*handler)(void *), void *context) {
    LOG("Starting sigtramp");
    handler(context);
    // Rewind stack to point to old context, and 
    // restore previous return value.
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
//void init_sig_context(pcb *process_to_signal) {
//    process_to_signal->sig_prio = signal_num;
//
//        __asm __volatile( " \
//            movl %%esp, kern_stack \n\
//            movl proc_stack, %%esp \n\
//            push proc_stack \n\
//            push handler \n\
//            push GP_REGISTER \n\
//            push EFLAGS \n\
//            push CS \n\
//            push EIP \n\
//            push signal_num \n\
//            push proc_stack \n\
//            push OLD_RV \n\
//            push GP_REGISTER \n\
//            push GP_REGISTER \n\
//            push GP_REGISTER \n\
//            push GP_REGISTER \n\
//            push GP_REGISTER \n\
//            movl %%esp, proc_stack \n\
//            movl kern_stack, %%esp \n\
//        "
//        :
//        :
//        :
//        );
//
//        process_to_signal->stack_ptr = proc_stack;
//}

/**
 * Returns the highest signal number that exists in the mask.
 * If there is no signal pending in mask, returns -2.
 */
//int get_highest_signal_number(unsigned long pending_sig_mask) {
//    int highest_so_far = 0;
//    for (int i = 0; i < MAX_SIGNALS; i ++) {
//        int mask = pending_sig_mask;
//        mask = mask & sig_masks[i];
//        if (mask > highest_so_far) {
//            highest_so_far = i + 1;
//        }
//    }
//
//    // because I made the mask values go from 1 - 32,
//    // subtract 1 to get the actual signal number
//    if (highest_so_far == 0) return -2;
//    return highest_so_far - 1;
//}
//
//
/**
 * Returns the signal mask for a specified signal number
 */
//unsigned long get_pending_sig_mask(int signal_num) {
//    return sig_masks[signal_num];
//}


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
//int kill(PID_t pid, int signal_num) {
//
//    // Make sure pid to send to exists
//    pcb *receiving_process = get_active_pcb(pid);
//
//    if (!receiving_process) return -514;
//    if (!is_valid_signal_num(signal_num)) return -583;
//
//    // No handler for this signal, ignore it
//    if (receiving_process->sig_handlers[signal_num] == NULL)
//        return 0;
//
//    // If process to signal is blocked, set its return value to -666, unless it
//    // is sleeping
//    if (is_blocked(receiving_process)) {
//
//        if (!on_sleeper_queue(receiving_process))
//            receiving_process->ret_value = INTERRUPTED_SYSCALL;
//
//        // Clear all IPC state from this process because we're cancelling any
//        // system call it was making (including IPC system calls)
//        remove_from_ipc_queues(receiving_process);
//
//        LOG("Pulling from sleep list");
//        // TODO: No need to pull from sleep list everytime
//        pull_from_sleep_list(receiving_process);
//        enqueue_in_ready(receiving_process);
//
//        signal(pid, signal_num);
//        return 0;
//
//    } else {
//        signal(pid, signal_num);
//        return 0;
//    }
//}


/**
 * Kernel side implementation of the system call syssigreturn.
 */
int sigreturn(pcb *process, void *old_sp) {
    int ret_value = process->sig_context->old_ret_value;
    process->stack_ptr = process->sig_context->process_context;
    process->sig_context = process->sig_context->prev_sig_context;
    return ret_value;
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
//                           Testing
// =============================================================================

// ======================================================
//              Test signal helpers
// ======================================================


pcb *init_dummy_process(void) {
    int _dummy_stack_var;
    pcb *process = dequeue_from_stopped();
    process->stack_ptr = (&_dummy_stack_var) - 200;
    process->ret_value = 1337;
    return process;
}


/**
 * This should not be run inside of a process.
 */
void test_signal_helpers(void) {
    reset_pcb_table();

    pcb *process = init_dummy_process();

    // Check that signal mask math is right
    ASSERT_INT_EQ(NULL, (int) process->sig_context);
    ASSERT_INT_EQ(NULL, process->pending_sig_mask);
    set_signal(process, 0);
    ASSERT_INT_EQ(1, process->pending_sig_mask);
    set_signal(process, 0);
    ASSERT_INT_EQ(1, process->pending_sig_mask);
    clear_signal(process, 0);
    ASSERT_INT_EQ(0, process->pending_sig_mask);
    clear_signal(process, 0);
    ASSERT_INT_EQ(0, process->pending_sig_mask);
    set_signal(process, 0);
    set_signal(process, 1);
    ASSERT_INT_EQ(3, process->pending_sig_mask);
    clear_signal(process, 2);
    ASSERT_INT_EQ(3, process->pending_sig_mask);
    clear_signal(process, 0);
    ASSERT_INT_EQ(2, process->pending_sig_mask);
    clear_signal(process, 0);
    ASSERT_INT_EQ(2, process->pending_sig_mask);
    clear_signal(process, 1);
    ASSERT_INT_EQ(0, process->pending_sig_mask);

    ASSERT_INT_EQ(0, is_signal_pending(process, 0));
    set_signal(process, 0);
    ASSERT_INT_EQ(1, is_signal_pending(process, 0));
    clear_signal(process, 0);
    ASSERT_INT_EQ(0, is_signal_pending(process, 0));

    // Do we figure out if a process has pending signals correctly?
    ASSERT_INT_EQ(-1, get_pending_sig_num(process));
    set_signal(process, 1);
    ASSERT_INT_EQ(1, get_pending_sig_num(process));
    set_signal(process, 2);
    set_signal(process, 3);
    ASSERT_INT_EQ(3, get_pending_sig_num(process));
    clear_signal(process, 3);
    ASSERT_INT_EQ(2, get_pending_sig_num(process));
    clear_signal(process, 2);
    ASSERT_INT_EQ(1, get_pending_sig_num(process));
    clear_signal(process, 1);
    ASSERT_INT_EQ(-1, get_pending_sig_num(process));

    // Slightly more in depth; get pending signals correctly?
    set_signal(process, 1);
    setup_sig_context(process, 1);
    ASSERT_INT_EQ(-1, get_pending_sig_num(process));
    clear_signal(process, 1);
    set_signal(process, 2);
    ASSERT_INT_EQ(2, get_pending_sig_num(process));
    clear_signal(process, 2);

    // ========================================
    // Test the sig context
    // ========================================
    process = init_dummy_process();
    process->ret_value = 1337;
    void *initial_stack_ptr = process->stack_ptr;

    // Setup one context
    set_signal(process, 0);
    setup_sig_context(process, 0);
    process->ret_value = 777;
    ASSERT_INT_EQ(1337, process->sig_context->old_ret_value);
    __asm __volatile("push $9":::); // Push to simulate running process

    // Setup next context
    set_signal(process, 1);
    setup_sig_context(process, 1);
    process->ret_value = 888;

    ASSERT_INT_EQ(1337, process->sig_context->prev_sig_context->old_ret_value);
    ASSERT_INT_EQ(-1, get_pending_sig_num(process));
    ASSERT_INT_EQ(1, get_current_sig_num(process));
    process->ret_value = sigreturn(process, NULL);
    ASSERT_INT_EQ(0, get_current_sig_num(process));
    ASSERT_INT_EQ(777, process->ret_value);
    ASSERT_INT_EQ(1337, process->sig_context->old_ret_value);

    // Setup another context on top
    set_signal(process, 2);
    setup_sig_context(process, 2);
    process->ret_value = 999;

    ASSERT_INT_EQ(2, get_current_sig_num(process));
    process->ret_value = sigreturn(process, NULL);
    ASSERT_INT_EQ(0, get_current_sig_num(process));
    ASSERT_INT_EQ(777, process->ret_value);

    ASSERT_INT_EQ(1337, process->sig_context->old_ret_value);
    process->ret_value = sigreturn(process, NULL);
    ASSERT_INT_EQ(1337, process->ret_value);

    ASSERT_INT_EQ((int) initial_stack_ptr, (int) process->stack_ptr);
    ASSERT_INT_EQ(0, process->pending_sig_mask);

    reset_pcb_table();
}


// ======================================================
//              Other tests
// ======================================================


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
    ASSERT_INT_EQ(INTERRUPTED_SYSCALL, result);
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
    syskill(sysgetpid(), 5);
    sysputs("I'm a lower priority\n");
}


/**
 * Helper for sending signals and checking successful return.
 */
#define SYSKILL(pid, signal_num) ASSERT_INT_EQ(0, syskill(pid, signal_num))


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

    // TEST 16: attempt to do a syswait() on a non-existent process
    int syswait_result = syswait(10000);
    ASSERT_INT_EQ(-1, syswait_result);
}


// =============================================================================
// =============================================================================
// =============================================================================
// =============================================================================
//                          MORE TESTS
// =============================================================================
// =============================================================================
// =============================================================================
// =============================================================================


//void handler2(void *context) {
//    kprintf("hi");
//}
//
//
//void _test_signal2(void) {
//
//    // =======================================================================
//    // Signal yourself
//    // =======================================================================
//
//    funcptr_t old_handler;
//    PID_t pid = sysgetpid();
//    int high_prio_runs = 0;
//    int low_prio_runs = 0;
//
//    int num_runs = 0;
//
//    syssighandler(0, handler2, &old_handler);
//    SYSKILL(pid, 0);
//    ASSERT_INT_EQ(1, num_runs);
//
//    STOP;

// =======================================================================
// TEST Signal a process multiple times
// =======================================================================

//    void high_prio_handler(void *context) {
//        high_prio_runs++;
//        SYSKILL(pid, 0);
//        ASSERT_INT_EQ(0, low_prio_runs);
//    }
//
//    void low_prio_handler(void *context) {
//        low_prio_runs++;
//        ASSERT_INT_EQ(1, high_prio_runs);
//        SYSKILL(pid, 1);
//        ASSERT_INT_EQ(2, high_prio_runs);
//    }
//
//    syssighandler(1, high_prio_handler, &old_handler);
//    syssighandler(0, low_prio_handler, &old_handler);
//
//    SYSKILL(pid, 1);
//    ASSERT_INT_EQ(1, low_prio_runs);
//    ASSERT_INT_EQ(2, high_prio_runs);

// =======================================================================
// Simple test case like above except have a signal handler send the same
// signal to itself. The signal handler should in fact run twice.
// =======================================================================
// TODO
//}
