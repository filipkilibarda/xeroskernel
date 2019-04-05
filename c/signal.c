/** signal.c - support for signal handling
 *
 * Contains kernel side implementations of system calls used for process
 * signalling.
 *
 * List of public functions:
 * See doc strings above functions for more details.
 *
 *      void setup_sig_context(pcb *process, int signal_num)
 *      int  signal(PID_t pid, int signal_num)
 *      void sigtramp(void (*handler)(void *), void *context)
 *      int  sigreturn(pcb *process, void *old_sp)
 *      int  sighandler(pcb *process, int signal_num, funcptr_t newHandler,
 *                      funcptr_t *oldHandler)
 *      int  is_valid_signal_num(int signal_num)
 *
 */

#include <xeroskernel.h>
#include <xeroslib.h>
#include <i386.h>
#include <test.h>


static void      somethings_broken_function(void);
static int       has_pending_signals(pcb* process);
static int       get_current_sig_num(pcb *process);
static int       is_signal_pending(pcb *process, int signal_num);
static void      set_signal(pcb *process, int signal_num);
static void      clear_signal(pcb *process, int signal_num);
static funcptr_t get_sig_handler(pcb *process, int signal_num);
static void      set_sig_handler(pcb *process, funcptr_t handler,
                                 int signal_num);


/**
 * Setup the signal context on the stack of the given process for the given
 * signal number.
 *
 * Should be called right before context switching to the process.
 *
 * See sig_context_t for details on what exactly is pushed onto the stack.
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
 * Set the corresponding bit in the signal mask for the given signal number.
 *
 * If the process to signal is blocked, unblock it and set its return value.
 **/
int signal(PID_t pid, int signal_num) {

    pcb *process_to_signal = get_active_pcb(pid);

    if (!is_valid_signal_num(signal_num))                       return -583;
    if (!process_to_signal)                                     return -514;
    if (get_sig_handler(process_to_signal, signal_num) == NULL) return 0;

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
 * Signal trampoline placed on process stack as EIP when signal context is set
 * up.
 *
 * Calls the specified handler and performs a sigreturn. Does not return control
 * to function after calling syssigreturn.
 */
void sigtramp(void (*handler)(void *), void *context) {
    LOG("Starting sigtramp");
    handler(context);
    // Rewind stack to point to old context, and restore previous return value.
    syssigreturn(context);
}


/**
 * Kernel side implementation of the system call syssigreturn.
 *
 * Caller is responsible for assigning the return value here to the process'
 * return value entry in the pcb.
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
    unsigned long nh = (unsigned long) newHandler;
    unsigned long oh = (unsigned long) oldHandler;
    if (!is_valid_signal_num(signal_num) || signal_num == 31) return -1;
    if (nh && !within_kernel_memory_bounds(nh))               return -2;
    if (!within_kernel_memory_bounds(oh))                     return -3;

    *oldHandler = get_sig_handler(process, signal_num);
    set_sig_handler(process, newHandler, signal_num);
    LOG("Registered handler %d for proc %d", signal_num, process->pid);
    return 0;
}


// =============================================================================
//                           HELPERS
// =============================================================================

/**
 * Return 1 if the given signal number is valid.
 * Return 0 otherwise
 */
int is_valid_signal_num(int signal_num) {
    return 0 <= signal_num && signal_num < MAX_SIGNALS;
}


/**
 * Return signal number of the highest priority outstanding (pending) signal
 * that is of greater priority than the current signal being serviced.
 *
 * Return -1 if no pending signals exceed the current signal priority or if
 * there are no pending signals at all.
 */
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


/**
 * Function that automatically tells you if your program is broken.
 */
static void somethings_broken_function(void) {
    FAIL("Your code is broken!");
}


static int has_pending_signals(pcb* process) {
    int current_sig_num = get_current_sig_num(process);
    if (current_sig_num == -1)
        return process->pending_sig_mask > 0;
    return (process->pending_sig_mask >> (current_sig_num + 1)) > 0;
}


static int get_current_sig_num(pcb *process) {
    if (!process->sig_context)
        return -1;
    return process->sig_context->signal_num;
}


static int is_signal_pending(pcb *process, int signal_num) {
    return (process->pending_sig_mask & (1 << signal_num)) > 0;
}


static void set_signal(pcb *process, int signal_num) {
    process->pending_sig_mask |= 1 << signal_num;
}


static void clear_signal(pcb *process, int signal_num) {
    process->pending_sig_mask &= ~(1 << signal_num);
}


static funcptr_t get_sig_handler(pcb *process, int signal_num) {
    if (!is_valid_signal_num(signal_num))
        FAIL("Bug. Invalid signal num.");
    return process->sig_handlers[signal_num];
}


static void set_sig_handler(pcb *process, funcptr_t handler, int signal_num) {
    if (!is_valid_signal_num(signal_num))
        FAIL("Bug. Invalid signal num.");
    process->sig_handlers[signal_num] = handler;
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

    // Continuation of above
    process = init_dummy_process();
    set_signal(process, 1);
    setup_sig_context(process, 1);
    clear_signal(process, 1);
    set_signal(process, 1);
    ASSERT_INT_EQ(-1, get_pending_sig_num(process));

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
static void _test_signal2(void);
void test_handler(void *);

static PID_t proc;

/**
 * Wrapper function for test routine. 
 */
void test_signal(void) {
    RUN_TEST(_test_signal);
    RUN_TEST(_test_signal2);
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
    funcptr_t oldHandler;
    int result = syssighandler(2, newHandler, &oldHandler);
    ASSERT_INT_EQ(0, result);
    result = syssleep(10000); 
    ASSERT(result > 0, "Result should have been > 0\n");
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
    // Used for test cleanup later
    int initial_num_stopped = get_num_stopped_processes();
    int initial_free_memory = total_free_memory();

    PID_t p1;
    funcptr_t newHandler = NULL;
    funcptr_t oldHandler = NULL;
    int result;

    // A basic test of syssigkill() functionality
    // TEST 1: Ensure that one process can signal another
    p1 = syscreate(test_process, DEFAULT_STACK_SIZE);
    pcb *p1_pcb = get_active_pcb(p1);

    syssleep(200);
    ASSERT_INT_EQ(0, syskill(p1, 31));
    ASSERT_INT_EQ(PROC_STOPPED, p1_pcb->state);
    ASSERT_INT_EQ(initial_num_stopped, get_num_stopped_processes());

    // ======================================================
    // BEGIN SYSSIGHANDLER TESTS
    // ======================================================

    // TEST 2: attempt to register handler for invalid signals
    result = syssighandler(-3, newHandler, &oldHandler);
    ASSERT_INT_EQ(result, -1);
    result = syssighandler(32, newHandler, &oldHandler);
    ASSERT_INT_EQ(result, -1);

    // TEST 3: attempt to register handler for signal 31
    result = syssighandler(31, newHandler, &oldHandler);
    ASSERT_INT_EQ(-1, result);

    // TEST 4: attempt to register newHandler at invalid addresses
    result = syssighandler(10, (funcptr_t) (HOLESTART + 10), &oldHandler);
    ASSERT_INT_EQ(-2, result);
    result = syssighandler(4, (funcptr_t) (END_OF_MEMORY + 10), &oldHandler);
    ASSERT_INT_EQ(-2, result);
    // TODO: test NULL newHandler (expect 0)

    // TEST 5: attempt to pass in oldHandler pointer at invalid addresses
    result = syssighandler(5, newHandler, (funcptr_t *) (HOLESTART + 10));
    ASSERT_INT_EQ(-3, result);
    result = syssighandler(6, newHandler, (funcptr_t *) (END_OF_MEMORY + 10));
    ASSERT_INT_EQ(-3, result);
    // TODO: test NULL oldHandler (expect -3)

    // TEST 6: successfully install a 'handler'
    result = syssighandler(4, newHandler, &oldHandler);
    ASSERT_INT_EQ(0, result);
    // Since the signal table was empty, there shouldn't be anything here
    ASSERT(oldHandler == NULL, "oldHandler should be NULL\n");

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
    ASSERT_INT_EQ(0, syskill(proc, 31));
    ASSERT_INT_EQ(0, syskill(p3, 31));

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
    LOG("RETURNED TO TEST");

    // TEST 13: Interrupt a process sleeping for a while with a signal
    // Expect that its return value will not be 0.
    PID_t sleeper = syscreate(sleep_a_while, DEFAULT_STACK_SIZE);
    syssleep(1000);
    LOG("Calling syskill on sleeper");
    ASSERT_INT_EQ(0, syskill(sleeper, 5));
    syssleep(1000);
    ASSERT_INT_EQ(0, syskill(sleeper, 31));

    // TODO:
    // TEST 14: Signal a non-blocking system call
    // Expect that ssysigreturn will retrieve the old return 
    // value of the non-blocking system call, and thus
    // the value will be returned as normal.

    // TEST 15: prioritization and signals interrupting each other
    // Expect that higher priority signal handler will run first
    int handler_one = syssighandler(3, sig_low_priority, &oldHandler);
    int handler_two = syssighandler(5, sig_high_priority, &oldHandler);
    ASSERT_INT_EQ(0, handler_one);
    ASSERT_INT_EQ(0, handler_two);
    syskill(sysgetpid(), 3);

    // TEST 16: attempt to do a syswait() on a non-existent process
    int syswait_result = syswait(10000);
    ASSERT_INT_EQ(-1, syswait_result);

    // Cleanup and validate
    // ====================
    // Ensures all processes created in here finished. That is, none of them
    // deadlocked waiting for a message.
    // NOTE: This code is duplicated elsewhere. IF YOU MAKE CHANGES HERE MAKE
    // SURE TO CTRL+F AND ADD ELSEWHERE
    wait_for_free_pcbs(initial_num_stopped);
    validate_stopped_queue();
    ASSERT_INT_EQ(initial_free_memory, total_free_memory());
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

int high_prio_runs = 0;
int low_prio_runs = 0;
int num_runs = 0;
PID_t pid;

void handler2(void *context) {
    num_runs++;
}

void high_prio_handler(void *context) {
    LOG("Running high priority handler");
    if (high_prio_runs++ == 0) {
        SYSKILL(pid, 0);
        ASSERT_INT_EQ(0, low_prio_runs);
    }
}

void low_prio_handler(void *context) {
    LOG("Running low priority handler");
    low_prio_runs++;
    ASSERT_INT_EQ(1, high_prio_runs);
    SYSKILL(pid, 1);
    ASSERT_INT_EQ(2, high_prio_runs);
}

void handler_run_twice(void *context) {
    num_runs++;
    if (num_runs == 1) {
        SYSKILL(pid, 3);
        ASSERT_INT_EQ(1, num_runs);
    }
}

void _test_signal2(void) {

    // =======================================================================
    // Signal yourself
    // =======================================================================

    num_runs = 0;
    pid = sysgetpid();
    funcptr_t old_handler;

    syssighandler(0, handler2, &old_handler);
    SYSKILL(pid, 0);
    ASSERT_INT_EQ(1, num_runs);

    // =======================================================================
    // TEST Signal a process multiple times
    // =======================================================================

    syssighandler(1, high_prio_handler, &old_handler);
    syssighandler(0, low_prio_handler, &old_handler);

    SYSKILL(pid, 1);
    ASSERT_INT_EQ(1, low_prio_runs);
    ASSERT_INT_EQ(2, high_prio_runs);

    // =======================================================================
    // Simple test case like above except have a signal handler send the same
    // signal to itself. The signal handler should in fact run twice.
    // =======================================================================

    num_runs = 0;
    syssighandler(3, handler_run_twice, &old_handler);
    SYSKILL(pid, 3);
    ASSERT_INT_EQ(2, num_runs);

    // TODO Write a test where IPC is happening and make sure return value is
    //  restored after signal.
}
