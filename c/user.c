/** user.c : User processes
 *
 * The functions in this file contain the code for "user" processes.
 **/

#include <i386.h>
#include <xeroskernel.h>
#include <xeroslib.h>
#include <test.h>


void wait_for_free_pcbs(int num_pcbs);
static PID_t root_pid; // Stores root PID for message passing purposes
static PID_t shell_pid; // used by a() to signal the shell. 
int global_milliseconds;


/**
 * Producer for the producer/consumer problem we did in A1.
 **/
void producer(void) {
    for (int i = 0; i < 15; i++) {
        kprintf("Happy 2019\n");
        sysyield();
    }
    sysstop();
}


/**
 * Consumer for the producer/consumer problem we did in A1.
 **/
void consumer(void) {
    for (int i = 0; i < 15; i++) {
        kprintf("everyone\n");
        //return;
        // Test to see if process can kill itself
        syskill(sysgetpid(), 31);
        // This won't happen
        kprintf("This line shouldn't print.");
        sysyield();
    }
    sysstop();
}


/**
 * Used for testing.
 **/
void simple_process(void) {
    PID_t pid = sysgetpid();
    pid = pid; // Suppress compiler warning about unused var
    LOG("Running inside process %d", pid);
    for(;;) sysyield();
}


/**
 * Test that syscreate returns the PID on success and -1 on failure.
 **/
void test_syscreate(void) {
    LOG("==== syscreate_return_value ====");

    int original_num = num_ready_processes();

    int pid = syscreate(simple_process, 4096);
    ASSERT_INT_EQ(1, num_ready_processes());
    ASSERT(pid >= 0, "Expected PID to be greater than 0");
    ASSERT_INT_EQ(PROC_READY, get_state(pid));

    ASSERT_INT_EQ(0, syskill(pid, 31));
    syswait(pid);
    ASSERT_INT_EQ(PROC_STOPPED, get_state(pid));
    ASSERT_INT_EQ(original_num, num_ready_processes());
}


void yield_500_times(void) {
    for (int i = 0; i < 500; i++) {
        sysyield();
    }
    sysstop();
}


/**
 * Test the case where we fill up the PCB table completely. Also test
 * overflowing the PCB table.
 *
 * Ensure that no memory is leaked once the processes finish.
 **/
void test_pcb_table_full(void) {

    LOG("======Starting test for pcb_table_full======");

    int pid;
    int original_num_free_pcbs = get_num_stopped_processes();
    unsigned long original_free_mem = total_free_memory();

    for (int i = 0; i < original_num_free_pcbs; i++) {
        pid = syscreate(yield_500_times, 4096);
        ASSERT_INT_NEQ(-1, pid);
    }


    ASSERT_INT_EQ(0, get_num_stopped_processes());

    pid = syscreate(yield_500_times, 4096);
    ASSERT_INT_EQ(-1, pid);

    ASSERT_INT_EQ(0, get_num_stopped_processes());

    wait_for_free_pcbs(original_num_free_pcbs);
    ASSERT_INT_EQ(original_num_free_pcbs, get_num_stopped_processes());

    ASSERT_INT_EQ(original_free_mem, total_free_memory());
}


/**
 * Test creating a process with a stack that's too big.
 **/
void test_stack_too_big(void) {
    LOG("======Starting test for stack_too_big======");

    int original_num_free_pcbs = get_num_stopped_processes();
    unsigned long original_free_mem = total_free_memory();

    ASSERT_INT_EQ(-1, syscreate(yield_500_times, original_free_mem));

    ASSERT_INT_EQ(original_free_mem, total_free_memory());
    ASSERT_INT_EQ(original_num_free_pcbs, get_num_stopped_processes());
    ASSERT_INT_EQ(0, num_ready_processes());
}


/**
 * Add a test that ensures syscreate can't be called with a function pointer
 * that points into the hole or off the end of memory.
 *
 * It's fine if the instruction pointer points to a region where kernel code
 * resides because that's exactly where the "user" process code resides in
 * our current kernel.
 **/
void test_invalid_process_code(void) {
    void *process_code = (void *) HOLESTART + 10;
    int create_result = syscreate(process_code, DEFAULT_STACK_SIZE);
    ASSERT(create_result == -1, "Should not have been able to create process"); 
}


#define PUTS(msg, ...) do {\
    sprintf(buff, "Process %d: ", process_pid);\
    sprintf(&buff[12], msg VA_ARGS(__VA_ARGS__));\
    strcat(buff, "\n");\
    sysputs(buff);\
} while(0)


/**
 * Process used in assignment 2 revised consumer/producer
 **/
void _producer_consumer_proc(void) {

    char buff[80];
    PID_t *receive_from = (PID_t*) kmalloc(4);
    unsigned long *num = (unsigned long*) kmalloc(4);
    PID_t process_pid = sysgetpid();

    PUTS("Starting...");

    // Sleep 5 seconds
    syssleep(5000);

    // Do a sysrecv from root process
    *receive_from = root_pid;
    sysrecv(receive_from, num);
    PUTS("Message received; going to sleep for %d ms", *num);
    syssleep(*num);

    // Free resources, and indicate exit
    kfree(num);
    kfree(receive_from);
    PUTS("Woke up! Exiting now.");
}


/**
 * Root process for the extended producer consumer problem.
 **/
void producer_consumer(void) {
    char buff[80];
    PID_t pids[4];
    PID_t process_pid;

    // Put this process's PID in a global variable so the other processes can
    // explicitly receive from this process using the PID.
    root_pid = process_pid = sysgetpid();

    PUTS("Starting producer consumer");

    // Create 4 processes, track their PIDs
    for (int i = 0; i < 4; i++) {
        PID_t pid = syscreate(_producer_consumer_proc, 4096);
        pids[i] = pid;
        PUTS("Created a process with PID %d", pid);
    }

    // Sleep for 4 seconds
    syssleep(4000);

    // Send to each process
    syssend(pids[2], 10000);
    syssend(pids[1], 7000);
    syssend(pids[0], 20000);
    syssend(pids[3], 27000);

    // Receive from process 4 
    PID_t *from_pid = (PID_t*) kmalloc(4);
    *from_pid = pids[3];
    unsigned long *num = (unsigned long*) kmalloc(4);
    int ret_status = sysrecv(from_pid, num);
    
    // Log the return status (should be -1 since process 3 died)
    PUTS("Receive from pid %d returned status %d", *from_pid, ret_status);

    // Send to third process created.
    int send_result = syssend(pids[2], 1000);
    PUTS("Send to pid %d returned status %d", pids[2], send_result);

    // Process kills itself
    syskill(sysgetpid(), 31);
}


/**
 * A special process that only runs when there's no other process for the
 * kernel to schedule. Runs with PID 0.
 */
void idleproc(void) {
    for(;;);
}


/**
 * This is the first real (not idle process) process in the system that handles
 * running every other process. Runs with PID 1.
 *
 * I think this is how it's done in Linux.
 */
void root(void) {
    // Tests
    // =====
    #ifdef TESTING
    syswait(create(test_syscreate, DEFAULT_STACK_SIZE));
    syswait(create(test_pcb_table_full, DEFAULT_STACK_SIZE));
    syswait(create(test_stack_too_big, DEFAULT_STACK_SIZE));
    syswait(create(test_invalid_process_code, DEFAULT_STACK_SIZE));
    syswait(create(test_ipc, DEFAULT_STACK_SIZE));
    syswait(create(test_signal, DEFAULT_STACK_SIZE));
//    syswait(create(test_kb, DEFAULT_STACK_SIZE));
//    syswait(create(test_time_slice, DEFAULT_STACK_SIZE));
//    syswait(create(producer_consumer, DEFAULT_STACK_SIZE));
    #endif
    // Start up the shell
    syswait(create(init_program, DEFAULT_STACK_SIZE));
}


/**
 * Returns 0 if user & password match the 
 * correct user and password.
 */
int verify_user(char *user, char *pass, int len1, int len2) {
    if (strncmp(user, "cs415\n", len1) == 0 &&
            strncmp(pass, "EveryonegetsanA\n", len2) == 0) {
        return 0;
    }

    return -1;
}

/* =========
 * BUILTINS
 * =========
 */


char *process_state_strings[4] = {"READY  ", "RUNNING", "STOPPED", "BLOCKED"};


/**
 * Prints process statuses in system for 
 * running/blocked processes. 
 */
void ps(void) {
    char buff[100];
    process_statuses psTab;
    int procs = sysgetcputimes(&psTab);

    sysputs("  PID    STATE       UPTIME (ms)\n");
    sysputs("  ===    =====       ===========\n");
    for (int i = 0; i <= procs; i++) {
        sprintf(buff, "%4d     %s  %10d\n", psTab.pid[i],
                process_state_strings[psTab.status[i]],
                psTab.cpu_time[i]);
        sysputs(buff);
    }    
}

/**
 * Causes the shell to exit. 
 */
void ex(void) {
    kprintf("Exiting...\n");
    syskill(shell_pid, 31);
}


/**
 * Kills the process with specified PID, 
 * otherwise prints "No such process" if 
 * PID does not exist.
 */
void k(PID_t pid) {
    char buff[30];
    int result = syskill(pid, 31);
    if (result == -514) sysputs("No such process\n");
    else {
        sprintf(buff, "Killed PID %d\n", pid);
        sysputs(buff);
    }
}


// The t process.
void t_proc(void) {
    while(1) {
        kprintf("t\n");
        syssleep(9000);
    }
}


/**
 * Starts the t() process, which 
 * prints t on a new line every ~10 secs.
 */
void t(void) {
    syscreate(t_proc, DEFAULT_STACK_SIZE);
}


/**
 * Handler installed by the a() command.
 */
void alarm_handler(void *context) {
    funcptr_t old_handler;
    sysputs("ALARM, ALARM, ALARM\n");
    syssighandler(18, NULL, &old_handler);
}


/**
 * The alarm process. Sleeps for 
 * the specified number of seconds, 
 * then sends a signal 18 to the shell. 
 */
void alarm_process(void) {
    syssleep(global_milliseconds);
    if (syskill(shell_pid, 18) != 0)
        sysputs("Failed to kill the shell!");
}


/**
 * Takes # seconds before a signal 18 is sent as parameter
 * - Installs a handler that prints "ALARM, ALARM, ALARM", 
 * - Disables signal 18 once alarm has been delivered
 * - if command line ends w/&, shell will run the process
 *   in the background, otherwise it waits for the process to
 *   terminate.
 * - Alarm process will sleep for the specified # of ticks, 
 *   then sends a signal 18 to the shell
 */
void a(int milliseconds, char *buff, int length) {
    global_milliseconds = milliseconds;

    funcptr_t old_handler;
    if (syssighandler(18, alarm_handler, &old_handler) != 0) {
        sysputs("Failed to install the alarm signal handler!");
        return;
    }

    PID_t alarm = syscreate(alarm_process, DEFAULT_STACK_SIZE);
    if (alarm == -1) {
        sysputs("Failed to create the alarm process!");
        return;
    }

    if (buff[length - 2] != '&')
        // If buff ends in &, run in background, else wait.
        syswait(alarm);
}


/**
 * Returns -1 if command does not exist, 
 * otherwise a code in the range 0-4 inclusive
 * indicating which command it is. 
 * 
 * Codes:
 * - 0 = ps
 * - 1 = ex/EOF
 * - 2 = k 
 * - 3 = t
 * - 4 = a
 */
int does_command_exist(char *buff) {

    if (strncmp(buff, "ps", 2) == 0) return 0;
    else if (strncmp(buff, "ex", 2) == 0) return 1;
    else if (strncmp(buff, "k ", 2) == 0) return 2;
    else if (strncmp(buff, "t", 1) == 0) return 3;
    else if (strncmp(buff, "a ", 2) == 0) return 4;

    return -1;
}

/**
 * Returns the numeric component of the command typed
 */
int get_numeric_arg(char *buff) {
    buff += 2;
    int result = atoi(buff);
    return result;
}

/**
 * Executes the appropriate command 
 * based off of the code passed to it 
 * by does_command_exist. 
 * 
 */
void execute_command(int command, char *buff, int length) {
    PID_t pid;
    int milliseconds;

    switch(command) {
        case 0: 
            ps();
            break;
        case 1:
            ex();
            break;
        case 2:
            pid = (PID_t) get_numeric_arg(buff);
            k(pid);
            break;
        case 3:
            t();
            break;
        case 4: 
            milliseconds = get_numeric_arg(buff);
            a(milliseconds, buff, length);
            break;
            
    }
}

/**
 * The shell program.
 * 
 * Takes user input and executes valid commands. 
 * Valid commands include:
 * - ps
 * - ex (or current EOF)
 * - k 
 * - t
 * - a
 * 
 * If a command is invalid, a message indicating 
 * this is displayed to the user. 
 */
void shell(void) {
    int fd;
    fd = sysopen(1);
    PROMPT:
    sysputs("\n");
    sysputs(">");
    char buff[60];
    int length = sysread(fd, buff, 60);

    // If EOF was input, exit shell.
    if (length == 0) ex();

    // Determine if buff command is valid
    // if so, return value indicates which command
    // it is.
    int command = does_command_exist(buff);
    if (command == -1) {
        sysputs("Command not found\n");
        goto PROMPT;
    } else {
        // Wrapper function to execute appropriate command
        execute_command(command, buff, length);
    }
    goto PROMPT;
}

/**
 * The init program, as specified in A3
 * Prompts user for a username and password. 
 * If the username and password are correct, 
 * starts the shell program. 
 */
void init_program(void) {
    int fd;
    sysputs("===========================================\n");
    sysputs("Welcome to Xeros - a not so experimental OS\n");
    sysputs("===========================================\n");

START:

    // Open echoing keyboard
    fd = sysopen(1);
    sysputs("\n");
    sysputs("Username: ");
    // Allocate buffer to hold 'cs415' as username
    char user[10];
    int len1 = sysread(fd, user, 10);
    sysclose(fd);

    // Open non-echoing keyboard
    fd = sysopen(0);
    sysputs("Password: ");
    // Allocate buffer to hold 'EveryonegetsanA' as password
    char pass[25];
    int len2 = sysread(fd, pass, 25);
    sysclose(fd);

    if (verify_user(user, pass, len1, len2) == -1) goto START;
    sysputs("\n");
    sysputs("Successfully logged in, starting terminal...\n");
    shell_pid = syscreate(shell, DEFAULT_STACK_SIZE);
    syswait(shell_pid);
    goto START;
} 