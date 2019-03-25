/** user.c : User processes
 *
 * The functions in this file contain the code for "user" processes.
 *
 *  root():
 *      This is the most important process. It runs with PID 0 and it's
 *      purpose is to start any other processes we want, then simply yield
 *      continuously.
 **/

#include <xeroskernel.h>
#include <xeroslib.h>
#include <test.h>


void wait_for_free_pcbs(int num_pcbs);
static PID_t root_pid; // Stores root PID for message passing purposes


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
        syskill(sysgetpid(), 9);
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
    for(;;) sysyield();
}


/**
 * Test that syscreate returns the PID on success and -1 on failure.
 **/
void test_syscreate_return_value(void) {
    kprintf("\n======Starting test for syscreate_return_value======\n");

    int original_num = num_ready_processes();

    int pid = syscreate(simple_process, 4096);
    LOG("PID is %d", pid);
    ASSERT_INT_EQ(1, num_ready_processes());
    ASSERT(pid >= 0, "Expected PID to be greater than 0");
    ASSERT_INT_EQ(PROC_READY, get_state(pid));

    kill(pid);
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

    kprintf("\n======Starting test for pcb_table_full======\n");

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
    kprintf("\n======Starting test for stack_too_big======\n");

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
    void *user_memory = kmalloc(4096);
    int create_result = syscreate(user_memory, 4096);
    ASSERT(create_result == -1, "Should not have been able to create process"); 
 }


#define VA_ARGS(...) , ##__VA_ARGS__

#define PUTS(msg, ...) do {\
    sprintf(buff, "Process %d: ", process_pid);\
    sprintf(&buff[12], msg VA_ARGS(__VA_ARGS__));\
    strcat(buff, "\n");\
    sysputs(buff);\
} while(0)


/**
 * Process used in assignment 2 revised consumer/producer
 **/
void proc(void) {

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
extern void root(void) {
    char buff[80];
    PID_t pids[4];
    PID_t process_pid;

    // Put this process's PID in a global variable so the other processes can
    // explicitly receive from this process using the PID.
    root_pid = process_pid = sysgetpid();

    PUTS("Root process started.");

    // Create 4 processes, track their PIDs
    for (int i = 0; i < 4; i++) {
        PID_t pid = syscreate(proc, 4096);
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
    syskill(sysgetpid(), 9);
}


// Idle process 
extern void idleproc(void) {
    for(;;);
}
