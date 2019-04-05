/* sleep.c : sleep device 
   This file does not need to modified until assignment 2
 */

#include <xeroskernel.h>
#include <xeroslib.h>
#include <test.h>


pcb *sleep_delta_list;

// Testing methods
static pcb *init_test_pcb(unsigned int milliseconds);
int    get_sleep_time(pcb *process);


/**
 * Adds a given process to its spot in the sleep queue.
 * Sleep queue is ordered by sleep time remaining. 
 * 
 * Returns 0 on success.
 */
int sleep(pcb *process, unsigned int milliseconds) {

    // Convert the milliseconds to ticks
    int num_ticks = ms_to_ticks(milliseconds);

    process->sleep_ticks = num_ticks;
    process->state = PROC_BLOCKED;

    // Handle empty sleeper list case
    if (sleep_delta_list == NULL) {
        sleep_delta_list = process;
        process->next = NULL;
        return 0;
    }

    // Handle non-empty sleep list
    pcb *cur = sleep_delta_list;
    pcb *prev = NULL;
    while (cur != NULL) {
        if (num_ticks < cur->sleep_ticks) {
            // Handle head case
            if (prev == NULL) {
                process->next = sleep_delta_list;
                sleep_delta_list = process;
            } else {
                prev->next = process;
                process->next = cur;
            }
            return 0;
        }
        prev = cur;
        cur = cur->next;
    }

    // Should be at end of list
    prev->next = process;
    process->next = NULL;
    return 0;
}

/**
 * Loops through sleep queue and decreases each process' sleep ticks.
 * When a process' time is up, the process is rescheduled to ready queue.
 *
 * TODO: If you have time fix this so it uses a delta list.
 */
void tick() {
    pcb *cur = sleep_delta_list;
    while (cur != NULL) {
        // TODO: just decrease the number of ticks not the time
        cur->sleep_ticks -= 1;
        // Always update return value with remaining
        // sleep time; if process is woken early, 
        // it will then return with the time remaining
        cur->ret_value = ticks_to_ms(cur->sleep_ticks);
        cur = cur->next;
    }

    cur = sleep_delta_list;
    pcb *prev = NULL;
    while (cur != NULL) {
        if (cur->sleep_ticks == 0) {
            if (prev == NULL) {
                // Advance head
                sleep_delta_list = cur->next;
            } else {
                // 'Cut out' the process from the list
                prev->next = cur->next;
            }
            enqueue_in_ready(cur);
        }
        prev = cur;
        cur = cur->next;
    }

}

/**
 * Removes the specified pcb from the sleep queue
 */
void pull_from_sleep_list(pcb *process) {
    pcb *cur = sleep_delta_list;
    pcb *prev = NULL;
    while (cur != NULL) {
        if (cur == process) {
            //LOG("Pulling pid %d from sleep list", cur->pid);
            if (prev == NULL) {
                sleep_delta_list = cur->next;
            } else {
                prev->next = cur->next;
            }
        }
        prev = cur;
        cur = cur->next;
    }
}

/**
 * Return 1 if on sleeper queue
 * Return 0 otherwise
 */
int on_sleeper_queue(pcb *process) {
    pcb *cur = sleep_delta_list;
    while(cur != NULL) {
        if (cur == process) return 1;
        cur = cur->next;
    }
    return 0;
}


/**
 * Convert ticks to milliseconds.
 */
int ticks_to_ms(int num_ticks) {
    return num_ticks * TICK_MILLISECONDS;
}


/**
 * Convert milliseconds to ticks.
 */
int ms_to_ticks(int ms) {
    return (ms/TICK_MILLISECONDS + (ms%TICK_MILLISECONDS > 0));
}


/* ======================================================================
 *                              TESTING
 * ====================================================================== */

// For debugging 
void print_sleep_list(void) {
    pcb *head = sleep_delta_list;
    while (head) {
        kprintf("PID: %d\n", head->pid);
        kprintf("Ticks remaining: %d\n", head->sleep_ticks);
        head = head->next;
    }
}


/**
 * Return the amount of time (ms) that's left for the given process to sleep
 */
int get_sleep_time(pcb *process) {
    return ticks_to_ms(process->sleep_ticks);
}


/**
 * Tests various aspects of the sleep functionality. 
 * 
 * Ensure that:
 * - PCB enqueued into correct spot in delta list.
 * - PCB removed from delta list after sufficient number of quantums. 
 * - PCB added back correctly to ready queue.
 **/
void test_sleep(void) {

    ASSERT_INT_EQ(1, ms_to_ticks(10));
    ASSERT_INT_EQ(2, ms_to_ticks(11));
    ASSERT_INT_EQ(1, ms_to_ticks(9));
    ASSERT_INT_EQ(0, ms_to_ticks(0));

    // TEST 1: Create 4 PCBs with different sleep times,
    // add them to sleep queue.
    // Ensure that they get added in the correct order.
    pcb *pcb_1 = init_test_pcb(1000);
    pcb *pcb_2 = init_test_pcb(2000);
    pcb *pcb_3 = init_test_pcb(1500);
    pcb *pcb_4 = init_test_pcb(500);

    sleep(pcb_1, get_sleep_time(pcb_1));
    sleep(pcb_2, get_sleep_time(pcb_2));
    sleep(pcb_3, get_sleep_time(pcb_3));
    sleep(pcb_4, get_sleep_time(pcb_4));

    int expected_times[4] = {500, 1000, 1500, 2000};

    pcb *cur = sleep_delta_list;
    for (int i = 0; i < 4; i++) {
        ASSERT_INT_EQ(expected_times[i], get_sleep_time(cur));
        cur = cur->next;
    }

    kfree(pcb_1);
    kfree(pcb_2);
    kfree(pcb_3);
    kfree(pcb_4);

    // TEST 2: Ensure that after an ample number of ticks,
    // Processes are removed from sleep queue AND added
    // back to the ready queue.
    pcb_1 = init_test_pcb(50);
    pcb_2 = init_test_pcb(20);
    pcb_3 = init_test_pcb(10);
    pcb_4 = init_test_pcb(30);

    // Give them simple PIDs for testing purposes
    pcb_1->pid = 1;
    pcb_2->pid = 2;
    pcb_3->pid = 3;
    pcb_4->pid = 4;

    sleep(pcb_1, get_sleep_time(pcb_1));
    sleep(pcb_2, get_sleep_time(pcb_2));
    sleep(pcb_3, get_sleep_time(pcb_3));
    sleep(pcb_4, get_sleep_time(pcb_4));

    ASSERT_INT_EQ(4, get_length_pcb_list(sleep_delta_list));

    for (int i = 0; i < 5; i++) {
        tick();
    }

    ASSERT(sleep_delta_list == NULL,
           "Processes should have all been removed from the sleep list.");
    // Get the ready queue
    pcb *ready_queue = get_ready_queue(3);

    // Make sure all processes that were on the sleeping queue are now
    // on the ready queue
    int seen1, seen2, seen3, seen4 = 0;
    PID_t pid_1 = pcb_1->pid;
    PID_t pid_2 = pcb_2->pid;
    PID_t pid_3 = pcb_3->pid;
    PID_t pid_4 = pcb_4->pid;
    while (ready_queue != NULL) {
        PID_t this_pid = ready_queue->pid;
        if (this_pid == pid_1) seen1 = 1;
        else if (this_pid == pid_2) seen2 = 1;
        else if (this_pid == pid_3) seen3 = 1;
        else if (this_pid == pid_4) seen4 = 1;
        LOG("Ready queue PID is %d", this_pid);
        ready_queue = ready_queue->next;
    }

    ASSERT(seen1 == 1, "PCB 1 not added back to the ready queue");
    ASSERT(seen2 == 1, "PCB 2 not added back to the ready queue");
    ASSERT(seen3 == 1, "PCB 3 not added back to the ready queue");
    ASSERT(seen4 == 1, "PCB 4 not added back to the ready queue");

    reset_pcb_table();
    return;
}


/**
 * Loops and prints "Hello, process 1"
 * Used to test time slicing
 */
void print_loop_one(void) {
    while (1) {
        kprintf("Hello, process 1\n");
    }
}


/**
 * Loops and prints "Hello, process 2"
 * Used to test time slicing
 */
void print_loop_two(void) {
    while (1) {
        kprintf("Hello, process 2\n");
    }
}


/**
 * Tests time slicing by creating two infinite loop
 * processes that print messages. If time slicing works
 * the messages should eventually alternate when a timer 
 * interrupt goes off.
 */
void test_time_slice(void) {
    create(print_loop_one, DEFAULT_STACK_SIZE);
    create(print_loop_two, DEFAULT_STACK_SIZE);
}


/**
 * Helpful function for creating PCBs to be used in 
 * testing of sleep functionality.
 **/
pcb *init_test_pcb(unsigned int milliseconds) {
    // For testing sleep, all we really need is a PCB with
    // a sleep time.
    pcb *test_pcb = kmalloc(sizeof(pcb));
    test_pcb->state = PROC_BLOCKED;
    test_pcb->sleep_ticks = ms_to_ticks(milliseconds);
    test_pcb->priority = 3;
    test_pcb->next = NULL;
    test_pcb->sending_to_pid = NULL;
    test_pcb->receiving_from_pid = NULL;
    return test_pcb;
}