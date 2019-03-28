/* sleep.c : sleep device 
   This file does not need to modified until assignment 2
 */

#include <xeroskernel.h>
#include <xeroslib.h>
#include <test.h>

#define TICK_TIME 10
pcb *sleep_delta_list = NULL;

// Testing methods
pcb *init_test_pcb(unsigned int milliseconds);

void _sleep_test(void);

void _test_time_slice(void);

/**
 * Used as a wrapper for running the sleep tests
 **/
void test_sleep(void) {
    RUN_TEST(_sleep_test);
}

/**
 * Used as a wrapper for running time slice test
 */
void test_time_slice(void) {
    RUN_TEST(_test_time_slice);
}

/**
 * Adds a given process to its spot in the sleep queue.
 * Sleep queue is ordered by sleep time remaining. 
 * 
 * Returns 0 on success.
 */
int sleep(pcb *process, unsigned int milliseconds) {
    // Set PCB metadata
    process->sleep_time = milliseconds;
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
        if (milliseconds < cur->sleep_time) {
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
 * Loops through sleep queue and decreases each process' time by TICK_TIME.
 * When a process' time is up, the process is rescheduled to ready queue.
 */
void tick() {
    pcb *cur = sleep_delta_list;
    while (cur != NULL) {
        cur->sleep_time -= TICK_TIME;
        // Always update return value with remaining
        // sleep time; if process is woken early, 
        // it will then return with the time remaining
        cur->ret_value = cur->sleep_time;
        cur = cur->next;
    }

    cur = sleep_delta_list;
    pcb *prev = NULL;
    while (cur != NULL) {
        if (cur->sleep_time <= 0) {
            if (prev == NULL) {
                // Advance head
                sleep_delta_list = cur->next;
            } else {
                // 'Cut out' the process from the list
                prev->next = cur->next;
            }
            // For this assignment we never wake up early
            cur->ret_value = 0;
            LOG("Finished sleeping %d.", cur->pid);
            enqueue_in_ready(cur);
        }
        prev = cur;
        cur = cur->next;
    }

}


// For debugging 
void print_sleep_list(void) {
    pcb *head = sleep_delta_list;
    while (head) {
        kprintf("PID: %d\n", head->pid);
        kprintf("Time remaining: %d\n", head->sleep_time);
        head = head->next;
    }
}


/**
 * Tests various aspects of the sleep functionality. 
 * 
 * Ensure that:
 * - PCB enqueued into correct spot in delta list.
 * - PCB removed from delta list after sufficient number of quantums. 
 * - PCB added back correctly to ready queue.
 **/
void _sleep_test(void) {
    // TEST 1: Create 4 PCBs with different sleep times,
    // add them to sleep queue.
    // Ensure that they get added in the correct order.
    pcb *pcb_1 = init_test_pcb(1000);
    pcb *pcb_2 = init_test_pcb(2000);
    pcb *pcb_3 = init_test_pcb(1500);
    pcb *pcb_4 = init_test_pcb(500);

    sleep(pcb_1, pcb_1->sleep_time);
    sleep(pcb_2, pcb_2->sleep_time);
    sleep(pcb_3, pcb_3->sleep_time);
    sleep(pcb_4, pcb_4->sleep_time);

    pcb *cur = sleep_delta_list;
    for (int i = 0; i < 4; i++) {
        switch (i) {
            case 0:
                ASSERT(cur->sleep_time == 500, "Order wrong!");
                break;
            case 1:
                ASSERT(cur->sleep_time == 1000, "Order wrong!");
                break;
            case 2:
                ASSERT(cur->sleep_time == 1500, "Order wrong!");
                break;
            case 3:
                ASSERT(cur->sleep_time == 2000, "Order wrong!");
                break;
        }
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

    sleep(pcb_1, pcb_1->sleep_time);
    sleep(pcb_2, pcb_2->sleep_time);
    sleep(pcb_3, pcb_3->sleep_time);
    sleep(pcb_4, pcb_4->sleep_time);

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
        LOG("Ready queue PID is %d\n", this_pid);
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
void _test_time_slice(void) {
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
    test_pcb->sleep_time = milliseconds;
    test_pcb->priority = 3;
    test_pcb->next = NULL;
    return test_pcb;
}