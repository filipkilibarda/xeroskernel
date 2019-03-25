/** disp.c : dispatcher
 *
 * This file handles process scheduling and system calls.
 *
 *  dispatch():
 *      Does exactly as stated above.
 **/

#include <xeroskernel.h>
#include <i386.h>
#include <test.h>


char *proc_state_str[4] = {"READY", "RUNNING", "STOPPED", "BLOCKED"};

void free_process_memory(pcb *process);
pcb *get_pcb(PID_t pid);
int count_pcbs(pcb_queue *queue);

// Set up stopped queue
static pcb_queue _stopped_queue;
static pcb_queue *stopped_queue = &_stopped_queue;

// Set up multiple ready queues, one for each priority
static pcb_queue _ready_queue_p0;
static pcb_queue _ready_queue_p1;
static pcb_queue _ready_queue_p2;
static pcb_queue _ready_queue_p3;

static pcb_queue *ready_queue_p0 = &_ready_queue_p0;
static pcb_queue *ready_queue_p1 = &_ready_queue_p1;
static pcb_queue *ready_queue_p2 = &_ready_queue_p2;
static pcb_queue *ready_queue_p3 = &_ready_queue_p3;

// Array of queue structs, one for each priority
static pcb_queue *ready_queues[4];

/**
 * Initializes the PCB table entries.
 * Adds all entries to the stopped queue.
 **/
extern void pcb_init(void) {
    reset_pcb_table();
}


/**
 * Reset the pcbs and queues back to their initial state. Note, you shouldn't
 * use this unless you're sure all the memory allocated for the PCBs has been
 * freed.
 **/
void reset_pcb_table(void) {
    stopped_queue->front_of_line = NULL;
    stopped_queue->end_of_line = NULL;

    // Populate PCB table with initial values
    for (int i = 0; i < MAX_PCBS; i++) {
        pcb_table[i] = (pcb) {.pid = i, .state = PROC_STOPPED,
                .stack_ptr = NULL, .next = NULL,
                .ret_value = -1};
        enqueue_in_stopped(&pcb_table[i]);
    }

    // Set up ready queues array
    ready_queues[0] = ready_queue_p0;
    ready_queues[1] = ready_queue_p1;
    ready_queues[2] = ready_queue_p2;
    ready_queues[3] = ready_queue_p3;

    // Initialize all ready queues
    for (int i = 0; i < 4; i++) {
        ready_queues[i]->front_of_line = NULL;
        ready_queues[i]->end_of_line = NULL;
    }

}


/**
 * Schedules processes and handles system calls from running processes.
 **/
extern void dispatch(void) {
    int request;
    int priority;              // used in SYSCALL_SET_PRIO
    char *message;             // used in SYSCALL_PUTS
    PID_t pid;                 // used in SYSCALL_KILL
    void *process_func_ptr;    // used in SYSCALL_CREATE
    unsigned int milliseconds; // used in SYSCALL_SLEEP
    int stack_size;            // used in SYSCALL_CREATE
    unsigned long *num;        // used in SYSCALL_RECV
    PID_t *pid_ptr;            // used in SYSCALL_RECV
    unsigned long data;        // used in SYSCALL_SEND

    // Grab the first process to service
    pcb *process = dequeue_from_ready();

    for (;;) {
        request = contextswitch(process);

        switch(request) {
            case SYSCALL_CREATE:
                // eip_ptr field points to top of interrupted stack, just
                // before all the general purpose registers are pushed. So it
                // points to the EIP of the interrupted process. Here we get
                // the first argument passed to syscreate (the function pointer)
                process_func_ptr = *((void **) (process->eip_ptr + 24));
                stack_size = *((int *) (process->eip_ptr + 28));
                process->ret_value = create(process_func_ptr, stack_size);
                break;

            case SYSCALL_YIELD:
                enqueue_in_ready(process);
                process = dequeue_from_ready();
                break;

            case SYSCALL_STOP:
                if (kill(process->pid) != 0) {
                    FAIL("Should always be able to kill this process.");
                }
                process = dequeue_from_ready();
                break;

            case SYSCALL_GET_PID:
                // Return process PID
                process->ret_value = process->pid;
                enqueue_in_ready(process);
                process = dequeue_from_ready();
                break;

            case SYSCALL_PUTS:
                // Obtain message and print to screen
                message = *((char **) (process->eip_ptr + 24));
                kprintf(message);
                enqueue_in_ready(process);
                process = dequeue_from_ready();
                break;

            case SYSCALL_KILL:
                // Obtain PID to kill and kill it
                pid = *((PID_t *) (process->eip_ptr + 24));
                process->ret_value = kill(pid);

                // Check if process killed itself,
                // if not, enqueue process back to ready
                if (process->state != PROC_STOPPED) {
                    enqueue_in_ready(process);
                }

                process = dequeue_from_ready();
                break;

            case SYSCALL_SET_PRIO:
                // Get requested priority
                priority = *((int *) (process->eip_ptr + 24));

                // Check for valid priority
                if (priority < -1 || priority > 3) {
                    process->ret_value = -1;
                    enqueue_in_ready(process);
                    process = dequeue_from_ready();
                    break;
                }

                // Set the priority, or return the current priority
                if (priority == -1) process->ret_value = process->priority;
                else {
                    process->ret_value = process->priority;
                    process->priority = priority;
                }

                enqueue_in_ready(process);
                process = dequeue_from_ready();
                break;

            case SYSCALL_SLEEP:
                // Obtain time to sleep for and sleep
                milliseconds = *((unsigned int *) (process->eip_ptr + 24));
                sleep(process, milliseconds);
                process = dequeue_from_ready();
                break;

            case SYSCALL_SEND:
                // Obtain PID and data and call send
                pid = *((PID_t*) (process->eip_ptr + 24));
                data = *((unsigned long*) (process->eip_ptr + 28));
                send(process, pid, data);
                process = dequeue_from_ready();
                break;

            case SYSCALL_RECV:
                // Obtain PID and number buffers and call recv
                pid_ptr = *((PID_t**) (process->eip_ptr + 24));
                num = *((unsigned long**) (process->eip_ptr + 28));
                recv(process, pid_ptr, num);
                process = dequeue_from_ready();
                break;

            case SYSCALL_GET_CPU_TIMES:
                process_statuses *proc_stats =
                        (process_statuses *) (process->eip_ptr + 24);
                process->ret = get_cpu_times(proc_stats);
                enqueue_in_ready(process);
                process = dequeue_from_ready();
                break;

            case TIMER_INT:
                // Tick the clock and signal completion
                tick();
                end_of_intr();
                process->num_ticks++;

                // Ensure we don't enqueue idle process
                if (process != idle_process) 
                    enqueue_in_ready(process);

                process = dequeue_from_ready();
                break;

            default: 
                LOG("Invalid request code %d", request);
                break;
        }
    }
}


/**
 * Free up the memory associated with the given process.
 **/
void free_process_memory(pcb *process) {
    int result = kfree(process->stack_end);
    if (result == 0)
        FAIL("Kfree failed. Bug or user process destroyed a memheader.");
}


/**
 * Kill the process with the given pid. Note, this will add the PCB to the
 * stopped queue and remove it from the ready queue, even if it's not at the
 * front of the ready queue.
 *
 * This will kill any process you ask it to no matter what it was doing or
 * what system call it made.
 **/
int kill(PID_t pid) {
    pcb *process = get_pcb(pid);
    // Can't kill the idle process
    if (pid == IDLE_PROCESS_PID) return -1;
    // Process with given PID doesn't exist
    if (!process) return -1;
    // Can't kill a stopped process.
    if (is_stopped(process)) return -1;

    LOG("Killing process PID: %d", process->pid);
    free_process_memory(process);
    enqueue_in_stopped(process);
    pull_from_queue(ready_queues[process->priority], process);
    notify_dependent_processes(process);
    remove_from_ipc_queues(process);
    return 0;
}


/**
 * Return the process control block for the given pid.
 *
 * If the PID of the process control block doesn't match the given PID, then
 * there is no process with the given PID so return NULL.
 *
 * If you want to access the idle process's PCB for some reason, use the pcb
 * table directly.
 **/
pcb *get_pcb(PID_t pid) {
    pcb* process = &pcb_table[get_pcb_index(pid)];
    if (process->pid != pid || process->pid == IDLE_PROCESS_PID) return NULL;
    return process;
}


/**
 * Create and initialize a queue of PCBs.
 **/
pcb_queue queue_constructor(void) {
    pcb_queue ret = {
            .front_of_line = NULL,
            .end_of_line = NULL
    };
    return ret;
}


/**
 * Add a pcb to the queue.
 **/
void enqueue(pcb_queue *queue, pcb *process) {
    process->next = NULL;
    if (queue->front_of_line == NULL) {
        queue->front_of_line = process;
        queue->end_of_line = process;
    } else {
        queue->end_of_line->next = process;
        queue->end_of_line = process;
    }
}


/**
 * Remove pcb from queue.
 **/
pcb *dequeue(pcb_queue *queue) {
    if (queue->front_of_line == NULL) return NULL;

    pcb *process_removed = queue->front_of_line;

    if (queue->front_of_line == queue->end_of_line) {
        queue->front_of_line = NULL;
        queue->end_of_line = NULL;
    } else {
        queue->front_of_line = queue->front_of_line->next;
    }

    process_removed->next = NULL;
    return process_removed;
}


/**
 * Removes the given PCB from the queue no matter where in the queue it was.
 *
 * Return 1 if process was found and removed from queue, 0 if not
 **/
int pull_from_queue(pcb_queue *queue, pcb *process) {
    pcb_queue tmp_queue = { NULL, NULL };
    int removed = 0;

    pcb *current_pcb = dequeue(queue);
    while (current_pcb != NULL) {
        if (current_pcb == process) {
            removed = 1;
        } else {
            enqueue(&tmp_queue, current_pcb);
        }
        current_pcb = dequeue(queue);
    }

    current_pcb = dequeue(&tmp_queue);
    while (current_pcb != NULL) {
        enqueue(queue, current_pcb);
        current_pcb = dequeue(&tmp_queue);
    }

    return removed;
}


/**
 * Fetch the next process that should be run.
 * Tries each queue, starting from priority 0
 * until a non-null queue is found.
 *
 * Return the idle process if all ready queues are empty.
 **/
pcb *dequeue_from_ready(void) {
    int q_index = 0;
    // Advance queue index to first non-empty queue
    while(queue_is_empty(ready_queues[q_index])) q_index++;
    // Return the idle process if they're all empty
    if (q_index > 3) return idle_process;

    pcb *process_to_run = dequeue(ready_queues[q_index]);
    process_to_run->state = PROC_RUNNING;
    return process_to_run;
}


/**
 * Mark a process as ready to run, and place it
 * on the queue corresponding to its priority.
 **/
void enqueue_in_ready(pcb *process) {
    if (process->sending_to_pid || process->receiving_from_pid)
        FAIL("Bug. Ready processes should never have these fields set.");
    if (process == idle_process)
        FAIL("Bug. Idle process should never be enqueued!");
    process->state = PROC_READY;
    enqueue(ready_queues[process->priority], process);
}


/**
 * This will be called from create to grab a free process control block.
 **/
pcb *dequeue_from_stopped(void) {
    return dequeue(stopped_queue);
}


/**
 * Stop the given process by adding it to the stopped queue. Note, this
 * doesn't guarantee that the process has been removed from the ready queue.
 **/
void enqueue_in_stopped(pcb *process) {
    process->state = PROC_STOPPED;
    enqueue(stopped_queue, process);
}


/**
 * Return 1 if the queue is empty, 0 otherwise.
 **/
int queue_is_empty(pcb_queue *queue) {
    return queue->front_of_line == NULL;
}


/**
 * Return the total number of running processes.
 **/
int num_ready_processes(void) {
    int total_ready = 0;
    for (int i = 0; i < 4; i++) {
        total_ready += count_pcbs(ready_queues[i]);
    }
    return total_ready;
}


/**
 * Return the number of stopped processes (vacant process control blocks).
 **/
int get_num_stopped_processes(void) {
    return count_pcbs(stopped_queue);
}


/**
 * Count the number of process control blocks in the given linked list.
 **/
int count_pcbs(pcb_queue *queue) {
    int count = 0;
    pcb *process = queue->front_of_line;
    while (process != NULL) {
        count++;
        process = process->next;
    }
    return count;
}


/**
 * Return the state of the process with the given pid.
 **/
int get_state(int pid) {
    return get_pcb(pid)->state;
}


/**
 * Return 1 if the given pid is READY, 0 otherwise.
 **/
int is_ready(int pid) {
    return get_state(pid) == PROC_READY;
}


/**
 * Return the index corresponding to a given PID
 **/
int get_pcb_index(PID_t pid) {
    return pid % MAX_PCBS;
}


/**
 * Returns the ready queue for a given priority of process
 **/
pcb *get_ready_queue(int priority) {
    return ready_queues[priority]->front_of_line;
}

/*
 * Print the state of the PCB.
 **/
void print_pcb_state(pcb *process) {
    kprintf("pid: %d, state: %s ", process->pid,
            proc_state_str[process->state]);
    if (process->next) kprintf("next pid: %d", process->next->pid);
    kprintf("\n");
}


/**
 * Prints the given queue for debugging purposes.
 **/
void print_queue(pcb_queue *queue) {
    pcb *cur = queue->front_of_line;
    if (queue->front_of_line == NULL) kprintf("Empty queue\n");
    while (cur != NULL) {
        print_pcb_state(cur);
        cur = cur->next;
    }
}


/**
 * Print the state of the ready queues.
 **/
void dump_queues(void) {
    for (int i = 0; i < 4; i++) {
        pcb_queue *head = ready_queues[i];
        print_queue(head);
    }
}


/**
 * Print the state of the stopped queue.
 **/
void print_stopped_queue(void) {
    print_queue(stopped_queue);
}


/**
 * Print the state of all PCBs.
 **/
void print_pcb_table(void) {
    for (int i = 0; i < MAX_PCBS; i++) {
        print_pcb_state(&pcb_table[i]);
    }
}


/**
 * Check that the given queue is valid. Used for testing.
 **/
void validate_stopped_queue(void) {
    pcb *process = stopped_queue->front_of_line;
    while (process) {
        if (process->state != PROC_STOPPED) FAIL("Invalid stopped queue.");
        process = process->next;
    }
}


/**
 * Allow all running processes to finish.
 **/
void wait_for_free_pcbs(int num_pcbs) {
    int i;
    int max_yields = 10000;
    for (i = 1; i <= 10000; i++) {
        if (get_num_stopped_processes() >= num_pcbs) break;
        sysyield();
    }
    if (i >= max_yields) {
        print_pcb_table();
        FAILL("Took too long waiting for %d free pcbs", num_pcbs);
    }
    LOG("Finished waiting for free pcbs (%d)", get_num_stopped_processes());
}


/**
 * This function is the system side of the sysgetcputimes call. It places into a
 * the structure being pointed to information about each currently active
 * process.
 *
 * Args:
 *     proc_stats: a pointer to a process_statuses structure that is filled with
 *                 information about all the processes currently in the system
 *
 * Return: The index of the last slot in process_statuses that got
 *         filled in. Basically, this is the number of active processes
 *         minus one.
 **/
int get_cpu_times(process_statuses *proc_stats) {

    int current_slot;
    current_slot = -1;

    // Used for validation
    unsigned long ptr = (unsigned long) proc_stats;
    unsigned long ptr_end = ptr + sizeof(process_statuses) - 1;

    if (in_hole(ptr) || in_hole(ptr_end))
        return -1;

    // TODO: In the solution given to us, they only check that the address
    //  doesn't go beyond main memory. They don't check that the address
    //  isn't in kernel space. User processes shouldn't be passing kernel
    //  space pointers into system calls, so I'm going to put that check here.
    if (!within_memory_bounds(ptr) || !within_memory_bounds(ptr_end))
        return -2;

    for (int i=0; i < MAX_PCBS; i++) {
        if (pcb_table[i].state != PROC_STOPPED) {
            // fill in the table entry
            current_slot++;
            proc_stats->pid[current_slot] = pcb_table[i].pid;
            proc_stats->status[current_slot] = pcb_table[i].state
            proc_stats->cpu_time[current_slot] =
                    pcb_table[i].num_ticks * TICK_MILLISECONDS;
        }
    }

    return current_slot;
}



/**
 * Print the status and cpu times for all active processes.
 **/
void print_cpu_times(process_statuses *proc_stats) {
    char buff[200];
    for(int j = 0; j <= procs; j++) {
        sprintf(buff, "%4d    %4d    %10d\n",
                proc_stats.pid[j],
                proc_stats.status[j],
                proc_stats.cpu_time[j]);
        kprintf(buff);
    }
}


/**
 * Test the dispatcher code.
 **/
void test_dispatcher(void) {

    kprintf("=========Starting tests for dispatcher!=========\n\n");

    pcb *process;

    for (int i = 0; i < 4; i++) {
        ASSERT(ready_queues[i]->front_of_line == NULL, "Ready queue should be empty");
    }

    ASSERT_INT_EQ(MAX_PCBS, get_num_stopped_processes());
    ASSERT_INT_EQ(0, num_ready_processes());

    process = dequeue_from_stopped();
    ASSERT_INT_EQ(0, process->pid);
    ASSERT(process->state == PROC_STOPPED, "Process state should be stopped");
    ASSERT_INT_EQ(MAX_PCBS-1, get_num_stopped_processes());
    enqueue_in_stopped(process);
    ASSERT_INT_EQ(MAX_PCBS, get_num_stopped_processes());

    // Pull out the second in line pcb from the stopped queue
    int pid = 3;
    process = get_pcb(pid);
    ASSERT_INT_EQ(1, pull_from_queue(stopped_queue, process));
    ASSERT(process->next == NULL, "Next process should be null");

    ASSERT_INT_EQ(0, num_ready_processes());

    ASSERT_INT_EQ(MAX_PCBS-1, get_num_stopped_processes());
    process = dequeue_from_stopped();
    ASSERT_INT_EQ(1, process->pid);
    process = dequeue_from_stopped();
    ASSERT_INT_EQ(2, process->pid);
    process = dequeue_from_stopped(); // Shouldn't be 3 because it cut the line
    ASSERT_INT_EQ(4, process->pid);

    ASSERT_INT_EQ(MAX_PCBS-4, get_num_stopped_processes());

    reset_pcb_table();
    ASSERT_INT_EQ(MAX_PCBS, get_num_stopped_processes());
    ASSERT_INT_EQ(0, num_ready_processes());

    kprintf("Finished dispatcher tests!\n\n");
}
