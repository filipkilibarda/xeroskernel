/** msg.c : messaging system
 *
 *  Implements direct inter-process communication where messages are limited
 *  to simple integers.
 **/

#include <xeroskernel.h>
#include <i386.h>
#include <test.h>


// NOTE: This implementation currently doesn't use list of senders/receivers. 

static pcb_queue receive_any_queue;
int is_blocked_receiving_from(pcb *receiving_pcb, pcb *sending_pcb);
void notify_queue(pcb_queue queue);


/**
 * Initialize inter process communication. To be called during kernel
 * initialization.
 **/
void init_ipc(void) {
    receive_any_queue = queue_constructor();
}


/**
 * Send an integer from the given process to the process with the given PID.
 **/
void send(pcb *sending_pcb, PID_t dest_pid, unsigned long num) {
    int ret = 0;
    pcb *receiving_pcb = get_active_pcb(dest_pid);

    if (sending_pcb == receiving_pcb)                       ret = -3;
    else if (receiving_pcb == NULL || is_stopped(receiving_pcb)) ret = -2;

    if (ret != 0) {
        LOG("Failed send; %d -> %d", sending_pcb->pid, dest_pid);
        sending_pcb->ret_value = ret;
        enqueue_in_ready(sending_pcb);
        return;
    }

    if (is_blocked_receiving_from(receiving_pcb, sending_pcb)) {
        // Obtain receiver's buffers
        PID_t *from_pid = *((PID_t **)(receiving_pcb->eip_ptr + 24));
        unsigned long *number = *((unsigned long **)(receiving_pcb->eip_ptr + 28));

        // Do exchange of data
        *number = num;
        *from_pid = sending_pcb->pid;
        sending_pcb->ret_value = 0;
        receiving_pcb->ret_value = 0;
        receiving_pcb->receiving_from_pid = NULL;

        // Add both processes on to the ready queue
        enqueue_in_ready(sending_pcb);
        enqueue_in_ready(receiving_pcb);
        LOG("Completed transfer %d -> %d", sending_pcb->pid, dest_pid);

    } else {
        LOG("Blocking on send %d -> %d", sending_pcb->pid, dest_pid);
        sending_pcb->state = PROC_BLOCKED;
        sending_pcb->sending_to_pid = dest_pid;
        enqueue(&receiving_pcb->sender_queue, sending_pcb);
    }
}


void recv(pcb *receiving_pcb, PID_t *from_pid, unsigned long *dst_num) {

    pcb *sending_pcb;
    int do_transfer;
    int ret = 0;

    if (receiving_pcb->pid == *from_pid)                      ret = -3;
    else if (!within_memory_bounds((unsigned long) dst_num))  ret = -4;
    else if (!within_memory_bounds((unsigned long) from_pid)) ret = -5;
    else if (*from_pid != 0) {
        sending_pcb = get_active_pcb(*from_pid);
        if (sending_pcb == NULL)                            ret = -2;
    } else if (get_num_stopped_processes() >= MAX_PCBS - 2) ret = -10;

    if (ret != 0) {
        LOG("Failed receive; %d <- %d", receiving_pcb->pid, *from_pid);
        receiving_pcb->ret_value = ret;
        enqueue_in_ready(receiving_pcb);
        return;
    }

    if (*from_pid == 0) {
        // If receiving from any process, simply dequeue from the sender queue
        sending_pcb = dequeue(&receiving_pcb->sender_queue);
        do_transfer = sending_pcb != NULL;
    } else {
        // If receiving from specific process, ensure that it's blocked, then
        // check that it's blocked waiting to send to this specific process.
        do_transfer = is_blocked(sending_pcb) &&
            pull_from_queue(&receiving_pcb->sender_queue, sending_pcb);
    }

    if (do_transfer) {
        // Obtain sender's data
        unsigned long num = *((unsigned long *) (sending_pcb->eip_ptr + 28));

        // Copy data into buffers
        *dst_num = num;
        *from_pid = sending_pcb->pid;
        sending_pcb->ret_value = 0;
        receiving_pcb->ret_value = 0;
        sending_pcb->sending_to_pid = NULL;

        // Add both back to ready
        enqueue_in_ready(sending_pcb);
        enqueue_in_ready(receiving_pcb);
        LOG("Completed transfer %d -> %d", *from_pid, receiving_pcb->pid);

    } else {
        receiving_pcb->state = PROC_BLOCKED;

        if (*from_pid == 0) {
            LOG("Blocking on receive %d <- ANY", receiving_pcb->pid);
            enqueue(&receive_any_queue, receiving_pcb);
        } else {
            LOG("Blocking on receive %d <- %d", receiving_pcb->pid, *from_pid);
            receiving_pcb->receiving_from_pid = sending_pcb->pid;
            enqueue(&sending_pcb->receiver_queue, receiving_pcb);
        }
    }
}


/**
 * Return 1 if state of process is STOPPED, 0 otherwise.
 **/
int is_stopped(pcb *process) {
    return process->state == PROC_STOPPED;
}


/**
 * Return 1 if the process state is BLOCKED, 0 otherwise.
 **/
int is_blocked(pcb *process) {
    return process->state == PROC_BLOCKED;
}


/**
 * Return 1 if process is blocked receiving from sending process or if it's
 * willing to receive from any process, 0 otherwise.
 **/
int is_blocked_receiving_from(pcb *receiving_pcb, pcb *sending_pcb) {
    return (receiving_pcb->receiving_from_pid == sending_pcb->pid &&
            pull_from_queue(&sending_pcb->receiver_queue, receiving_pcb)) ||
            pull_from_queue(&receive_any_queue, receiving_pcb);
}


/**
 * Remove this process from all IPC queues. Should be called when a process
 * is killed while blocked on some form of IPC.
 **/
void remove_from_ipc_queues(pcb *process) {
    pcb *other_process;

    pull_from_queue(&receive_any_queue, process);

    other_process = get_active_pcb(process->receiving_from_pid);
    if (other_process) pull_from_queue(&other_process->receiver_queue, process);

    other_process = get_active_pcb(process->sending_to_pid);
    if (other_process) pull_from_queue(&other_process->sender_queue, process);
}


/**
 * Notify all dependent processes that the given process has died.
 **/
void notify_dependent_processes(pcb *process) {
    notify_queue(process->receiver_queue);
    notify_queue(process->sender_queue);
}


/**
 * Go through the given queue and notify all processes that the process
 * they're depending on has died.
 **/
void notify_queue(pcb_queue queue) {
    pcb *dependent;
    while ((dependent = dequeue(&queue))) {
        dependent->ret_value = -1;
        dependent->receiving_from_pid = NULL;
        dependent->sending_to_pid = NULL;
        enqueue_in_ready(dependent);
        LOG("Failed transfer; put %d on ready queue", dependent->pid);
    }
}


// =============================================================================
// Testing
// =============================================================================


#define MSG 99000000
#define START 88000000

#define SEND(...) ASSERT_INT_EQ(0, syssend(__VA_ARGS__));
#define RECEIVE(...) ASSERT_INT_EQ(0, sysrecv(__VA_ARGS__));
#define WAIT(...) ASSERT_INT_EQ(0, syswait(__VA_ARGS__));
#define KILL(...) ASSERT_INT_EQ(0, syskill(__VA_ARGS__, 31));


// Holds the PID of the sender so the receiver knows which PID to receive from
static int sender_pid;
static int* kernel_space_pointer;


static void _test_ipc(void);
static void receiver(void);
static void receiver2(void);
static void receive_any(void);
static void dying_process(void);
static void echo(void);


/**
 * Simply wrapper for the actual test routine.
 **/
void test_ipc(void) {
    RUN_TEST(_test_ipc);
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
/**
 * Test the IPC system.
 *
 * Note: This needs to run inside a process, not the kernel.
 **/
void _test_ipc(void) {
    kprintf("Starting test IPC\n");
    // Used for memory leak test later on
    int initial_free_memory = total_free_memory();
    int num_stopped_processes = get_num_stopped_processes();
    sender_pid = sysgetpid();
    pcb *sender_pcb = get_active_pcb(sender_pid);
    PID_t from_pid;
    unsigned long msg;
    pcb *unused_pcb;

    // Send a message to non-existent process
    // ======================================
    unused_pcb = dequeue_from_stopped();
    ASSERT_INT_EQ(-2, syssend(unused_pcb->pid, MSG));
    enqueue_in_stopped(unused_pcb);

    // Send a message to itself
    // ========================
    ASSERT_INT_EQ(-3, syssend(sysgetpid(), MSG));

    // Receive from self
    // =================
    from_pid = sysgetpid();
    ASSERT_INT_EQ(-3, sysrecv(&from_pid, &msg));

    // Receive from stopped process
    // ============================
    unused_pcb = dequeue_from_stopped();
    from_pid = unused_pcb->pid;
    ASSERT_INT_EQ(-2, sysrecv(&from_pid, &msg));
    enqueue_in_stopped(unused_pcb);

    // Receive when this is the only running process
    // =============================================
    from_pid = 0;
    // Can't run this test when the root process is alive
//    ASSERT_INT_EQ(-10, sysrecv(&from_pid, &msg));

    // Send a message to a valid process
    // =================================
    int ret;
    PID_t receiver_pid;

    receiver_pid = create(receiver, DEFAULT_STACK_SIZE);
    ret = syssend(receiver_pid, MSG);
    ASSERT_INT_EQ(0, ret);
    ret = sysrecv(&receiver_pid, &msg);
    ASSERT_INT_EQ(0, ret);
    ASSERT_INT_EQ(MSG+1, msg);

    // Pass invalid pointer into from_pid parameter of receive
    // =======================================================
    ASSERT_INT_EQ(-5, sysrecv((PID_t *) kernel_space_pointer, &msg));
    ASSERT_INT_EQ(-5, sysrecv((PID_t *) HOLESTART, &msg));
    ASSERT_INT_EQ(-5, sysrecv((PID_t *) HOLEEND - 1, &msg));
    ASSERT_INT_EQ(-5, sysrecv((PID_t *) NULL, &msg));

    // Pass kernel space pointer into receive, num
    // ===========================================
    receiver_pid = create(receiver, DEFAULT_STACK_SIZE);
    ASSERT_INT_EQ(-4, sysrecv(&receiver_pid, (unsigned long *) kernel_space_pointer));
    ASSERT_INT_EQ(-4, sysrecv(&receiver_pid, (unsigned long *) HOLESTART));
    ASSERT_INT_EQ(-4, sysrecv(&receiver_pid, (unsigned long *) HOLEEND - 1));
    ASSERT_INT_EQ(-4, sysrecv(&receiver_pid, (unsigned long *) NULL));
    KILL(receiver_pid);

    // A simple receive_any test
    // =========================
    receiver_pid = create(receive_any, DEFAULT_STACK_SIZE);
    SEND(receiver_pid, MSG);

    // Send to process that dies while we're blocked
    // =============================================
    receiver_pid = create(dying_process, DEFAULT_STACK_SIZE);
    ASSERT_INT_EQ(-1, syssend(receiver_pid, MSG));
    // Expect -1 from because process should already be dead.
    ASSERT_INT_EQ(-1, syswait(receiver_pid));

    // Receive from a process that dies while we're blocked
    // ====================================================
    receiver_pid = create(dying_process, DEFAULT_STACK_SIZE);
    ASSERT_INT_EQ(-1, sysrecv(&receiver_pid, &msg));
    // Expect -1 from because process should already be dead.
    ASSERT_INT_EQ(-1, syswait(receiver_pid));

    // Ensure killed receive any proc gets removed from receive any queue
    // ==================================================================
    receiver_pid = create(receive_any, DEFAULT_STACK_SIZE);
    sysyield(); // Yield so other process can start
    ASSERT(!queue_is_empty(&receive_any_queue), "Queue should have one proc.");
    KILL(receiver_pid);
    ret = syswait(receiver_pid);
    ASSERT(ret == 0 || ret == -1, "Invalid return value from syswait");
    ASSERT(queue_is_empty(&receive_any_queue), "Queue should be empty.");
    ASSERT_INT_EQ(-2, syssend(receiver_pid, MSG));

    // Many receivers blocked on one process
    // =====================================
    PID_t r1 = create(receiver2, DEFAULT_STACK_SIZE);
    PID_t r2 = create(receiver2, DEFAULT_STACK_SIZE);
    PID_t r3 = create(receiver2, DEFAULT_STACK_SIZE);
    ASSERT(r1 > 0, "Failed to create receiver2 process");
    ASSERT(r2 > 0, "Failed to create receiver2 process");
    ASSERT(r3 > 0, "Failed to create receiver2 process");
    // Notify them about this process and what message to expect
    SEND(r1, MSG+1);
    SEND(r2, MSG+2);
    SEND(r3, MSG+3);
    // Send them the messages, they'll check that they get the expected msg
    SEND(r2, MSG+2);
    SEND(r1, MSG+1);
    SEND(r3, MSG+3);

    // Many senders blocked on one process
    // ===================================
    PID_t s1 = create(echo, DEFAULT_STACK_SIZE);
    PID_t s2 = create(echo, DEFAULT_STACK_SIZE);
    PID_t s3 = create(echo, DEFAULT_STACK_SIZE);
    ASSERT(s1 > 0, "Failed to create echo process");
    ASSERT(s2 > 0, "Failed to create echo process");
    ASSERT(s3 > 0, "Failed to create echo process");
    // Notify them about this process and what to send back here
    SEND(s1, MSG+1);
    SEND(s2, MSG+2);
    SEND(s3, MSG+3);
    // First receive from any process
    from_pid = 0;
    RECEIVE(&from_pid, &msg);
    switch (msg) {
        case MSG+1:
            ASSERT_INT_EQ(s1, from_pid);
            RECEIVE(&s3, &msg); ASSERT_INT_EQ(MSG+3, msg);
            RECEIVE(&s2, &msg); ASSERT_INT_EQ(MSG+2, msg);
            break;
        case MSG+2:
            ASSERT_INT_EQ(s2, from_pid);
            RECEIVE(&s3, &msg); ASSERT_INT_EQ(MSG+3, msg);
            RECEIVE(&s1, &msg); ASSERT_INT_EQ(MSG+1, msg);
            break;
        case MSG+3:
            ASSERT_INT_EQ(s3, from_pid);
            RECEIVE(&s1, &msg); ASSERT_INT_EQ(MSG+1, msg);
            RECEIVE(&s2, &msg); ASSERT_INT_EQ(MSG+2, msg);
            break;
        default:
            FAIL("Shouldn't reach here");
    }

    // Cleanup and validate
    // ====================
    // Ensures all processes created in here finished. That is, none of them
    // deadlocked waiting for a message.
    wait_for_free_pcbs(num_stopped_processes);
    validate_stopped_queue();
    ASSERT(queue_is_empty(&sender_pcb->receiver_queue), "Expect empty queue");
    ASSERT(queue_is_empty(&sender_pcb->sender_queue), "Expect empty queue");
    ASSERT(queue_is_empty(&receive_any_queue), "Expect empty queue");
    ASSERT_INT_EQ(initial_free_memory, total_free_memory());
}
#pragma GCC diagnostic pop


/**
 * This process will die as soon as another process blocks on it.
 **/
void dying_process(void) {
    pcb *my_pcb = get_active_pcb(sysgetpid());
    while (queue_is_empty(&my_pcb->sender_queue) &&
           queue_is_empty(&my_pcb->receiver_queue))
    {
        continue;
    }
}


/**
 * Receive from any process and end.
 **/
void receive_any(void) {
    LOCK(
        PID_t from_pid = 0;
        unsigned long msg;
        int ret = sysrecv(&from_pid, &msg);
        ASSERT_INT_EQ(0, ret);
        ASSERT_INT_EQ(MSG, msg);
    );
}


/**
 * Receive a message from the process that created it.
 **/
void receiver(void) {
    PID_t from_pid = sender_pid;
    unsigned long msg;
    // Receive from any process
    int ret = sysrecv(&from_pid, &msg);
    ASSERT_INT_EQ(0, ret);
    ASSERT_INT_EQ(MSG, msg);
    syssend(from_pid, msg+1);
}


void receiver2(void) {
    PID_t from_pid = 0;
    unsigned long msg;
    unsigned long expected_msg;
    // Receive from any process
    RECEIVE(&from_pid, &expected_msg);
    LOG("Pid received: %d", from_pid);
    // Receive from a specific process
    RECEIVE(&from_pid, &msg);
    ASSERT_INT_EQ(expected_msg, msg);
}


/**
 * Echo whatever is sent to it back to the sender.
 **/
void echo(void) {
    PID_t from_pid = 0;
    unsigned long msg;
    // Receive from any process
    RECEIVE(&from_pid, &msg);
    // Send reply
    SEND(from_pid, msg);
}
