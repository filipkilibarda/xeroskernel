/** create.c : create a process
 *
 * This file implements one function that's used by the kernel to create new
 * processes.
 *
 *  create(func, stack_size):
 *      Called by the kernel after user process calls syscreate(...). Sets up
 *      a PCB for the new process, allocates stack space for it, puts it on
 *      the ready queue and sets up its stack so the dispatcher can handle it.
 **/

#include <xeroskernel.h>
#include <xeroslib.h>
#include "test.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static unsigned long EFLAGS = 0x00003200;
static unsigned long GP_REGISTER = 0x00000000;
static void *kern_stack;
static void *SYS_STOP_ADDRESS = &sysstop;
#pragma GCC diagnostic pop

static unsigned long CS;
static void *EIP;
static void *ESP;

pcb *setup_process(void (*func)(void), int stack_size, int priority);


/**
 * Creates a process running the provided routine, with a stack 
 * of size stack_size. 
 * 
 * Returns the process ID on success, -1 on failure
 * */
extern int create(void (*func)(void), int stack_size) {
    pcb *process = setup_process(func, stack_size, DEFAULT_PRIORITY);
    if (process == NULL) return -1;
    enqueue_in_ready(process);
    LOG("Created process %d", process->pid);
    return process->pid;
}


/**
 * Setup everything that's needed to run a process with the given routine.
 * Don't enqueue it. Return the PCB of the created process.
 **/
pcb *setup_process(void (*func)(void), int stack_size, int priority) {
    // Obtain a free pcb
    pcb *free_pcb = dequeue_from_stopped();
    if (free_pcb == NULL) return NULL;

    free_pcb->stack_end = kmalloc(stack_size);

    if (free_pcb->stack_end == NULL) {
        // kmalloc failed so need to return the pcb back to the stopped pcbs
        enqueue_in_stopped(free_pcb);
        return NULL;
    }

    ESP = free_pcb->stack_end + stack_size - sizeof(safety_zone);
    EIP = func;
    CS = getCS();

    __asm __volatile(" \
        movl %%esp, kern_stack \n\
        movl ESP, %%esp \n\
        push SYS_STOP_ADDRESS \n\
        push EFLAGS \n\
        push CS \n\
        push EIP \n\
        push GP_REGISTER \n\
        push GP_REGISTER \n\
        push GP_REGISTER \n\
        push GP_REGISTER \n\
        push GP_REGISTER \n\
        push GP_REGISTER \n\
        push GP_REGISTER \n\
        push GP_REGISTER \n\
        movl %%esp, ESP \n\
        movl kern_stack, %%esp \n\
    "
    :
    :
    :
    );

    free_pcb->stack_ptr = ESP;
    free_pcb->state = PROC_READY;
    // Priority of newly created process is 3 by default.
    free_pcb->priority = priority;
    free_pcb->pid = generate_pid(free_pcb);

    free_pcb->receiver_queue = queue_constructor();
    free_pcb->sender_queue = queue_constructor();
    free_pcb->receiving_from_pid = NULL;
    free_pcb->sending_to_pid = NULL;
    free_pcb->num_ticks = 0;
    free_pcb->sig_mask = (unsigned long) 0x00000000;

    // Initialize all signal handlers to NULL
    for (int i = 0; i < 31; i++) {
        free_pcb->sig_handlers[i] = NULL;
    }
    
    free_pcb->sig_handlers[31] = &sysstop;

    return free_pcb;
}


/**
 * Create the idle process. This function must run before create is called
 * for the first time. I.e., the idle process must be the first process in
 * the system.
 *
 * Ensures that the idle process has PID of zero.
 **/
void create_idle_process(void) {
    // Create idle process with lowest priority
    idle_process = setup_process(idleproc, DEFAULT_STACK_SIZE, 0);

    if (get_pcb_index(idle_process->pid) != IDLE_PROCESS_PID) {
        FAIL("The idle process must be the first one that's created.");
    }

    // Hack to make sure the PID is zero for the idle process.
    idle_process->pid = IDLE_PROCESS_PID;
}


/**
 * Generate a PID for the given process control block that is different from
 * the previous PID. Ensures that the generated PID is different from other
 * running processes.
 *
 * This works by simply incrementing the PCB's pid field by the size of the PCB
 * table. Since the PID of all PCBs is simply initialized to the index of the
 * PCB in the table, computing the index into the PCB table given the PID is
 * a very simple operation. See get_pcb_index() for more details on that.
 **/
PID_t generate_pid(pcb *process) {
    return process->pid + MAX_PCBS;
}
