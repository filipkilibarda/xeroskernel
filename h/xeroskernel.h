/* xeroskernel.h - disable, enable, halt, restore, isodd, min, max */

#ifndef XEROSKERNEL_H
#define XEROSKERNEL_H

/* Symbolic constants used throughout Xinu */

typedef	char    Bool;        /* Boolean type                  */
typedef unsigned int size_t; /* Something that can hold the value of
                              * theoretical maximum number of bytes 
                              * addressable in this architecture.
                              */
#define	FALSE   0       /* Boolean constants             */
#define	TRUE    1
#define	EMPTY   (-1)    /* an illegal gpq                */
#define	NULL    0       /* Null pointer for linked lists */
#define	NULLCH '\0'     /* The null character            */


/* Universal return constants */

#define	OK            1         /* system call ok               */
#define	SYSERR       -1         /* system call failed           */
#define	EOF          -2         /* End-of-file (usu. from read)	*/
#define	TIMEOUT      -3         /* time out  (usu. recvtim)     */
#define	INTRMSG      -4         /* keyboard "intr" key pressed	*/
                                /*  (usu. defined as ^B)        */
#define	BLOCKERR     -5         /* non-blocking op would block  */

// Syscall request IDs
#define SYSCALL_CREATE         0
#define SYSCALL_YIELD          1
#define SYSCALL_STOP           2
#define SYSCALL_RUNNING        3
#define SYSCALL_GET_PID        4
#define SYSCALL_PUTS           5
#define SYSCALL_KILL           6
#define SYSCALL_SET_PRIO       7
#define SYSCALL_SEND           8
#define SYSCALL_RECV           9
#define SYSCALL_SLEEP          10
#define SYSCALL_GET_CPU_TIMES  11
#define SYSCALL_SIG_HANDLER    12
#define SYSCALL_SIG_RETURN     13
#define SYSCALL_WAIT           14
#define SYSCALL_OPEN           15
#define SYSCALL_CLOSE          16
#define SYSCALL_WRITE          17
#define SYSCALL_READ           18
#define SYSCALL_IOCTL          19

#define TIMER_INT              100
#define KEYBOARD_INT           101

#define SYSCALL_IDT_INDEX 60 // Used for generic syscall interface

#define END_OF_MEMORY 0x400000
#define DEFAULT_STACK_SIZE 4096
#define DEFAULT_PRIORITY 3
// Maximum number of processes. Must be power of two
#define MAX_PCBS 32
#define IDLE_PROCESS_PID 0
// Process state numbers
#define PROC_READY 0
#define PROC_RUNNING 1
#define PROC_STOPPED 2
#define PROC_BLOCKED 3

// TODO: Assignment description says only 2 devices will be in our kernel so
//  that's why I'm choosing 2 here.
#define MAX_DEVICES 2

// TODO: Total guess. I just don't feel like figuring out how many
//  milliseconds I should actually put here right now.
#define TICK_MILLISECONDS 100

void           bzero(void *base, int cnt);
void           bcopy(const void *src, void *dest, unsigned int n);
void           disable(void);
unsigned short getCS(void);
unsigned char  inb(unsigned int);
void           init8259(void);
int            kprintf(char * fmt, ...);
void           lidt(void);
void           outb(unsigned int, unsigned char);
void           set_evec(unsigned int xnum, unsigned long handler);


// Memory management function prototypes
extern void    kmeminit(void);
extern int     kfree(void *ptr);
extern void *  kmalloc(size_t size);
unsigned long  total_free_memory(void);
int            within_memory_bounds(unsigned long address);
int            in_hole(unsigned long address);


// Header struct used in memory allocation
struct mem_header_s {
    unsigned long size;         // Size of memory chunk including this header
    struct mem_header_s *next;  // Next memory chunk
    struct mem_header_s *prev;  // Prev memory chunk
    char *sanity_check;         // Used for debugging.
    unsigned char mem_start[0]; // Start of the allocated memory
};
typedef struct mem_header_s mem_header;

// NEW FOR A2
typedef unsigned int PID_t;

struct pcb_s;

typedef struct pcb_queue_s {
    struct pcb_s *front_of_line;
    struct pcb_s *end_of_line;
} pcb_queue;

// Process Control Block
struct pcb_s {
    PID_t pid;
    int state;
    void *stack_ptr;
    // Points to address returned by kfree, which is the end of the stack.
    void *stack_end;
    // Points to the place on the process stack where eip was pushed after an
    // interrupt. This is simply here for convenience to make addressing
    // system call arguments off the stack easier.
    void *eip_ptr;
    int ret_value;            // The value to return to proc after sys call.
    int old_ret_value;        // Used in signaling to save old ret value
    int priority;             // Scheduling priority.
    int sleep_time;
    long num_ticks;           // Number of ticks used by this.
    struct pcb_s *next;       // Generic next pcb; used for queues.
    pcb_queue sender_queue;   // pcbs wanting to send to this.
    pcb_queue receiver_queue; // pcbs wanting to recv from this.
    PID_t receiving_from_pid; // PID that this is blocked receiving from.
    PID_t sending_to_pid;     // PID that this is blocked sending to.
    void *sig_handlers[32];
    unsigned long sig_mask;
    unsigned long sig_prio;   // The current highest priority signal for this process 
    pcb_queue waiter_queue;   // pcbs wanting to wait for this to end.
};
typedef struct pcb_s pcb;

// TODO: Update func decl. below s.t. take actual params
typedef struct device device_t;
struct device {
    int  major_num;
    int  minor_num;
    char *name;
    int  (*init)(void);
    int  (*open)(void);
    int  (*close)(void);
    int  (*read)(void);
    int  (*write)(void);
    int  (*seek)(void);
    int  (*getc)(void);
    int  (*putc)(void);
    int  (*cntl)(void);
    void *csr;
    void *ivec;
    void *ovec;
    int  (*iint)(void);
    int  (*oint)(void);
    void *ioblk;
};

// TODO: Clarify w/ TAs if this struct should be exactly the same as
//  what they gave us for a3 starter code
typedef struct struct_ps process_statuses;
struct struct_ps {
    int   length;             // Number of entries that are populated.
    int   pid[MAX_PCBS];      // The process ID
    int   status[MAX_PCBS];   // The process status
    long  cpu_time[MAX_PCBS]; // CPU time used in milliseconds
};


// TODO: We could probably get rid of the safety zone since everything is
//  working. Will do it once things are stable.
struct safety_zone_s {
    long one;
    long two;
};
typedef struct safety_zone_s safety_zone;

void        contextinit(void);
extern void pcb_init(void);
int         contextswitch(pcb *process);
extern void dispatch(void);
void        reset_pcb_table(void);

// disp.c
void      init_ipc(void);
int       kill(PID_t pid);
pcb_queue queue_constructor(void);
pcb *     get_ready_queue(int priority);
int       queue_is_empty(pcb_queue *queue);
int       pull_from_queue(pcb_queue *queue, pcb *process);
void      enqueue(pcb_queue *queue, pcb *process);
void      enqueue_in_ready(pcb *process);
void      enqueue_in_stopped(pcb *process);
pcb *     dequeue(pcb_queue *queue);
pcb *     dequeue_from_ready(void);
pcb *     dequeue_from_stopped(void);
int       num_ready_processes(void);
int       get_num_stopped_processes(void);
int       get_state(int pid);
pcb *     get_pcb(PID_t pid);
int       get_pcb_index(PID_t pid);
int       is_stopped(pcb *process);
void      wait_for_free_pcbs(int num_pcbs);
void      print_ready_queue(void);
void      print_stopped_queue(void);
void      print_pcb_table(void);
void      print_queue(pcb_queue *queue);
void      dump_queues(void);
void      validate_stopped_queue(void);
void      enqueue_in_waiters(pcb *process, pcb *wait_for);


// create.c
int  create(void (*func)(void), int stack_size);
void create_idle_process(void);


// user.c
void root(void);
void idleproc(void);


// syscall.c
unsigned int syscreate(void (*func)(void), int stack_size);
void         sysyield(void);
void         sysstop(void);
PID_t        sysgetpid(void);
void         sysputs(char *str);
int          syskill(PID_t pid, int signalNumber);
int          syssetprio(int priority);
int          syssend(PID_t dest_pid, unsigned long num);
int          sysrecv(PID_t *from_pid, unsigned long * num);
unsigned int syssleep(unsigned int milliseconds);
int          syssighandler(int signal, void (*newHandler)(void *), void (**oldHandler)(void *));
void         syssigreturn(void *old_sp);
int          syswait(PID_t pid);


// msg.c
PID_t generate_pid(pcb *process);
void  send(pcb *sender, PID_t dest_pid, unsigned long num);
void  recv(pcb *receiver, PID_t *from_pid, unsigned long *dst_num);
void  remove_from_ipc_queues(pcb *process);
void  notify_dependent_processes(pcb *process);
int   is_blocked(pcb *process);


// sleep.c
int  sleep(pcb *process, unsigned int milliseconds);
void tick(void);
void print_sleep_list(void);

// signal.c
int signal(PID_t pid, int signalNumber);
void sigtramp(void (*handler)(void *), void *context);
unsigned long get_sig_mask(int signalNumber);

// tests
void test_memory_manager(void);
void test_dispatcher(void);
void test_ipc(void);
void test_sleep(void);
void test_time_slice(void);

extern pcb pcb_table[];       // The table of process ctrl blocks
extern pcb *idle_process;     // Pointer to the idle process
extern device_t device_table[]; // The device table

#endif
