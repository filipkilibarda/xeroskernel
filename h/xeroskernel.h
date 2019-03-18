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

/* Functions defined by startup code */


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
extern void kmeminit(void);
extern int  kfree(void *ptr);
extern void *kmalloc(size_t size);
unsigned long total_free_memory(void);
int within_memory_bounds(unsigned long address);


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
    int ret_value;
    int priority;
    int sleep_time;
    struct pcb_s *next;
    pcb_queue sender_queue;
    pcb_queue receiver_queue;
    PID_t receiving_from_pid;
    PID_t sending_to_pid;
};
typedef struct pcb_s pcb;

struct safety_zone_s {
    long one;
    long two;
};
typedef struct safety_zone_s safety_zone;


// Syscall request IDs
#define SYSCALL_CREATE 0
#define SYSCALL_YIELD 1
#define SYSCALL_STOP 2
#define SYSCALL_RUNNING 3
#define SYSCALL_GET_PID 4
#define SYSCALL_PUTS 5
#define SYSCALL_KILL 6
#define SYSCALL_SET_PRIO 7
#define SYSCALL_SEND 8
#define SYSCALL_RECV 9
#define TIMER_INT 10
#define SYSCALL_SLEEP 11

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

void        contextinit(void);
extern void pcb_init(void);
int         contextswitch(pcb *process);
extern void dispatch(void);
void        reset_pcb_table(void);

// disp.c
void      init_ipc(void);
int       kill(PID_t pid);
pcb_queue queue_constructor(void);
pcb       *get_ready_queue(int priority);
int       queue_is_empty(pcb_queue *queue);
int       pull_from_queue(pcb_queue *queue, pcb *process);
void      enqueue(pcb_queue *queue, pcb *process);
void      enqueue_in_ready(pcb *process);
void      enqueue_in_stopped(pcb *process);
pcb       *dequeue(pcb_queue *queue);
pcb       *dequeue_from_ready(void);
pcb       *dequeue_from_stopped(void);
int       num_ready_processes(void);
int       get_num_stopped_processes(void);
int       get_state(int pid);
pcb       *get_pcb(PID_t pid);
int       get_pcb_index(PID_t pid);
int       is_stopped(pcb *process);
void      wait_for_free_pcbs(int num_pcbs);
void      print_ready_queue(void);
void      print_stopped_queue(void);
void      print_pcb_table(void);
void      print_queue(pcb_queue *queue);
void      dump_queues(void);
void      validate_stopped_queue(void);

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
int          syskill(PID_t pid);
int          syssetprio(int priority);
int          syssend(PID_t dest_pid, unsigned long num);
int          sysrecv(PID_t *from_pid, unsigned long * num);
unsigned int syssleep(unsigned int milliseconds);

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

// tests
void test_memory_manager(void);
void test_dispatcher(void);
void test_ipc(void);
void test_sleep(void);
void test_time_slice(void);

// It helps if this is accessible from other modules.
pcb pcb_table[MAX_PCBS];

// Pointer to the idle process
pcb *idle_process;

#endif
