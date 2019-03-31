/**
 * kbd.c: Keyboard device driver
 *
 * The keyboard can only be opened by one process at a time and only one type
 * of keyboard can be open.
 *
 * Also, since our kernel doesn't support async reads, we can have only one
 * pending read request to the keyboard driver at a time.
 *
 * This simplifies the design a lot, because we don't have to track the state
 * of multiple read requests. Thus a lot of state can be stored in simple global
 * variables.
 */

#include <i386.h>
#include <kbd.h>
#include <test.h>

#define KEY_UP   0x80            /* If this bit is on then it is a key   */
                                 /* up event instead of a key down event */

/* Control code */
#define LSHIFT  0x2a
#define RSHIFT  0x36
#define LMETA   0x38
#define LCTL    0x1d
#define CAPSL   0x3a

/* scan state flags */
#define INCTL           0x01    /* control key is down          */
#define INSHIFT         0x02    /* shift key is down            */
#define CAPSLOCK        0x04    /* caps lock mode               */
#define INMETA          0x08    /* meta (alt) key is down       */
#define EXTENDED        0x10    /* in extended character mode   */

#define EXTESC          0xe0    /* extended character escape    */
#define NOCHAR  256

static  int     state;       /* the state of the keyboard */
static  int     echoing = 1; /* indicates if the keyboard is echoing or not*/

// Buffer belonging to the process that's currently executing a sysread.
// If no pending sysread, this is NULL;
static char *user_buff;
static char user_bufflen;

// The pid that's currently holding the keyboard device
// 0 if no process has opened the keyboard
static PID_t holding_pid;

// Contains info about the current read
static reader_metadata_t read_md;

// Buffer belonging to the kernel. Data from keyboard is stuffed into here.
// If there's a pending sysread, upper half will remove data from here.
// Otherwise, data will pile up.
static char kernel_buff[KEYBOARD_BUFFLEN];


/*  Normal table to translate scan code  */
unsigned char   kbcode[] = { 0,
          27,  '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',  '9',
         '0',  '-',  '=', '\b', '\t',  'q',  'w',  'e',  'r',  't',
         'y',  'u',  'i',  'o',  'p',  '[',  ']', '\n',    0,  'a',
         's',  'd',  'f',  'g',  'h',  'j',  'k',  'l',  ';', '\'',
         '`',    0, '\\',  'z',  'x',  'c',  'v',  'b',  'n',  'm',
         ',',  '.',  '/',    0,    0,    0,  ' ' };

/* captialized ascii code table to tranlate scan code */
unsigned char   kbshift[] = { 0,
           0,  '!',  '@',  '#',  '$',  '%',  '^',  '&',  '*',  '(',
         ')',  '_',  '+', '\b', '\t',  'Q',  'W',  'E',  'R',  'T',
         'Y',  'U',  'I',  'O',  'P',  '{',  '}', '\n',    0,  'A',
         'S',  'D',  'F',  'G',  'H',  'J',  'K',  'L',  ':',  '"',
         '~',    0,  '|',  'Z',  'X',  'C',  'V',  'B',  'N',  'M',
         '<',  '>',  '?',    0,    0,    0,  ' ' };

unsigned char   kbctl[] = { 0,
           0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
           0,   31,    0, '\b', '\t',   17,   23,    5,   18,   20,
          25,   21,    9,   15,   16,   27,   29, '\n',    0,    1,
          19,    4,    6,    7,    8,   10,   11,   12,    0,    0,
           0,    0,   28,   26,   24,    3,   22,    2,   14,   13 };


static void init_generic_keyboard(device_t *device, int (*opener)(PID_t));
static char get_char(void);
static int  is_locked(void);
static int  read_from_lower_half(char *buff, unsigned int bufflen);
void        put_in_buffer(unsigned char ascii);
int         copy_from_kernel_buff(char *buff, unsigned long bufflen, 
unsigned long num_read);
void _test_keyboard(void);



/* ========================================================
 *                        Upper half
 * ======================================================== */

/**
 * Enable interrupts from the keyboard.
 *
 * Return 0 if failed to open keyboard.
 * Return 1 otherwise.
 */
int keyboard_open(PID_t pid) {

    if (is_locked()) {
        LOG("Keyboard is already in use!");
        return 0;
    }

    echoing = 0;
    enable_irq(KEYBOARD_IRQ, 0);
    holding_pid = pid;
    return 1;
}

/**
 * Enable interrupts from the keyboard.
 *
 * Return 0 if failed to open keyboard.
 * Return 1 otherwise.
 */
int keyboard_open_echoing(PID_t pid) {

    if (is_locked()) {
        LOG("Keyboard is already in use!");
        return 0;
    }

    echoing = 1;
    enable_irq(KEYBOARD_IRQ, 0);
    holding_pid = pid;
    return 1;
}


/**
 * Disable interrupts from the keyboard.
 *
 * TODO: Fail if keyboard is already closed? (return 0)
 */
int keyboard_close(void) {
    enable_irq(KEYBOARD_IRQ, 1);
    holding_pid = 0;
    LOG("Keyboard closed!");
    return 1;
}


/**
 * Writing to keyboard is not supported so return -1.
 */
int keyboard_write(void *void_buff, unsigned int bufflen) {
    return -1;
}


/**
 * Read from the keyboard. This function is referenced in the keyboard device
 * structure and constitutes the upper half of the keyboard driver.
 *
 * TODO: We *might* need two upper halves for the two types of keyboard drivers.
 * TODO: I feel like the device driver doesn't need to know about processes.
 *       It should just know about buffers?
 */
int keyboard_read(void *_buff, unsigned int bufflen) {
    kprintf("In keyboard read, setting things up!\n");
    pcb *reading_process = get_pcb(holding_pid);
    ASSERT(reading_process != NULL, "did not get the process correctly\n");
    char *buff = (char *) _buff;
    read_md.process = reading_process;
    read_md.buff = buff;
    read_md.bufflen = bufflen;
    read_md.num_read = 0;

    // result will indicate number of bytes read from kernel buffer
    int result = 
    copy_from_kernel_buff(read_md.buff, read_md.bufflen, read_md.num_read);    
    read_md.num_read += result;
   
    // if num_read is less than bufflen, block the process 
    // and update the read_md struct to reflect # read so far
    if (read_md.num_read < bufflen) {
        kprintf("Blocking\n");
        reading_process->state = PROC_BLOCKED;
    } else {
        enqueue_in_ready(reading_process);
    }

    
}


/**
 * Interface for non-standard interactions with the keyboard device.
 */
int keyboard_ioctl(int command, ...) {
    return 0; // TODO
}


/**
 * Initialize the given device structure with attributes of the quiet
 * keyboard (the keyboard that doesn't echo).
 */
void init_quiet_keyboard(device_t device_table[], int index) {
    init_generic_keyboard(&device_table[index], keyboard_open);
}


/**
 * Initialize the given device structure with attributes of the echo keyboard.
 */
void init_echo_keyboard(device_t device_table[], int index) {
    init_generic_keyboard(&device_table[index], keyboard_open_echoing);
}


/**
 * Initialize functionality that's shared between both types of keyboards.
 */
static void init_generic_keyboard(device_t *device, int (*opener)(PID_t)) {
    device->open  = opener;
    device->close = keyboard_close;
    device->write = keyboard_write;
    device->read  = keyboard_read;
    device->ioctl = keyboard_ioctl;
}


/**
 * Grab a character from the lower half buffer.
 * Called from the upper half.
 */
static char get_char(void) {
    return 0; // TODO
}


/**
 * Return 1 if the keyboard device is currently locked (in use by some process)
 * Return 0 otherwise.
 */
static int is_locked(void) {
    return holding_pid != 0;
}


/**
 * Read up to bufflen bytes from the lower half and return how many bytes
 * were read.
 */
static int read_from_lower_half(char *buff, unsigned int bufflen) {
    return 0; // TODO
}

/**
 * Checks to see if there is a process blocked waiting
 * on a read from the keyboard. If there is, it copies the
 * data from the kernel buffer into the process' buffer.
 * If the number of bytes the process wished to read is 
 * met, then the process will get added back to the ready queue. 
 * Otherwise, the process stays blocked. 
 *  
 * Otherwise it returns immediately to lower half. 
 */
void notify_upper_half(void) {
    if (read_md.process != NULL) {
        // result is number of bytes copied from kernel buffer
        int result = 
        copy_from_kernel_buff(read_md.buff, read_md.bufflen, read_md.num_read);
        // if we've now read enough bytes into our buffer, add to ready
        read_md.num_read += result;
        kprintf("Num_read is: %d\n", read_md.num_read);
        if (read_md.num_read == read_md.bufflen) {
            kprintf("Enqueueing back, read enough!\n");
            enqueue_in_ready(read_md.process);
        }
    }
}

/**
 * Copies data from the kernel buffer into the process 
 * provided buffer. 
 * 
 * Returns the number of bytes read into the buffer from
 * the kernel buffer.
 */
int copy_from_kernel_buff(char *buff, unsigned long bufflen, 
unsigned long num_read) {
    int num_to_copy = (bufflen - num_read < 4) ? 
    bufflen - num_read : KEYBOARD_BUFFLEN;
    int bytes_read = 0;

    for (int i = 0; i < num_to_copy; i++) {
        if (kernel_buff[i] != NULL) {
            buff[num_read + i] = kernel_buff[i];
            kernel_buff[i] = NULL;
            bytes_read++;
            //kprintf("Read a byte!\n");
        } else {
            break;
        }
    }

    return bytes_read;
}

/* ========================================================
 *                        Lower half
 * ======================================================== */


int data_available(void) {
    return inb(KEYBOARD_COMMAND_PORT) & 1;
}


/**
 * Read a char from the keyboard device, and convert it to ASCII. 
 * Next, place it into the kernel buffer and call the upper half. 
 * 
 */
void read_char(void) {

    // Grab data from keyboard port
    unsigned char data = inb(KEYBOARD_DATA_PORT);

    // Convert character to ASCII
    unsigned char ascii = convert_to_ascii(data);
    
    // If we're an echoing keyboard, we'll print 
    if (echoing && ascii != NOCHAR) kprintf("%c", ascii);

    // Put the ASCII character into the kernel buffer
    if (ascii != NOCHAR) {
        kprintf("Putting %c into the buffer\n", ascii);
        put_in_buffer(ascii);
        // Tells the upper half that data arrived in the buffer
        notify_upper_half();
    }
}

/**
 * Places the provided ASCII character into 
 * the kernel's buffer. 
 */
void put_in_buffer(unsigned char ascii) {
    for (int i = 0; i < KEYBOARD_BUFFLEN; i++) {
        if (kernel_buff[i] == NULL) {
            kernel_buff[i] = ascii;
            break;
        }
    }
}


static int
extchar(code)
unsigned char   code;
{
        state &= ~EXTENDED;
}


/**
 * Returns the correct ASCII representation of a given scancode
 * Lots of bit **wizardry**
 */
unsigned int convert_to_ascii(unsigned char code) {
   unsigned int    ch;
  
  if (state & EXTENDED)
    return extchar(code);
  if (code & KEY_UP) {
    switch (code & 0x7f) {
    case LSHIFT:
    case RSHIFT:
      state &= ~INSHIFT;
      break;
    case CAPSL:
      //kprintf("Capslock off detected\n");
      state &= ~CAPSLOCK;
      break;
    case LCTL:
      state &= ~INCTL;
      break;
    case LMETA:
      state &= ~INMETA;
      break;
    }
    
    return NOCHAR;
  }
  
  
  /* check for special keys */
  switch (code) {
  case LSHIFT:
  case RSHIFT:
    state |= INSHIFT;
    //kprintf("shift detected!\n");
    return NOCHAR;
  case CAPSL:
    state |= CAPSLOCK;
    //kprintf("Capslock ON detected!\n");
    return NOCHAR;
  case LCTL:
    state |= INCTL;
    return NOCHAR;
  case LMETA:
    state |= INMETA;
    return NOCHAR;
  case EXTESC:
    state |= EXTENDED;
    return NOCHAR;
  }
  
  ch = NOCHAR;
  
  if (code < sizeof(kbcode)){
    if ( state & CAPSLOCK )
      ch = kbshift[code];
	  else
	    ch = kbcode[code];
  }
  if (state & INSHIFT) {
    if (code >= sizeof(kbshift))
      return NOCHAR;
    if ( state & CAPSLOCK )
      ch = kbcode[code];
    else
      ch = kbshift[code];
  }
  if (state & INCTL) {
    if (code >= sizeof(kbctl))
      return NOCHAR;
    ch = kbctl[code];
  }
  if (state & INMETA)
    ch += 0x80;
  return ch;
}


/* ========================================================
 *                        Tests
 * ======================================================== */


void reader_process(void) {
    kprintf("Opening non-echoing keyboard\n");
    int fd = sysopen(0);
    char *buff = kmalloc(16);
    kprintf("Doing a sysread\n");
    int result = sysread(fd, buff, 16);
    kprintf("Printing what was typed!, starts with %c\n", buff[0]);
    sysputs(buff);
    kfree(buff);
    return;
}

void test_kb(void) {
    PID_t test_proc = syscreate(reader_process, DEFAULT_STACK_SIZE);
    syswait(test_proc);
    kprintf("Ending test!\n");
}

/**
 * Run some tests for the keyboard.
 */
void _test_keyboard(void) {
    // TODO: Multiple attempts to open keyboard should fail
    // TODO: Attempt to open both keyboard devices should fail
    // TODO: Multiple processes opening keyboard, only one should succeed
    
}
