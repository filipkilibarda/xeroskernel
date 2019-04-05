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
#include <stdarg.h>

#define KEY_UP   0x80            /* If this bit is on then it is a key   */
                                 /* up event instead of a key down event */

/* Control codes */
#define LSHIFT  0x2a
#define RSHIFT  0x36
#define LMETA   0x38
#define LCTL    0x1d
#define CAPSL   0x3a

#define ENTER   10              // Enter key ASCII code

/* scan state flags */
#define INCTL           0x01         /* control key is down        */
#define INSHIFT         0x02         /* shift key is down          */
#define CAPSLOCK        0x04         /* caps lock mode             */
#define INMETA          0x08         /* meta (alt) key is down     */
#define EXTENDED        0x10         /* in extended character mode */

#define EXTESC          0xe0         /* extended character escape  */
#define NOCHAR  256                  /* indicates no character     */

static  int     state;               /* the state of the keyboard */
static  int     echoing = 1;         /* indicates if the keyboard is echoing */
static  int     eof_indicator = 0x4; /* stores the current EOF */

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
static int  is_locked(void);
void        put_in_buffer(unsigned char ascii);
int         copy_from_kernel_buff(char *buff, unsigned long bufflen, 
unsigned long num_read);
void        _test_keyboard(void);



/* ========================================================
 *                        Upper half
 * ======================================================== */

/**
 * Enable interrupts from the silent keyboard.
 *
 * Return 0 if failed to open keyboard.
 * Return 1 otherwise.
 */
int keyboard_open(PID_t pid) {

    if (is_locked()) {
        LOG("Keyboard is already in use!, holding_pid is %d\n", holding_pid);
        return 0;
    }

    echoing = 0;
    enable_irq(KEYBOARD_IRQ, 0);
    holding_pid = pid;
    return 1;
}

/**
 * Enable interrupts from the echoing keyboard.
 *
 * Return 0 if failed to open keyboard.
 * Return 1 otherwise.
 */
int keyboard_open_echoing(PID_t pid) {

    if (is_locked()) {
        LOG("Keyboard is already in use!, holding_pid is %d\n", holding_pid);
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
int keyboard_close(int fd) {
    enable_irq(KEYBOARD_IRQ, 1);
    holding_pid = 0;
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
 * Returns: 
 * -1 if process blocked
 * 0 if EOF was pressed
 * 1 if read finished successfully 
 */
int keyboard_read(void *_buff, unsigned int bufflen) {
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

    if (result == -2) {
        reading_process->ret_value = 0;
        enqueue_in_ready(reading_process);
        return 0;
    } 

    read_md.num_read += result;
    
    // if num_read is less than bufflen, block the process 
    // and update the read_md struct to reflect # read so far
    if (read_md.num_read < bufflen) {
        reading_process->state = PROC_BLOCKED;
        return -1;
    } else {
        reading_process->ret_value = read_md.num_read;
        enqueue_in_ready(reading_process);
        return 1;
    }

}


/**
 * Interface for non-standard interactions with the keyboard device.
 * 
 * Returns 0 on success, -1 on failure. 
 */
int keyboard_ioctl(int command, va_list ap) {
    int new_eof;

    switch(command) {
        case 53:
            // Sets new EOF 
            new_eof = va_arg(ap, int);
            eof_indicator = new_eof;
            break;
        case 55:
            // Turns off echoing
            echoing = 0;
            break;
        case 56:
            // Turns on echoing
            echoing = 1;
            break;
        default:
            return -1;
    }

    return 0;
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
 * Return 1 if the keyboard device is currently locked (in use by some process)
 * Return 0 otherwise.
 */
static int is_locked(void) {
    if (holding_pid != 0) return 1;
    return 0;
}


/**
 * Checks to see if there is a process blocked waiting
 * on a read from the keyboard. If there is, it copies any
 * data currently in the kernel buffer into the process' buffer.
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
        if (result == -2) {
            read_md.process->ret_value = 0;
            enqueue_in_ready(read_md.process);
        }
        else if (result != -1) {
            read_md.num_read += result;
            if (read_md.num_read == read_md.bufflen) {
                enqueue_in_ready(read_md.process);
            }
        } 
    }
}

/**
 * Copies data from the kernel buffer into the process 
 * provided buffer. 
 * 
 * Returns the number of bytes read into the buffer from
 * the kernel buffer, -1 if enter was pressed, or -2 if 
 * current EOF indicator was pressed.  
 */
int copy_from_kernel_buff(char *buff, unsigned long bufflen, 
unsigned long num_read) {

    int bytes_read = 0;

    for (int i = 0; i < KEYBOARD_BUFFLEN; i++) {
        if (kernel_buff[i] != NULL) {
            // We don't want to put eof into buffer
            if (kernel_buff[i] != eof_indicator) {
                buff[num_read + i] = kernel_buff[i];
                bytes_read++;
            }

            char read_char = kernel_buff[i];
            kernel_buff[i] = NULL;

            if (read_char == ENTER) {
                read_md.process->ret_value = read_md.num_read + bytes_read;
                enqueue_in_ready(read_md.process);
                return -1;
            } else if (read_char == eof_indicator) {
                // Disable the keyboard at this point, 
                // return indication that EOF was entered
                enable_irq(KEYBOARD_IRQ, 1);
                // Set FDT entry to NULL
                pcb *process = get_pcb(holding_pid);
                // NOTE: this is hacky as hell 
                process->fdt[0].device = NULL;
                process->fdt[1].device = NULL;
                holding_pid = 0;

                return -2;
            }

        } else {
            // If we reach this branch, there
            // wasn't anything in the kernel buffer.
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

    if (data_available()) {
        // Grab data from keyboard port
        unsigned char data = inb(KEYBOARD_DATA_PORT);

        // Convert character to ASCII
        unsigned char ascii = convert_to_ascii(data);
        
        // If we're an echoing keyboard, we'll print 
        if (echoing && ascii != NOCHAR && ascii != eof_indicator) 
        kprintf("%c", ascii);

        // Put the ASCII character into the kernel buffer
        if (ascii != NOCHAR) {
            //kprintf("Putting %c into the buffer\n", ascii);
            put_in_buffer(ascii);
            // Tells the upper half that data arrived in the buffer
            notify_upper_half();
        }
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


/**
 * Returns the correct ASCII representation of a given scancode
 * Lots of bit **wizardry**
 */
unsigned int convert_to_ascii(unsigned char code) {
   unsigned int    ch;
  
  if (code & KEY_UP) {
    switch (code & 0x7f) {
    case LSHIFT:
    case RSHIFT:
      state &= ~INSHIFT;
      break;
    case CAPSL:
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
    return NOCHAR;
  case CAPSL:
    state |= CAPSLOCK;
    return NOCHAR;
  case LCTL:
    state |= INCTL;
    return NOCHAR;
  case LMETA:
    state |= INMETA;
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
    char buff[16];
    kprintf("Doing a sysread\n");
    sysread(fd, buff, 16);
    sysclose(fd);
    kprintf("Printing what was typed!\n");
    sysputs(buff);
    return;
}

void test_kb(void) {
    RUN_TEST(_test_keyboard);
}

/**
 * Run some tests for the keyboard.
 */
void _test_keyboard(void) {
    // TODO: Multiple attempts to open keyboard should fail
    // TODO: Attempt to open both keyboard devices should fail
    // TODO: Multiple processes opening keyboard, only one should succeed
    // Test open on invalid device number
    int sysopen_result = sysopen(12);
    ASSERT_INT_EQ(-1, sysopen_result);

    // Test syswrite to an invalid file descriptor
    char buff[10];
    int syswrite_result = syswrite(20, buff, 10);
    ASSERT_INT_EQ(-1, syswrite_result);

    // Test sysioctl() with an invalid command number
    int fd = sysopen(0);
    int sysioctl_result = sysioctl(fd, 60);
    ASSERT_INT_EQ(-1, sysioctl_result);
    sysclose(fd);

    // Test sysread() when more characters are buffered than
    // there are read requests. 
    fd = sysopen(0);
    sysputs("Please begin pounding the keyboard (press x first)\n");
    syssleep(3000);
    char read_buff[1];
    int length = sysread(fd, read_buff, 1);
    ASSERT_INT_EQ(1, length);
    ASSERT(read_buff[0] == 'x', "Oops");

    PID_t test_proc = syscreate(reader_process, DEFAULT_STACK_SIZE);
    syswait(test_proc);
    kprintf("Ending test!\n");
}
