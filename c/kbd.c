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

static  int     state;               /* the state of the keyboard */
static  int     echoing = 1;         /* indicates if the keyboard is echoing */
static  int     eof_indicator = 0x4; /* stores the current EOF */
static  int     eof_encountered = 0; /* When EOF is encountered always
                                        return EOF from then on, until
                                        keyboard closed/opened again. */

// Contains info about the current read
static reader_metadata_t read_md;
// Contains info about buffered characters from the keyboard
static kb_data_t kb_data;


static unsigned int  convert_to_ascii(unsigned char code);
static int           is_open(void);
static void          finish_read(int ret_value);
static char          get_from_buffer(void);
static int           consume_kernel_buff(void);
static void          put_in_buffer(unsigned char ascii);
static void          put_in_user_buffer(unsigned char ascii);
static int           data_available(void);
static int           data_in_buff(void);
static int           user_buff_full(void);
static void          _test_keyboard(void);
static void           print_buffer(void);
static void          init_generic_keyboard(device_t *device,
                                           int (*opener)(PID_t));


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

    if (is_open()) {
        LOG("Keyboard is already in use!");
        return 0;
    }

    read_md.process = get_active_pcb(pid);
    if (!read_md.process)
        FAIL("Bug. Reading process doesn't exist.");

    echoing = 0;
    enable_irq(KEYBOARD_IRQ, 0);
    kb_data.num_chars = 0;
    kb_data.start = 0;
    return 1;
}

/**
 * Enable interrupts from the echoing keyboard.
 *
 * Return 0 if failed to open keyboard.
 * Return 1 otherwise.
 */
int keyboard_open_echoing(PID_t pid) {
    int ret_value;
    if (!(ret_value = keyboard_open(pid)))
        return ret_value;
    echoing = 1;
    return ret_value;
}


/**
 * Disable interrupts from the keyboard.
 */
int keyboard_close(int fd) {
    enable_irq(KEYBOARD_IRQ, 1);
    read_md.process = NULL;
    read_md.buff = NULL;
    read_md.num_read = 0;
    kb_data.start = 0;
    kb_data.num_chars = 0;
    eof_encountered = 0;
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
 */
void keyboard_read(void *_buff, unsigned int bufflen) {
    LOG("Starting keyboard read");

    if (!is_open())
        FAIL("Bug. Keyboard should be open in order to get here.");

    char *buff = (char *) _buff;

    if (eof_encountered)
        finish_read(0);

    read_md.buff = buff;
    read_md.bufflen = bufflen;
    read_md.num_read = 0;

    if (consume_kernel_buff() == -1)
        read_md.process->state = PROC_BLOCKED;
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
 * Return 1 if the given pid is currently blocked reading from the keyboard.
 */
int blocked_on_keyboard(PID_t pid) {
    if (read_md.process)
        return read_md.process->pid == pid;
    return 0;
}


/**
 * Return the number of bytes that the current blocked process has read.
 */
int get_num_chars_read(void) {
    if (!is_open()) FAIL("Bug.");
    return read_md.num_read;
}


/**
 * Close up the pending read operation.
 */
static void finish_read(int ret_value) {
    LOG("Finishing read");
    read_md.process->ret_value = ret_value;
    enqueue_in_ready(read_md.process);
    stop_read();
}


/**
 * Stop the current read operation.
 */
void stop_read(void) {
    read_md.buff = NULL;
    read_md.bufflen = NULL;
    read_md.num_read = 0;
}


/**
 * Checks to see if there is a process blocked waiting
 * on a read from the keyboard. If there is, it copies any
 * data currently in the kernel buffer into the process' buffer.
 *
 * Otherwise it returns immediately to lower half. 
 */
static void notify_upper_half(void) {
    // If there's no process reading then nothing to do.
    if (!read_md.buff) return;
    consume_kernel_buff();
}


/**
 * Consume characters from the kernel buffer into the user buffer until a
 * carriage return or EOF is encountered.
 *
 * If the number of bytes the process wished to read is met, then the process
 * will get added back to the ready queue.
 *
 * Otherwise, the process stays blocked.
 */
static int consume_kernel_buff(void) {
    char ascii_char;

    while(data_in_buff() && !user_buff_full()) {
        ascii_char = get_from_buffer();

        if (ascii_char == eof_indicator) {
            eof_encountered = 1;
            enable_irq(KEYBOARD_IRQ, 1); // Disable keyboard
            finish_read(0);
            return 0;
        }

        put_in_user_buffer(ascii_char);

        if (ascii_char == ENTER) {
            finish_read(read_md.num_read);
            return 0;
        }
    }

    if (user_buff_full()) {
        finish_read(read_md.num_read);
        return 0;
    }

    // Process should be blocked
    return -1;
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
static int is_open(void) {
    return read_md.process != NULL;
}


/**
 * Add one character to the user buffer.
 */
static void put_in_user_buffer(unsigned char ascii) {
    if (read_md.num_read >= read_md.bufflen)
        FAIL("Bug. Buffer shouldn't overflow.");
    read_md.buff[read_md.num_read++] = ascii;
}


/**
 * Return 1 if the user's buffer is full.
 * Return 0 otherwise.
 */
static int user_buff_full(void) {
    return read_md.num_read >= read_md.bufflen;
}


/* ========================================================
 *                        Lower half
 * ======================================================== */


/**
 * Read a char from the keyboard device, and convert it to ASCII. 
 * Next, place it into the kernel buffer and call the upper half. 
 */
void read_from_keyboard(void) {

    if (!data_available())
        return;

    // Grab data from keyboard port
    unsigned char data = inb(KEYBOARD_DATA_PORT);
    unsigned char ascii = convert_to_ascii(data);

    if (ascii == NOCHAR || ascii == NULL)
        // Can't do anything useful with this.
        return;

    // If we're an echoing keyboard, we'll print
    if (echoing && ascii != eof_indicator)
        kprintf("%c", ascii);

    put_in_buffer(ascii);
}


/**
 * Return 1 if there's data available to be read from the keyboard port.
 * Return 0 otherwise.
 */
static int data_available(void) {
    return inb(KEYBOARD_COMMAND_PORT) & 1;
}


/**
 * Return the index for the ciruclar array.
 */
int get_index(int num) {
    return num % KEYBOARD_BUFFLEN;
}

void inc_start(void) {
    if (kb_data.num_chars <= 0) FAIL("Can't inc start when no chars");
    kb_data.start++;
    kb_data.start %= KEYBOARD_BUFFLEN;
    kb_data.num_chars--;
}

void inc_num_chars(void) {
    if (kb_data.num_chars >= KEYBOARD_BUFFLEN) FAIL("Bug.");
    kb_data.num_chars++;
}


/**
 * Put one character in kernel's buffer.
 *
 * If the buffer is full characters will be dropped.
 */
static void put_in_buffer(unsigned char ascii) {
    if (kb_data.num_chars > KEYBOARD_BUFFLEN)
        FAIL("Bug. Buffer shouldn't overflow.");
    if (kb_data.num_chars == KEYBOARD_BUFFLEN) {
        LOG("Keyboard buffer full, dropping characters!");
        return;
    }
    int index = get_index(kb_data.start + kb_data.num_chars);
    kb_data.buff[index] = ascii;
    inc_num_chars();
    // Tells the upper half that data arrived in the buffer
    notify_upper_half();
}


/**
 * Return one character from the kernel buffer.
 *
 * Caller's responsibility to check that the buffer actually has some data in
 * it before calling this.
 */
static char get_from_buffer(void) {
    if (!data_in_buff())
        FAIL("Bug. Shouldn't call this if there's no data.");
    char ret_value = kb_data.buff[kb_data.start];
    inc_start();
    return ret_value;
}


/**
 * Return 1 if there's data in the kernel buffer.
 * Return 0 otherwise.
 */
static int data_in_buff(void) {
    return kb_data.num_chars > 0;
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
void print_buffer() {
    for (int i = 0; i < KEYBOARD_BUFFLEN; i++) {
        LOCK(
        kprintf("%d", kb_data.buff[i]);
        );
    }
    kprintf("\n");
}

PID_t caller_pid;

void smash_the_keyboard(void) {
    syssleep(1000);
    put_in_buffer(41);
    put_in_buffer(42);
    syssleep(1000);
    ASSERT_INT_EQ(PROC_BLOCKED, get_pcb(caller_pid)->state);
    put_in_buffer('\n');
    syssleep(1000);
}

void type_eof(void) {
    syssleep(1000);
    ASSERT_INT_EQ(PROC_BLOCKED, get_pcb(caller_pid)->state);
    put_in_buffer(71);
    put_in_buffer(eof_indicator);
    syssleep(1000);
}

void test_kb(void) {
    RUN_TEST(_test_keyboard);
}

/**
 * Run some tests for the keyboard.
 */
void _test_keyboard(void) {
    int fd;
    PID_t pid;
    caller_pid = sysgetpid();

    // TODO: Multiple processes opening keyboard, only one should succeed
    // Test open on invalid device number
    ASSERT_INT_EQ(-1, sysopen(12));
    ASSERT_INT_EQ(-1, sysopen(11));
    ASSERT_INT_EQ(-1, sysopen(12));
    ASSERT_INT_EQ(-1, sysclose(12));

    LOG("ATTEMPT TO OPEN BOTH KEYBOARDS");
    ASSERT_INT_NEQ(-1, (fd = sysopen(0)));
    ASSERT_INT_EQ(-1, sysopen(0));
    ASSERT_INT_EQ(-1, sysopen(1));

    ASSERT_INT_EQ(0, sysclose(0));

    ASSERT_INT_NEQ(-1, (fd = sysopen(1)));
    ASSERT_INT_EQ(-1, sysopen(0));
    ASSERT_INT_EQ(0, sysclose(fd));

    LOG("WRITE FAILURE");
    char buff[10];
    ASSERT_INT_EQ(-1, syswrite(20, buff, 10));
    ASSERT_INT_EQ(-1, syswrite(20, buff, 10));

    ASSERT_INT_NEQ(-1, (fd = sysopen(0)));
    ASSERT_INT_EQ(-1, syswrite(fd, buff, 10));
    ASSERT_INT_EQ(0, sysclose(fd));

    LOG("IOCTL WITH INVALID COMMAND");
    ASSERT_INT_NEQ(-1, (fd = sysopen(0)));
    ASSERT_INT_EQ(-1, sysioctl(fd, 60));
    sysclose(fd);

    // Test sysread() when more characters are buffered than
    // there are read requests.
    LOG("READ FROM THE KEYBOARD");
    char read_buff[4];

    ASSERT_INT_NEQ(-1, (fd = sysopen(0)));
    put_in_buffer(65);
    put_in_buffer(65);
    put_in_buffer(65);
    ASSERT_INT_EQ(1, sysread(fd, read_buff, 1));
    ASSERT_INT_EQ(65, read_buff[0]);

    ASSERT_INT_EQ(2, sysread(fd, read_buff, 2));
    ASSERT_INT_EQ(65, read_buff[0]);
    ASSERT_INT_EQ(65, read_buff[1]);

    LOG("==== KEYBOARD TYPING SIMULATION ====");
    put_in_buffer(41);
    put_in_buffer(42);
    put_in_buffer(43);
    put_in_buffer(44);

    put_in_buffer(45);
    put_in_buffer(46);
    put_in_buffer(47);

    ASSERT_INT_EQ(4, sysread(fd, read_buff, 4));
    ASSERT_INT_EQ(41, read_buff[0]);
    ASSERT_INT_EQ(42, read_buff[1]);
    ASSERT_INT_EQ(43, read_buff[2]);
    ASSERT_INT_EQ(44, read_buff[3]);

    ASSERT_INT_EQ(0, sysclose(fd));
    ASSERT_INT_NEQ(-1, (fd = sysopen(1)));

    put_in_buffer(51);
    ASSERT_INT_EQ(1, sysread(fd, read_buff, 1));
    ASSERT_INT_EQ(51, read_buff[0]);

    LOG("==== KEYBOARD TYPING SIMULATION 2 ====");
    ASSERT_INT_EQ(0, sysclose(fd));
    ASSERT_INT_NEQ(-1, (fd = sysopen(1)));

    pid = syscreate(smash_the_keyboard, DEFAULT_STACK_SIZE);

    ASSERT_INT_EQ(3, sysread(fd, read_buff, 4));
    syswait(pid);

    // ========================
    LOG("=== EOF TEST ===");
    // ========================
    ASSERT_INT_EQ(0, sysclose(fd));
    ASSERT_INT_NEQ(-1, (fd = sysopen(0)));

    pid = syscreate(type_eof, DEFAULT_STACK_SIZE);
    ASSERT_INT_EQ(0, sysread(fd, read_buff, 4));
    ASSERT_INT_EQ(71, read_buff[0]);
    ASSERT_INT_EQ(0, sysread(fd, read_buff, 4));
    ASSERT_INT_EQ(0, sysread(fd, read_buff, 4));
    syswait(pid);
}
#pragma GCC diagnostic pop
