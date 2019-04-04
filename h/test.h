/**
 * Largely inspired by https://github.com/siu/minunit, some chunks of code
 * below are pretty much copied from that repo.
 *
 * Provides functionality typically used in tests. Asserts, fails, logging.
 *
 * Macros used outside this file:
 * ==============================
 *  LOG(msg, ...):
 *      Prints a log message to console only if in TESTING mode.
 *  STOP():
 *      Stop the cpu by disabling interrupts and halting the CPU.
 *  ASSERT(condition, msg):
 *      Check that condition is true, otherwise print the message.
 *  ASSERT_INT_EQ(a, b):
 *      Check that the two integers are equal. Stop cpu otherwise.
 *  ASSERT_INT_NEQ(a, b):
 *      Check that the two integers are not equal. Stop cpu otherwise.
 *  FAIL(msg):
 *      Stop cpu and print the given message.
 */

#ifndef TEST_H
#define TEST_H

#include <xeroslib.h>

// This turns on the tests
#define TESTING
// This makes it such that successful assertions are logged
#define PRINT_ASSERT_CONFIRMATION

// Helper for including variadic args in macros
#define VA_ARGS(...) , ##__VA_ARGS__


/**
 * Stop the CPU by disabling interrupts and halting the CPU so whatever is
 * running can't be preempted.
 **/
#define STOP do {\
    __asm __volatile(" \
        cli \n\
        hlt \n\
    ":::);\
} while(0)

/**
 * Print a starting message, run the given function pointer, then print a
 * closing message.
 **/
#ifdef TESTING
#define RUN_TEST(test_function) do {\
    LOG("=============== Starting test! ===============");\
    test_function();\
    LOG("=============== Finishing test! ===============");\
} while(0)
#else
#define RUN_TEST(test_function)
#endif


#define FAIL(message) do {\
    __asm __volatile("cli":::);\
    kprintf("%s failed:\n\t%s:%d: %s\n",\
            __func__, __FILE__, __LINE__, message);\
    STOP;\
} while(0)


#define FAILL(message, ...) do {\
    __asm __volatile("cli":::);\
    char msg[120];\
    sprintf(msg, message, __VA_ARGS__);\
    FAIL(msg);\
    STOP;\
} while(0)


/**
 * Lock the CPU by disabling interrupts while the given code runs.
 **/
#define LOCK(code) do {\
    __asm __volatile("pushf; cli":::);\
    code;\
    __asm __volatile("popf":::);\
} while(0)


/**
 * Lock the CPU by preventing interrupts. Restore the IF flag back to what it
 * was before this was called.
 **/
#ifdef TESTING
#define LOG(message, ...) do {\
    __asm __volatile("pushf; cli":::);\
    char info[80];\
    char spaces[80];\
    memset(spaces, 32, 80);\
    sprintf(info, "%s  %s:%d:  ", __FILE__, __func__, __LINE__);\
    int num_spaces = 35 - strlen(info);\
    spaces[num_spaces > 0 ? num_spaces : 0] = 0;\
    strcat(info, spaces);\
    kprintf(info+5); /* +5 Super hack to remove ../c/ from filepath */\
    kprintf(message VA_ARGS(__VA_ARGS__));\
    kprintf("\n");\
    __asm __volatile("popf":::);\
} while(0)
#else
#define LOG(message, ...)
#endif


#ifdef PRINT_ASSERT_CONFIRMATION
#define LOG_ASSERTION_SUCCESS(message, ...) do {\
    LOG(message VA_ARGS(__VA_ARGS__));\
} while(0)
#else
#define LOG_ASSERTION_SUCCESS(message, ...)
#endif


/**
 * Check the given condition and stop the CPU (infinite loop) if it fails. E.g.,
 *      ASSERT(1 != 1, "Never passes")
 */
#define ASSERT(test, message) do {\
    if (!(test)) {\
        FAIL(message);\
    }\
} while(0)


#define ASSERT_INT_EQ(expected, result) do {\
    int minunit_tmp_e;\
    int minunit_tmp_r;\
    minunit_tmp_e = (expected);\
    minunit_tmp_r = (result);\
    if (minunit_tmp_e != minunit_tmp_r) {\
        FAILL("%d expected but was %d", minunit_tmp_e, minunit_tmp_r);\
    } else {\
        LOG_ASSERTION_SUCCESS("Got %d as expected", expected);\
    }\
} while(0)


#define ASSERT_INT_NEQ(expected, result) do {\
    int minunit_tmp_e;\
    int minunit_tmp_r;\
    minunit_tmp_e = (expected);\
    minunit_tmp_r = (result);\
    if (minunit_tmp_e == minunit_tmp_r) {\
        FAILL("%d: didn't expect %d", minunit_tmp_e, minunit_tmp_r);\
    } else {\
        LOG_ASSERTION_SUCCESS("NEQ %d assertion passed!", expected);\
    }\
} while(0)

#endif
