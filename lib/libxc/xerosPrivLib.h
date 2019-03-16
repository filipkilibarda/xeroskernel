
#ifndef __XEROSPRIVLIB_H__
#define __XEROSPRIVLIB_H__

int getc(int);
int putc(int, unsigned char);



int _doscan(register char   *fmt,                   /* Format string for the scanf   */
            register int    **argp,                 /* Arguments to scanf            */
            int             (*getch)(int, int *),   /* Function to get a character   */
            void            (*ungetch)(int, int *), /* Function to unget a character */
            int             arg1,                   /* 1st argument to getch/ungetch */
            int             *arg2);                 /* 2nd argument to getch/ungetch */


#endif

