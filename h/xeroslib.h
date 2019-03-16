
#ifndef __XEROSLIB_H__
#define __XEROSLIB_H__

/* This is the list of functions available to the Xeros kernel writer. These
 * functions are all defined in the lib/libxc directory. The meaning and usage
 * of these functions match those of the standard C library or standard Unix
 * system calls. You can determine how to use them by using the man command on
 * your favourite Unix machine or just googleing it.
 */


int    abs(int arg);
double atof(char *p);
int    atoi(register char *p);
long   atol(register char *p);

char *ecvt(double arg, int ndigits, int *decpt, int *sign);
char *fcvt(double arg, int ndigits, int *decpt, int *sign);
char *fgets(int dev, char *s, int n);
int   fprintf(int dev, char *fmt, int args);
int   fputs(register char *s,  register int dev);
char *gets(char *s);
char *index(char *sp, char c);
void  memset(void *pch, int c, int len);
int   printf(char *fmt, int args);
int   puts(register char *s);
void  qsort(char *a, unsigned n, int es, int (*qcmp)(void *, void *));
void  srand(unsigned int x);
int   rand(void);
char *rindex(register char *sp, register char c);
int   scanf(char * fmt, char args);
int   fscanf(int dev, char *fmt, int args);
int   sscanf(char * str, char *fmt, int args);
int   sprintf(char *str, char *fmt, ...);
char *strcat(register char *s1, register char *s2);
int   strcmp(register char *s1, register char *s2) ;
char *strcpy(char *s1, char *s2);
int   strlen(register char *s);
char *strncat(register char *s1, register char *s2, register int n);
int   strncmp(register char *s1, register char *s2, register int n);
char *strncpy(register char *s1, register char *s2, register int n);
void  swab(register short *pf, register short *pt, register int n);
void  blkcopy(const void *, void *, int);

extern char _ctype_[];

double ldexp(double, int);
double modf(double, double *);


/* The following function is used by kprintf() but it cannot be used in the 
 * CPSC 415 code added by students for their assignments.
 */


void _doprnt(char *fmt,                             /* Format string for printf        */
             int *args,                             /* Arguments to printf             */
             int (*func)(int, unsigned char),      /* Function to put a character     */
             unsigned int farg);                    /* Arg to function                 */

#endif
