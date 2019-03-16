/* fprintf.c - fprintf */

#define	OK	1
#include <xeroslib.h>
#include "xerosPrivLib.h"

/*------------------------------------------------------------------------
 *  fprintf  --  print a formatted message on specified device (file)
 *------------------------------------------------------------------------
 */
int fprintf(int dev, char *fmt, int args) {
  
  void *argAddr;
  int * addr;
  
  addr = ((int *) &fmt);
  argAddr = addr++;
  
  _doprnt(fmt, argAddr, putc, dev);
  return OK;
}
