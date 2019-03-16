/* sprintf.c - sprintf */


#include <xeroslib.h>
#include "xerosPrivLib.h"


static int sprntf(int, unsigned char c);

/*------------------------------------------------------------------------
 *  sprintf  --  format arguments and place output in a string
 *------------------------------------------------------------------------
 */
int sprintf(char *str, char *fmt, ...)
{
	void *argAddr;
	int  *addr; 

	/* Determint the address on the stack where the arguments
           for the format string start.
	*/ 
	addr = ((int *) &fmt);
	argAddr = ++addr;

        _doprnt(fmt, argAddr, sprntf, (int) &str);
	
	/* Make sure the sting is null terminated */
        *str++ = '\0';

        return((int)str);
}

/*------------------------------------------------------------------------
 *  sprntf  --  routine called by doprnt to handle each character
 *              essentially this is the function that prints to the device
 *   input arg cp -> is the id of the device to print to. In this case
 *                   it is the spot in memory to put the character
 *         arg c  -> The character that is being printed
 *------------------------------------------------------------------------
 */
static int sprntf(int cp, unsigned char c)
{
  char **cpp = (char **) cp;
  *(*cpp)++ = c;
  return (int) c;
}


