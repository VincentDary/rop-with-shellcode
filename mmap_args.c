/*
    Date: September 18 2015
    Author: Vincent Dary
    File: mmap_args.c

    Architecture: Intel x86
    Plateform: GNU/Linux 32 bits

    Description:
    Exploit Writing Tutorial: ROP with Shellcode.
    Give mmap combinated constant arguments.
*/

#include <sys/mman.h>
#include <stdio.h>

void main(void)
{
    printf("PROT_EXEC | PROT_WRITE: 0x%x\nMAP_ANONYMOUS | MAP_PRIVATE: 0x%x\n", PROT_EXEC|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE);
}
