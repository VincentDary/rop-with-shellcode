/*
    Date: September 18 2015
    Author: Vincent Dary
    File: StackBasedOverflow.c

    Architecture: Intel x86
    Plateform: GNU/Linux 32 bits

    Description:
    Exploit Writing Tutorial: ROP with Shellcode.
    Vulnerable program to a stack based overflow.

    Compile line:
    gcc -g -m32 -static StackBasedOverflow.c
*/


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int foo(char *str)
{
    char buffer[512];
    printf("[buffer:0x%x] %s\n\n", &buffer, str);
    strcpy(buffer, str);
    return 0;
}

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        sleep(20);
        exit(0);
    }
    else
    {
        foo(argv[1]);
    }
}
