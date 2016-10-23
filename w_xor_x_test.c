/*
    Date: October 05 2018
    Author: Vincent Dary
    File: w_xor_x_test.c

    Architecture: Intel x86
    Plateform: GNU/Linux 32 bits

    Description:
    Test the following memory restrictions on a memory mapping.

      - W^X write xor execute
      - X!->W execute never write
      - W!->X write never execute

    Compile line:
      gcc -m32 -z noexecstack w_xor_x_test.c
*/

#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define   MEM_PAGE_SIZE       4096

#define   EXEC_CODE_LENGHT    3

unsigned char *x86_exec_code = "\x31\xf6" // xor esi, esi
                               "\xc3";    // ret

sigjmp_buf point;


void segfault_sigaction(int signal, siginfo_t *si, void *arg)
{
    printf("[i] Caught segfault at address 0x%08x.\n", si->si_addr);
    longjmp(point, 1);
}


int set_segfault_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);

    sa.sa_sigaction = segfault_sigaction;
    sa.sa_flags   = SA_SIGINFO | SA_NODEFER;

    if ( sigaction(SIGSEGV, &sa, NULL) == -1 )
    {
        perror("[-] Error setting segfault handler : ");
        return -1;
    }

    return 0;
}


void * create_memory_page(int permission)
{
      int page_size = 0;
      void *mem = NULL;

      page_size = getpagesize();

      mem = mmap(NULL, page_size, permission, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

      if (mem == MAP_FAILED)
      {
          perror("      [-] Fail to create memory page : ");
          return NULL;
      }

      return mem;
}


int write_exec_code(void *addr)
{
      if (setjmp(point) == 0)
      {
          memcpy(addr, x86_exec_code, EXEC_CODE_LENGHT);
          printf("      [+] WRITE memory page code has succeeded.\n");
      }
      else
      {
          printf("      [-] WRITE memory page code has failed.\n");
          return -1;
      }

      return 0;
}

int execute_code(void *addr)
{
    void *(*runtime_code)(void) = NULL;
    register int esi asm("esi");

    runtime_code = addr;
    esi = -1;

    if (setjmp(point) == 0)
    {
        runtime_code();
        printf("      [+] EXECUTE memory page code has succeeded.\n");
    }
    else
    {
        printf("      [-] EXECUTE memory page code has failed.\n");
        return -1;
    }

    if (esi == 0)
      printf("      [+] Executable code successfully executed.\n");

    return 0;
}


int test_create_wx_mpage(void)
{
    void *mem = NULL;
    void *(*runtime_code)(void) = NULL;
    register int esi asm("esi");

    puts("[i] Test x^w");

    mem = create_memory_page(PROT_EXEC|PROT_WRITE);
    if (mem == NULL)
      return -1;

    printf("      [+] New W+X memory page at 0x%08x.\n", mem);

    if ( write_exec_code(mem) == -1 )
      return -1;

    if ( execute_code(mem) == -1 )
      return -1;

    return 0;
}

int test_change_mpage_perm_w_to_x(void)
{
    void *mem = NULL;
    void *(*runtime_code)(void) = NULL;
    register int esi asm("esi");

    puts("[i] Test W->X");

    mem = create_memory_page(PROT_WRITE);
    if (mem == NULL)
      return -1;

    printf("      [+] New W memory page at 0x%08x.\n", mem);

    if ( write_exec_code(mem) == -1 )
      return -1;

    printf("      [+] Change memory page permission to X.\n");

    mprotect(mem, MEM_PAGE_SIZE, PROT_EXEC);

    if ( execute_code(mem) == -1 )
      return -1;

    return 0;
}


int test_change_mpage_perm_x_to_w(void)
{
    void *mem = NULL;
    void *(*runtime_code)(void) = NULL;
    register int esi asm("esi");

    puts("[i] Test x->w");

    mem = create_memory_page(PROT_EXEC);
    if (mem == NULL)
      return -1;

    printf("      [+] New X memory page at 0x%08x.\n", mem);

    printf("      [+] Change memory page permission to W.\n");

    mprotect(mem, MEM_PAGE_SIZE, PROT_WRITE);

    if ( write_exec_code(mem) == -1 )
      return -1;

    return 0;
}



int main(int argc, char * argv[])
{
    if (set_segfault_handler() < 0)
        return -1;

    if (test_create_wx_mpage() < 0)
        return -1;

    if (test_change_mpage_perm_w_to_x() < 0)
        return -1;

    if (test_change_mpage_perm_x_to_w() < 0)
        return -1;

    return 0;
}
