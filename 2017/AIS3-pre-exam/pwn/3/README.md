# generate shell code
```shell=
nasm -f elf64 pflag.asm -o pflag.o
c=0;for i in $(objdump -d pflag.o | grep "^ " | cut -f2); do echo -n \\x$i; c=$(($c+1)); done
gcc testShellCode.c -o testShellCode.out -z execstack
```
