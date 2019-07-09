# Metasploit RE

## Stager Protocol

See:
 * https://blog.cobaltstrike.com/2012/09/13/a-loader-for-metasploits-meterpreter/

## Using Docker with debugging capabilities
```
# mkdir /tmp/shared
# docker run -it --rm --name deleteme -v /tmp/shared:/shared --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p2000:2000 ubuntu
# root@51d604030a59:/# apt install -y build-essential libc6-i386
```
