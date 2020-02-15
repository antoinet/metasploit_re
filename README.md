# Metasploit RE

## Description
This is a collection of reverse engineered metasploit payloads. The goal is
to understand how the payloads are generated and executed, especially when
delivered in stages.

For more information on payloads and payload stages, see:
 * https://metasploit.help.rapid7.com/docs/working-with-payloads
 * https://blog.cobaltstrike.com/2012/09/13/a-loader-for-metasploits-meterpreter/

## Using Docker with debugging capabilities for 32bit Linux payloads

In order to analyse and debug 32bit linux payloads in a Docker container, the
following arguments are required:

```
# mkdir /tmp/shared
# docker run -it --rm --name deleteme -v /tmp/shared:/shared --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p2000:2000 ubuntu
# root@51d604030a59:/# apt install -y build-essential libc6-i386 gcc-multilib
```
