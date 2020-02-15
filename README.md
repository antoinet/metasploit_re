# Metasploit RE

## Description
This is a collection of reverse engineered metasploit payloads. The goal is
to understand how the payloads are generated and executed, especially when
delivered in stages.

For more information on payloads and payload stages, see:
 * https://metasploit.help.rapid7.com/docs/working-with-payloads
 * https://blog.cobaltstrike.com/2012/09/13/a-loader-for-metasploits-meterpreter/

The payload descriptions in this repository are arrenged according to the
metasploit naming convention:

> If you look at Metasploit’s payload list, you will also notice that some
> payloads actually have the exact same name, but in different formats. For
> example: windows/shell/reverse_tcp and windows/shell_reverse_tcp. The one with
> the forward slash indicates that is a “staged” payload, the one with the
> underscore means it’s “single”.

## Single Payloads
 * [python/meterpreter_bind_tcp](../master/python/meterpreter_bind_tcp)
 * [python/meterpreter_reverse_tcp](../master/python/meterpreter_reverse_tcp)
 * [python/shell_bind_tcp](../master/python/shell_bind_tcp)
 * [python/shell_reverse_tcp](../master/python/shell_reverse_tcp)

## Staged payloads
 * [linux_x86/shell/bind_tcp](../master/linux_x86/shell/bind_tcp)
 * [python/meterpreter/bind_tcp](../master/python/meterpreter/bind_tcp)
 * [python/meterpreter/reverse_tcp](../master/python/meterpreter/reverse_tcp)
 * [python/shell/bind_tcp](../master/python/shell/bind_tcp)
 * [python/shell/reverse_tcp](../master/python/shell/reverse_tcp)

## Using Docker with debugging capabilities for 32bit Linux payloads

In order to analyse and debug 32bit linux payloads in a Docker container, the
following arguments are required:

```
# mkdir /tmp/shared
# docker run -it --rm --name deleteme -v /tmp/shared:/shared --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p2000:2000 ubuntu
# root@51d604030a59:/# apt install -y build-essential libc6-i386 gcc-multilib
```
