import socket
s = socket.socket()
s.settimeout(5)
try:
    s.connect(("10.180.247.221", 9000))
    print("OK - port 9000 reachable")
    s.close()
except Exception as e:
    print(f"FAIL - {e}")
