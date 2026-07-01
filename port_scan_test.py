import socket

target = "192.168.31.232"  # Change this if testing another machine

ports = [
    20, 21, 22, 23, 25,
    53, 80, 110, 143, 443,
    8080, 8443
]

print(f"Scanning {target}...\n")

for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)

    try:
        s.connect((target, port))
        print(f"[+] Port {port} OPEN")
    except:
        print(f"[-] Port {port} CLOSED")
    finally:
        s.close()

print("\nScan Complete.")