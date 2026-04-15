"""
========================================================
SDN IDS Traffic Generator (Normal Traffic Script)
========================================================

Purpose:
- Generate realistic NORMAL network traffic for Mininet-based SDN IDS training.
- Simulates multi-service behavior across LAN and DMZ:
  HTTP, FTP, SMTP, DNS, and ICMP.

--------------------------------------------------------
Execution Model
--------------------------------------------------------

Run this script independently on each host:

    h1 python3 traffic_normal.py
    h2 python3 traffic_normal.py
    h3 python3 traffic_normal.py

Stop all processes after some time (e.g. 15 minutes) to end data collection:

    h1 pkill -f traffic_normal.py
    h2 pkill -f traffic_normal.py
    h3 pkill -f traffic_normal.py

--------------------------------------------------------
Traffic Components & Frequency
--------------------------------------------------------

1. HTTP Traffic (TCP/80 to DMZ)
   - Frequency: high (0.5 - 2 sec intervals)
   - Purpose: main service load toward DMZ web server

2. DNS Traffic (UDP/53 to DNS server)
   - Frequency: medium-high (0.5 - 2 sec intervals)
   - Purpose: name resolution queries for internal services

3. FTP Traffic (TCP/21)
   - Frequency: low-medium (2 - 6 sec intervals)
   - Purpose: file transfer simulation

4. SMTP Traffic (TCP/25)
   - Frequency: low (3 - 8 sec intervals)
   - Purpose: email service simulation

5. ICMP Traffic (ping between hosts only)
   - Frequency: continuous (1 - 3 sec intervals)
   - Rule: NEVER ping self
   - Purpose: host reachability and baseline network chatter

--------------------------------------------------------
Important Rules
--------------------------------------------------------

- Only IPv4 traffic is used for feature extraction.
- No self-ping allowed in ICMP generation.
- Traffic must remain within Mininet topology (no external internet).
- Script is designed for NORMAL behavior only (no attacks).

--------------------------------------------------------
Expected Behavior in IDS Dataset
--------------------------------------------------------

- TCP flows dominate (HTTP/FTP/SMTP)
- UDP flows represent DNS activity
- ICMP provides low-volume baseline traffic
- Flow statistics reflect realistic enterprise-like usage

========================================================
"""

import subprocess
import time
import random
import threading

# ----------- TCP TRAFFIC -----------

def http_traffic():
    cmd = 'wget -q -O /dev/null http://192.168.10.10'
    
    while True:
        subprocess.run(cmd, shell=True)
        time.sleep(random.uniform(1, 3))


def ftp_traffic():
    while True:
        subprocess.run(
            'wget -q -O /dev/null ftp://192.168.20.10/',
            shell=True
        )
        time.sleep(random.uniform(2, 6))


def smtp_traffic():
    while True:
        subprocess.run(
            """python3 -c "import smtplib;
s = smtplib.SMTP('192.168.20.11', 25);
s.sendmail('a@test.com','b@test.com','Subject: test\\n\\nhello');
s.quit()" """,
            shell=True
        )
        time.sleep(random.uniform(3, 7))


# ----------- UDP (DNS) TRAFFIC -----------

def dns_traffic():
    valid_domains = ["http.local", "ftp.local", "smtp.local", "dns.local"]

    while True:
        # valid + random domains
        if random.random() < 0.7:
            domain = random.choice(valid_domains)
        else:
            domain = f"random{random.randint(1,1000)}.local"

        subprocess.run(
            f'nslookup {domain} 192.168.20.12',
            shell=True
        )

        time.sleep(random.uniform(0.2, 1))


# ----------- ICMP TRAFFIC -----------

def icmp_traffic():
    targets = [
        "192.168.20.101",   # h1
        "192.168.20.102",   # h2
        "192.168.20.103",   # h3
        "192.168.10.10",    # http (DMZ)
        "192.168.20.10",    # ftp (LAN)
        "192.168.20.11"     # smtp (LAN)
        "192.168.20.12"     # dns (LAN)
    ]

    my_ip = subprocess.getoutput("hostname -I").split()[0]

    # remove self IP
    targets = [t for t in targets if t != my_ip]

    while True:
        dst = random.choice(targets)
        subprocess.run(f"ping -c 5 {dst}", shell=True)
        time.sleep(random.uniform(0.5, 1.5))


# ----------- MAIN -----------

threads = [
    threading.Thread(target=http_traffic),
    threading.Thread(target=ftp_traffic),
    threading.Thread(target=smtp_traffic),
    threading.Thread(target=dns_traffic),
    threading.Thread(target=icmp_traffic),
]

for t in threads:
    t.daemon = True
    t.start()

while True:
    time.sleep(10)