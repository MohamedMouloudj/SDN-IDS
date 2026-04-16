"""
traffic_normal.py - Normal traffic generator (balanced protocol distribution)

Changes from previous version
------------------------------
- HTTP interval increased: 1.5-4s -> 6-14s (was dominant at 90%+ TCP)
- FTP interval increased: 2-6s -> 12-25s
- SMTP interval increased: 3-7s -> 18-35s
- ICMP increased: 5 pings per call -> 1 ping per call, interval 0.3-0.6s
- DNS interval unchanged (already fast: 0.2-1s)
- Added missing comma in icmp targets list (bug: "192.168.20.11""192.168.20.12" merged)
- DNS now does both nslookup and direct dig calls for variety

Desired target distribution: ~40% TCP | ~40% UDP | ~20% ICMP
(TCP will still lead slightly — that is realistic enterprise traffic)

Usage (run on each LAN host inside Mininet)
-------------------------------------------
    h1 python3 traffic_normal.py
    h2 python3 traffic_normal.py
    h3 python3 traffic_normal.py

Stop with:
    h1 pkill -f traffic_normal.py
    (repeat for h2, h3)
"""

import subprocess
import time
import random
import threading

# ----------- TCP TRAFFIC -----------

def http_traffic():
    """HTTP requests to DMZ web server. Slowed down to reduce TCP dominance."""
    while True:
        subprocess.run('wget -q -O /dev/null http://192.168.10.10', shell=True)
        time.sleep(random.uniform(6, 14))   # was 1.5-4


def ftp_traffic():
    """FTP directory listing to LAN FTP server."""
    while True:
        subprocess.run('wget -q -O /dev/null ftp://192.168.20.10/', shell=True)
        time.sleep(random.uniform(12, 25))


def smtp_traffic():
    """SMTP email to LAN mail server."""
    while True:
        subprocess.run(
            'python3 -c "'
            'import smtplib; s = smtplib.SMTP(\'192.168.20.11\', 25); '
            's.sendmail(\'a@test.com\',\'b@test.com\',\'Subject: test\\n\\nhello\'); '
            's.quit()"',
            shell=True
        )
        time.sleep(random.uniform(18, 35))


# ----------- UDP (DNS) TRAFFIC -----------

def dns_traffic():
    """
    DNS queries to LAN DNS server.
    Mix of nslookup and dig for variety in flow features.
    High frequency to offset the slow TCP threads.
    """
    valid_domains = ["http.local", "ftp.local", "smtp.local", "dns.local"]

    while True:
        domain = (
            random.choice(valid_domains)
            if random.random() < 0.7
            else f"random{random.randint(1, 1000)}.local"
        )

        # Alternate between nslookup and dig to vary packet sizes slightly
        if random.random() < 0.5:
            subprocess.run(f'nslookup {domain} 192.168.20.12', shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(f'dig @192.168.20.12 {domain}', shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(random.uniform(0.2, 1))


# ----------- ICMP TRAFFIC -----------

def icmp_traffic():
    """
    ICMP pings between LAN hosts.
    1 ping per call (was 5), tighter interval for more ICMP flow entries.
    """
    targets = [
        "192.168.20.101",   # h1
        "192.168.20.102",   # h2
        "192.168.20.103",   # h3
        "192.168.10.10",    # http (DMZ)
        "192.168.20.10",    # ftp (LAN)
        "192.168.20.11",    # smtp (LAN)
        "192.168.20.12",    # dns (LAN)
    ]

    my_ip = subprocess.getoutput("hostname -I").split()[0]
    targets = [t for t in targets if t != my_ip]

    while True:
        dst = random.choice(targets)
        # 1 ping only. creates more distinct short flows vs one long 5-ping flow
        subprocess.run(f"ping -c 1 {dst}", shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(random.uniform(0.3, 0.6))


# ----------- MAIN -----------

threads = [
    threading.Thread(target=http_traffic,  name='http'),
    threading.Thread(target=ftp_traffic,   name='ftp'),
    threading.Thread(target=smtp_traffic,  name='smtp'),
    threading.Thread(target=dns_traffic,   name='dns'),
    threading.Thread(target=icmp_traffic,  name='icmp'),
]

for t in threads:
    t.daemon = True
    t.start()

print("Traffic generation started. Press Ctrl+C to stop.")
try:
    while True:
        time.sleep(10)
except KeyboardInterrupt:
    print("Stopped.")