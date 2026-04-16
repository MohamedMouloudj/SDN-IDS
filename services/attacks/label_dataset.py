"""label_dataset.py - Label traffic_log.csv rows using run_attack_log.json timestamps.

Usage
-----
    python3 label_dataset.py

Reads traffic_log.csv and run_attack_log.json, then writes
traffic_log_labeled.csv with correct Attack_type and Traffic columns.

How it works
------------
Each row in traffic_log.csv has a Timestamp (unix float).
Each entry in run_attack_log.json has attack_type, start, end.
If a row's Timestamp falls within [start, end] of any attack window,
it is labeled as that attack type. Otherwise it is labeled Normal.
"""

import json
import pandas as pd

CSV_PATH        = '../../ryu-controller/traffic_log.csv'
ATTACK_LOG_PATH = '../../ryu-controller/run_attack_log.json'
OUTPUT_PATH     = '../../ryu-controller/traffic_log_labeled.csv'

# Load attack windows
with open(ATTACK_LOG_PATH, 'r') as f:
    attack_log = json.load(f)

print(f'Loaded {len(attack_log)} attack windows from {ATTACK_LOG_PATH}')
for entry in attack_log:
    duration = entry['end'] - entry['start']
    print(f"  {entry['attack_type']:15s}  start={entry['start']:.2f}  end={entry['end']:.2f}  duration={duration:.0f}s")

# Load CSV
df = pd.read_csv(CSV_PATH)
print(f'\nLoaded {len(df)} rows from {CSV_PATH}')

# Reset labels -- start clean
df['Traffic']     = 'Normal'
df['Attack_type'] = ''

# Label each row
def get_label(ts):
    for entry in attack_log:
        if entry['start'] <= ts <= entry['end']:
            return 'Attack', entry['attack_type']
    return 'Normal', ''

labels = df['Timestamp'].apply(get_label)
df['Traffic']     = [l[0] for l in labels]
df['Attack_type'] = [l[1] for l in labels]

# Report
attack_rows  = df[df['Traffic'] == 'Attack']
normal_rows  = df[df['Traffic'] == 'Normal']
print(f'\nLabeling results:')
print(f'  Total rows  : {len(df)}')
print(f'  Attack rows : {len(attack_rows)}')
print(f'  Normal rows : {len(normal_rows)}')
print(f'\nAttack type distribution:')
print(attack_rows['Attack_type'].value_counts())

df.to_csv(OUTPUT_PATH, index=False)
print(f'\nLabeled dataset saved to {OUTPUT_PATH}')