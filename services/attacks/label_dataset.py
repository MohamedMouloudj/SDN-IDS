"""label_dataset.py - Label traffic_log.csv rows using run_attack_log.json timestamps.

Usage
-----
    python3 label_dataset.py

Reads traffic_log.csv and run_attack_log.json, then writes
traffic_log_labeled.csv with correct Attack_type and Traffic columns.

Note: I am not usign pandas and numpy here to avoid memory issues with large CSV files. Instead, I read and write line by line.

How it works
------------
Each row in traffic_log.csv has a Timestamp (unix float).
Each entry in run_attack_log.json has attack_type, start, end.
If a row's Timestamp falls within [start, end] of any attack window,
it is labeled as that attack type. Otherwise it is labeled Normal.
"""

import json
import csv

CSV_PATH        = '../../ryu-controller/traffic_log.csv'
ATTACK_LOG_PATH = '../../ryu-controller/run_attack_log.json'
OUTPUT_PATH     = '../../ryu-controller/traffic_log_labeled.csv'

total_rows = 0
attack_rows = 0
attack_counts = {}

print(f'Labeling dataset using attack windows from {ATTACK_LOG_PATH}...')

# Load attack windows
with open(ATTACK_LOG_PATH, 'r') as f:
    attack_log = json.load(f)

print(f'Loaded {len(attack_log)} attack windows from {ATTACK_LOG_PATH}')
for entry in attack_log:
    duration = entry['end'] - entry['start']
    print(f"  {entry['attack_type']:15s}  start={entry['start']:.2f}  end={entry['end']:.2f}  duration={duration:.0f}s")


print(f'\nProcessing {CSV_PATH} line-by-line to avoid memory limits...')

with open(CSV_PATH, 'r', newline='') as infile, open(OUTPUT_PATH, 'w', newline='') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)
    
    header = next(reader)
    writer.writerow(header)
    
    # Find column indices
    try:
        ts_idx = header.index('Timestamp')
        traffic_idx = header.index('Traffic')
        attack_idx = header.index('Attack_type')
    except ValueError as e:
        print(f"Error parsing header: {e}")
        exit(1)

    for row in reader:
        if not row: continue
        
        try:
            ts = float(row[ts_idx])
        except ValueError:
            writer.writerow(row)
            continue
            
        traffic_label = 'Normal'
        attack_label = ''
        
        for entry in attack_log:
            if entry['start'] <= ts <= entry['end']:
                traffic_label = 'Attack'
                attack_label = entry['attack_type']
                break
                
        row[traffic_idx] = traffic_label
        row[attack_idx] = attack_label
        writer.writerow(row)
        
        total_rows += 1
        
        # stats
        if traffic_label == 'Attack':
            attack_rows += 1
            attack_counts[attack_label] = attack_counts.get(attack_label, 0) + 1

normal_rows = total_rows - attack_rows

print(f'\nLabeling results:')
print(f'  Total rows  : {total_rows}')
print(f'  Attack rows : {attack_rows}')
print(f'  Normal rows : {normal_rows}')
print(f'\nAttack type distribution:')
for k, v in sorted(attack_counts.items(), key=lambda item: item[1], reverse=True):
    print(f'{k:15} {v}')

print(f'\nLabeled dataset saved to {OUTPUT_PATH}')