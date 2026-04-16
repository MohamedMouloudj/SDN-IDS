## RYU Controller Environment

RYU requires a dedicated Python 3.8 virtual environment due to compatibility
constraints with eventlet. The environment is located at `.ryu-env/` inside
the `ryu-controller/` folder.

**Activate the environment:**

```bash
cd ryu-controller
source .ryu-env/bin/activate
pip install eventlet=0.30.2
```

**Verify the correct ryu-manager is used:**

```bash
which ryu-manager
# expected: .../ryu-controller/.ryu-env/bin/ryu-manager
```

**Run the monitor:**

```bash
ryu-manager monitor.py
```

> **Note:** Do not use the system `ryu-manager` at `/usr/local/bin/ryu-manager`.
> It runs on Python 3.10 (or higher, if you have it) which has an incompatible eventlet version.
> Always activate `.ryu-env` first.

## Wokfloe Guide

**Stage 1 - collect normal traffic (no models yet):**

- `NORMAL_COLLECTION_MODE = True` in [monitor.py](ryu-controller/monitor.py)
- `_detect_anomaly()` returns `(False, 0.0)` - bypass autoencoder entirely
- Run `traffic_normal.py` on h1/h2/h3 for 20-30 minutes
- Result: `traffic_log.csv` with `Traffic='Normal'` rows only

**Stage 2 - train autoencoders (offline, in notebook):**

- Open [train_autoencoders.ipynb](notebooks/train_autoencoders.ipynb)
- Run Pearson heatmap to decide which columns to drop
- Update `AUTOENCODER_FEATURES`, `AUTOENCODER_STD_COLS`, `AUTOENCODER_MM_COLS` in `pipeline.py` file to match exactly what the notebook used
- Run training cells -> produces `icmp.onnx`, `tcp.onnx`, `udp.onnx`, `std_{proto}.json`, `mm_{proto}.json`, `autoencoder_features.json`
- Update `THRESHOLD_ICMP`/`TCP`/`UDP` in [monitor.py](ryu-controller/monitor.py) with printed values

**Stage 3 - collect labelled attack traffic (models exist):**

- `NORMAL_COLLECTION_MODE = False` and `ATTACK_COLLECTION_MODE = True` in [monitor.py](ryu-controller/monitor.py) (mitigation stays OFF)
- Uncomment autoencoder blocks in [monitor.py](ryu-controller/monitor.py)
- Run `run_attack.py` -> produces `run_attack_log.json`
- Run `label_dataset.py` -> produces `traffic_log_labeled.csv`
- Result: balanced dataset for RF/SVM training

**Stage 4 - train classifiers + integrate:**

- Train RF and SVM on `traffic_log_labeled.csv`
- Fill in `_classify_attack()` stub in [monitor.py](ryu-controller/monitor.py)
- Set `NORMAL_COLLECTION_MODE = False` and `ATTACK_COLLECTION_MODE = False` for live IDS operation

## Generating Normal Traffic

### Prerequisites

#### 1. Ensure RYU monitor and switch are in collection mode

```python
NORMAL_COLLECTION_MODE = True
```

#### 2. Comment out model loading in `monitor.py`

Before running the monitor for data collection, the autoencoder models are not yet
trained. Comment out the following blocks in `monitor.py`:

```pythin
COLLECTION_MODE = True
```

#### 3. Delete old CSV if it exists

```bash
rm ryu-controller/traffic_log.csv
```

#### 4. Start RYU

```bash
cd ryu-controller
source .ryu-env/bin/activate
pip install -r requirements.txt
ryu-manager monitor.py
```

---

### 1. Start Mininet

```bash
cd mininet-topo
sudo python3 topo.py
```

### 2. Start services

```bash
http python3 ../services/http_server.py &
ftp python3 ../services/ftp_server.py &
smtp python3 ../services/smtp_server.py &
dns python3 ../services/dns_server.py &
```

### 3. Generate traffic

```bash
h1 python3 ../services/traffic_normal.py &
h2 python3 ../services/traffic_normal.py &
h3 python3 ../services/traffic_normal.py &
```

### 4. Wait

Let traffic run for at least 30 minutes. Monitor CSV row count from a separate terminal:

```bash
watch -n 10 wc -l ./ryu-controller/traffic_log.csv
```

Aim for at least 500 rows per protocol before stopping.

### 5. Stop traffic

```bash
h1 pkill -f traffic_normal.py
h2 pkill -f traffic_normal.py
h3 pkill -f traffic_normal.py
```

### 6. Exit Mininet

```bash
exit
sudo mn -c
```
