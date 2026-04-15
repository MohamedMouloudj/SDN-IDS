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

## Generating Normal Traffic

### Prerequisites

#### 1. Ensure RYU monitor and switch are in collection mode

```python
COLLECTION_MODE = True
```

#### 2. Comment out model loading in `monitor.py`

Before running the monitor for data collection, the autoencoder models are not yet
trained. Comment out the following blocks in `monitor.py`:

In `__init__`:

```python
# self._autoencoders = {
#     proto: rt.InferenceSession(f'{proto}.onnx')
#     for proto in ('icmp', 'tcp', 'udp')
# }

# self._scalers = {}
# for proto in ('icmp', 'tcp', 'udp'):
#     with open(f'std_{proto}.pkl', 'rb') as f:
#         self._scalers[proto] = pickle.load(f)
```

In `_detect_anomaly`:

```python
# X       = preprocess_for_autoencoder(records, proto, self._scalers[proto])
# session = self._autoencoders[proto]
# input_name      = session.get_inputs()[0].name
# X_reconstructed = session.run(None, {input_name: X})[0]
# mse  = np.mean(np.power(X - X_reconstructed, 2))
# rmse = float(np.sqrt(mse))
return False, 0.0
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
h1 ping -c 999 h2 &
h2 ping -c 999 h3 &
h1 ping -c 999 192.168.10.10 &
```

### 4. Wait

Let traffic run for at least 30 minutes. Monitor CSV row count from a separate terminal:

```bash
watch -n 10 wc -l ./ryu-controller/traffic_log.csv
```

Aim for at least 500 rows per protocol before stopping.

### 5. Stop traffic and services

```bash
h1 pkill -f traffic_normal.py
h2 pkill -f traffic_normal.py
h3 pkill -f traffic_normal.py
h1 pkill ping
h2 pkill ping
http pkill python3
ftp pkill python3
smtp pkill python3
dns pkill python3
```

### 6. Exit Mininet

```bash
exit
sudo mn -c
```
