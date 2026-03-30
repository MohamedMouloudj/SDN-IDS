"""pipeline.py - Stateless feature extraction and preprocessing helpers.

This module is the data pipeline layer. It is completely decoupled from RYU,
SQLAlchemy, and any AI model. All functions are pure (or close to it): given
inputs, return outputs, no side effects.

The module is organised in three sections:

    1. Feature extraction  - raw OpenFlow stat → feature dictionary
    2. Preprocessing       - feature dicts/DataFrames → model-ready arrays
    3. Post-processing     - model outputs → human-readable results

monitor.py calls these functions and owns all state (buffers, sessions, …).
The functions here can also be called offline from a training script to build
the dataset CSV, so the exact same feature logic is shared between training
and inference.

Conventions
-----------
* Every public function has a complete docstring (purpose, params, returns).
* Helper/private functions are prefixed with an underscore.
* No global state. No RYU imports. No DB imports.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ports that are kept as-is for the classifier's Port_dst feature.
# All other ports are mapped to 0 (the "other" class).
KNOWN_PORTS: frozenset[int] = frozenset({0, 21, 22, 53, 80, 443})

# Mapping from ip.proto integer to string label used in feature dicts.
PROTO_MAP: Dict[int, str] = {1: 'icmp', 6: 'tcp', 17: 'udp'}

# TCP flag bit positions inside the 9-bit flags field (MSB = bit 0).
# Index order: NS WCR ECE URG ACK PSH RST SYN FIN
_TCP_FLAG_NAMES = ('NS', 'WCR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN')

# Feature columns expected by each autoencoder model.
AUTOENCODER_FEATURES: Dict[str, List[str]] = {
    'icmp': [
        'Port_dst', 'Icmp', 'Icmp_type', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN',
        'FIN', 'Http', 'SSL', 'SSH', 'Ftp', 'Udp', 'Dns', 'Dhcp',
        'Flow_duration', 'Packet_count', 'Same_ip', 'Bytes',
    ],
    'tcp': [
        'Port_dst', 'Icmp', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN', 'FIN',
        'Http', 'SSL', 'SSH', 'Ftp', 'Udp', 'Flow_duration', 'Packet_count',
        'Same_ip', 'Bytes',
    ],
    'udp': [
        'Port_dst', 'Icmp', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN', 'FIN',
        'Http', 'SSL', 'SSH', 'Ftp', 'Udp', 'Dns', 'Dhcp',
        'Flow_duration', 'Packet_count', 'Same_ip', 'Bytes',
    ],
}

# Feature columns expected by the Random Forest classifier.
RF_FEATURES: List[str] = [
    'Port_dst', 'Icmp', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN', 'FIN',
    'Http', 'SSH', 'Ftp', 'Udp', 'Flow_duration', 'Flow_dur_nsec',
    'Packet_count', 'Pkt_per_sec', 'Same_ip',
]

# Columns scaled with MinMaxScaler before RF inference.
RF_MINMAX_COLS: List[str] = ['Pkt_per_sec', 'Flow_dur_nsec', 'Port_dst']

# Columns scaled with StandardScaler before RF inference.
RF_STANDARD_COLS: List[str] = ['Flow_duration', 'Packet_count']

# Columns scaled with the fitted per-protocol StandardScaler for autoencoders.
AUTOENCODER_SCALE_COLS: Dict[str, List[str]] = {
    'icmp': ['Flow_duration', 'Packet_count', 'Bytes', 'Icmp_type'],
    'tcp':  ['Flow_duration', 'Packet_count', 'Bytes', 'Port_dst'],
    'udp':  ['Flow_duration', 'Packet_count', 'Bytes'],
}

# Human-readable attack class labels (must match training label encoding).
ATTACK_LABELS: Dict[int, str] = {
    0: 'SLOWLORIS',
    1: 'ICMP_flood',
    2: 'LAND_attack',
    3: 'HTTP_flood',
    4: 'SYN_flood',
    5: 'UDP_flood',
}

# ---------------------------------------------------------------------------
# Section 1 - Feature extraction
# ---------------------------------------------------------------------------

def extract_flow_features(stat) -> Optional[Dict]:
    """Convert one OpenFlow flow-stats entry into a flat feature dictionary.

    This is the single source of truth for feature engineering. The same
    function is called during live inference (monitor.py) and offline dataset
    collection (traffic_normal.py / traffic_attack.py).

    Parameters
    ----------
    stat : ryu OFPFlowStats object
        One entry from ev.msg.body inside EventOFPFlowStatsReply.
        Must contain an IPv4 match with ip_proto set to 1, 6, or 17.

    Returns
    -------
    dict or None
        Feature dictionary on success.
        None if the flow's ip_proto is not ICMP/TCP/UDP (caller should skip).

    Notes
    -----
    The returned dict contains ALL columns used by every downstream consumer
    (autoencoders, RF classifier, DB packet table). Callers select the subset
    they need via AUTOENCODER_FEATURES or RF_FEATURES.
    """
    ip_proto = stat.match.get('ip_proto')
    if ip_proto not in PROTO_MAP:
        return None

    proto = PROTO_MAP[ip_proto]
    src_ip = stat.match.get('ipv4_src', '')
    dst_ip = stat.match.get('ipv4_dst', '')

    same_ip = int(src_ip == dst_ip)

    # Protocol-specific fields
    (
        port_src, port_dst,
        icmp_flag, icmp_code, icmp_type,
        tcp_flag, udp_flag,
        http, ssl, ftp, ssh, dns, dhcp,
        ack, psh, rst, syn, fin,
        proto_type_label,
    ) = _extract_proto_fields(stat, ip_proto)

    # Rate features
    pkt_per_sec, pkt_per_nsec = _safe_rate(stat.packet_count, stat.duration_sec, stat.duration_nsec)
    bytes_per_sec, bytes_per_nsec = _safe_rate(stat.byte_count, stat.duration_sec, stat.duration_nsec)

    return {
        # Identifiers / metadata
        'Ip_src':        src_ip,
        'Ip_dst':        dst_ip,
        'Same_ip':       same_ip,
        'Port_src':      port_src,
        'Port_dst':      port_dst,
        'Ip_protocole':  proto,
        'Type_protocole': proto_type_label,

        # Protocol flags
        'Icmp':          icmp_flag,
        'Icmp_code':     icmp_code,
        'Icmp_type':     icmp_type,
        'Tcp':           tcp_flag,
        'Udp':           udp_flag,

        # TCP control flags
        'ACK': ack, 'PSH': psh, 'RST': rst, 'SYN': syn, 'FIN': fin,

        # Application-layer flags
        'Http': http, 'SSL': ssl, 'SSH': ssh, 'Ftp': ftp,
        'Dns': dns, 'Dhcp': dhcp,

        # Flow counters
        'Flow_duration':  stat.duration_sec,
        'Flow_dur_nsec':  stat.duration_nsec,
        'Packet_count':   stat.packet_count,
        'Bytes':          stat.byte_count,

        # Derived rates
        'Pkt_per_sec':    pkt_per_sec,
        'Pkt_per_nsec':   pkt_per_nsec,
        'Bytes_per_sec':  bytes_per_sec,
        'Bytes_per_nsec': bytes_per_nsec,
    }


def _extract_proto_fields(stat, ip_proto: int) -> Tuple:
    """Return protocol-specific features as a flat tuple.

    Parameters
    ----------
    stat     : OFPFlowStats - one flow stat entry
    ip_proto : int - 1 (ICMP), 6 (TCP), or 17 (UDP)

    Returns
    -------
    Tuple with 20 values (see inline comments for names).
    """
    # Defaults for all flags
    port_src = port_dst = 0
    icmp_code = icmp_type = -1
    icmp_flag = tcp_flag = udp_flag = 0
    http = ssl = ftp = ssh = dns = dhcp = 0
    ack = psh = rst = syn = fin = 0
    proto_type_label = ''

    if ip_proto == 1:   # ICMP
        icmp_flag  = 1
        port_src = port_dst = -1
        icmp_code  = stat.match.get('icmpv4_code', -1)
        icmp_type  = stat.match.get('icmpv4_type', -1)

    elif ip_proto == 6:  # TCP
        tcp_flag   = 1
        port_src   = stat.match.get('tcp_src', 0)
        port_dst   = stat.match.get('tcp_dst', 0)

        # Application-layer detection by well-known port
        proto_type_label, http, ssl, ftp, ssh = _classify_tcp_service(port_src, port_dst)

        # TCP flags bitmask → individual bits
        raw_flags  = stat.match.get('tcp_flags', 0)
        flags_bin  = bin(raw_flags)[2:].zfill(len(_TCP_FLAG_NAMES))
        flag_dict  = dict(zip(_TCP_FLAG_NAMES, flags_bin))
        ack = int(flag_dict.get('ACK', '0'))
        psh = int(flag_dict.get('PSH', '0'))
        rst = int(flag_dict.get('RST', '0'))
        syn = int(flag_dict.get('SYN', '0'))
        fin = int(flag_dict.get('FIN', '0'))

    elif ip_proto == 17:  # UDP
        udp_flag   = 1
        port_src   = stat.match.get('udp_src', 0)
        port_dst   = stat.match.get('udp_dst', 0)
        proto_type_label, dns, dhcp = _classify_udp_service(port_src, port_dst)

    return (
        port_src, port_dst,
        icmp_flag, icmp_code, icmp_type,
        tcp_flag, udp_flag,
        http, ssl, ftp, ssh, dns, dhcp,
        ack, psh, rst, syn, fin,
        proto_type_label,
    )


def _classify_tcp_service(src_port: int, dst_port: int) -> Tuple[str, int, int, int, int]:
    """Identify the application-layer service from TCP port numbers.

    Parameters
    ----------
    src_port : int
    dst_port : int

    Returns
    -------
    tuple (label, http, ssl, ftp, ssh)
        label : human-readable service name or empty string
        http, ssl, ftp, ssh : binary flags (only one is 1)
    """
    ports = {src_port, dst_port}
    if   ports & {80}:          return 'Http', 1, 0, 0, 0
    elif ports & {443}:         return 'SSL',  0, 1, 0, 0
    elif ports & {20, 21}:      return 'Ftp',  0, 0, 1, 0
    elif ports & {22}:          return 'SSH',  0, 0, 0, 1
    return '', 0, 0, 0, 0


def _classify_udp_service(src_port: int, dst_port: int) -> Tuple[str, int, int]:
    """Identify the application-layer service from UDP port numbers.

    Parameters
    ----------
    src_port : int
    dst_port : int

    Returns
    -------
    tuple (label, dns, dhcp)
    """
    ports = {src_port, dst_port}
    if   ports & {53}:       return 'DNS',  1, 0
    elif ports & {67, 68}:   return 'Dhcp', 0, 1
    return '', 0, 0


def _safe_rate(count: int, sec: int, nsec: int) -> Tuple[float, float]:
    """Compute per-second and per-nanosecond rates, guarding against division by zero.

    Parameters
    ----------
    count : int - packet count or byte count
    sec   : int - flow duration in seconds
    nsec  : int - flow duration in nanoseconds

    Returns
    -------
    tuple (per_sec, per_nsec) - 0.0 when the denominator is zero
    """
    per_sec  = count / sec  if sec  else 0.0
    per_nsec = count / nsec if nsec else 0.0
    return per_sec, per_nsec


# ---------------------------------------------------------------------------
# Section 2 - Preprocessing
# ---------------------------------------------------------------------------

def preprocess_for_autoencoder(
    records: List[Dict],
    protocol: str,
    scaler,
) -> np.ndarray:
    """Prepare a window of flow records for autoencoder inference.

    Selects the correct feature subset, applies the fitted scaler to the
    numeric columns listed in AUTOENCODER_SCALE_COLS, and returns a float32
    NumPy array ready to be passed to model.evaluate() or model.predict().

    Parameters
    ----------
    records  : list of dict - raw feature dicts from extract_flow_features()
    protocol : str - 'icmp' | 'tcp' | 'udp'
    scaler   : fitted sklearn StandardScaler - loaded from std_<proto>.pkl

    Returns
    -------
    np.ndarray - shape (len(records), n_features), dtype float32
    """
    feature_cols = AUTOENCODER_FEATURES[protocol]
    scale_cols   = AUTOENCODER_SCALE_COLS[protocol]

    df = pd.DataFrame(records)[feature_cols].copy()

    # Port filtering: replace non-whitelisted ports with 0
    if 'Port_dst' in df.columns:
        df['Port_dst'] = df['Port_dst'].apply(filter_port)

    # Apply the pre-fitted scaler only to the designated columns
    df[scale_cols] = scaler.transform(df[scale_cols])

    return df.values.astype(np.float32)


def preprocess_for_classifier(records: List[Dict]) -> pd.DataFrame:
    """Prepare a window of flow records for Random Forest inference.

    Applies port filtering, MinMaxScaler on rate/port columns, and
    StandardScaler on flow duration and packet count. Scalers are fit on the
    batch itself (matching the original monitor.py behaviour - no pre-saved
    RF scalers exist).

    Parameters
    ----------
    records : list of dict - raw feature dicts from extract_flow_features()

    Returns
    -------
    pd.DataFrame - scaled feature DataFrame ready for model_rf.predict()
    """
    from sklearn.preprocessing import MinMaxScaler, StandardScaler  # local import keeps module lightweight

    df = pd.DataFrame(records)[RF_FEATURES].copy()

    df['Port_dst'] = df['Port_dst'].apply(filter_port)

    # MinMax on rate / port columns
    mm_scaler = MinMaxScaler()
    df[RF_MINMAX_COLS] = mm_scaler.fit_transform(df[RF_MINMAX_COLS])

    # Standard on flow-level counters
    std_scaler = StandardScaler()
    df[RF_STANDARD_COLS] = std_scaler.fit_transform(df[RF_STANDARD_COLS])

    return df


# ---------------------------------------------------------------------------
# Section 3 - Post-processing
# ---------------------------------------------------------------------------

def decode_attack_labels(raw_predictions: np.ndarray) -> List[str]:
    """Map integer class predictions from the RF model to human-readable labels.

    Parameters
    ----------
    raw_predictions : np.ndarray - 1-D array of integer class indices

    Returns
    -------
    list[str] - same length as raw_predictions
    """
    return [ATTACK_LABELS.get(int(p), 'Unknown') for p in raw_predictions]


def majority_attack_type(labels: List[str]) -> str:
    """Return the most common attack label in a list.

    Parameters
    ----------
    labels : list[str] - output of decode_attack_labels()

    Returns
    -------
    str - the most frequent label
    """
    return Counter(labels).most_common(1)[0][0]


def identify_attacker(df: pd.DataFrame) -> str:
    """Determine the dominant attacker IP in a flow window.

    If every source IP in the window is unique (fully distributed attack),
    returns 'random'. Otherwise returns the most frequent source IP.

    Parameters
    ----------
    df : pd.DataFrame - must contain 'Ip_src' column

    Returns
    -------
    str - IP address string or 'random'
    """
    if df['Ip_src'].nunique() == len(df):
        return 'random'
    return str(df['Ip_src'].value_counts().idxmax())


def identify_victim(df: pd.DataFrame) -> str:
    """Return the most frequent destination IP in a flow window.

    Parameters
    ----------
    df : pd.DataFrame - must contain 'Ip_dst' column

    Returns
    -------
    str
    """
    return str(df['Ip_dst'].value_counts().idxmax())


# ---------------------------------------------------------------------------
# Section 4 - Shared utility
# ---------------------------------------------------------------------------

def filter_port(port: int) -> int:
    """Map non-whitelisted destination ports to 0.

    The autoencoder and RF models were trained on a dataset where rare ports
    were replaced with 0 to reduce cardinality. This function replicates that
    transformation at inference time.

    Parameters
    ----------
    port : int - raw destination port number

    Returns
    -------
    int - original port if in KNOWN_PORTS, else 0
    """
    return port if port in KNOWN_PORTS else 0


def compute_rmse(loss: float) -> float:
    """Return the Root Mean Squared Error from a mean-squared-error loss value.

    Parameters
    ----------
    loss : float - MSE loss returned by model.evaluate()

    Returns
    -------
    float
    """
    return float(np.sqrt(loss))