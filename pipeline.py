"""pipeline.py - Stateless feature extraction and preprocessing helpers.

This module is the data pipeline layer. It is completely decoupled from RYU,
SQLAlchemy, and any AI model. All functions are pure (or close to it): given
inputs, return outputs, no side effects.

The module is organised in three sections:

    1. Feature extraction  - raw OpenFlow stat -> feature dictionary
    2. Preprocessing       - feature dicts/DataFrames -> model-ready arrays
    3. Post-processing     - model outputs -> human-readable results

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
from sklearn.preprocessing import MinMaxScaler, StandardScaler

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ports that are kept as-is for the classifier's Port_dst feature.
# All other ports are mapped to 0 (the "other" class).
KNOWN_PORTS: frozenset[int] = frozenset({0, 21, 20, 25, 53, 80})

# Mapping from ip.proto integer to string label used in feature dicts.
PROTO_MAP: Dict[int, str] = {1: 'icmp', 6: 'tcp', 17: 'udp'}

# TCP flag bit positions inside the 9-bit flags field (MSB = bit 0).
# Index order: NS WCR ECE URG ACK PSH RST SYN FIN
_TCP_FLAG_NAMES = ('NS', 'WCR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN')

# ---------------------------------------------------------------------------
# Autoencoder feature configuration
# ---------------------------------------------------------------------------
# NOTE: These lists are the DEFAULT values before Pearson analysis.
#       After running the correlation heatmap in train_autoencoders.ipynb
#       and deciding which columns to drop, paste the updated lists here.
#
#       The notebook's final cell prints the exact lists to paste.
#       The three dicts (FEATURES, STD_COLS, MM_COLS) must all be consistent
#       with each other and with what the trained models expect.
#
# "Bytes" is listed here but is very likely to be dropped after correlation
# analysis (highly correlated with Bytes_per_sec / Bytes_per_nsec).
# Similarly Pkt_per_nsec is often redundant with Pkt_per_sec.
# Leave them in until the heatmap confirms it.

AUTOENCODER_FEATURES: Dict[str, List[str]] = {
    'icmp': ['Port_dst', 'Icmp', 'Icmp_type', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN', 'FIN', 'Http', 'Smtp', 'Ftp', 'Udp', 'Dns', 'Flow_duration', 'Same_ip', 'Bytes_per_sec', 'Bytes_per_nsec', 'Bytes', 'Duration_per_packet', 'Avg_pkt_size'],
    'tcp': ['Port_dst', 'Icmp', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN', 'FIN', 'Http', 'Ftp', 'Smtp', 'Udp', 'Flow_duration', 'Same_ip', 'Bytes_per_sec', 'Bytes_per_nsec', 'Bytes', 'Duration_per_packet', 'Avg_pkt_size'],
    'udp': ['Port_dst', 'Icmp', 'Tcp', 'ACK', 'PSH', 'RST', 'SYN', 'FIN', 'Http', 'Ftp', 'Smtp', 'Udp', 'Dns', 'Flow_duration', 'Packet_count', 'Same_ip', 'Bytes_per_sec', 'Bytes_per_nsec', 'Bytes', 'Duration_per_packet', 'Avg_pkt_size']
}

# Columns to scale with StandardScaler (duration counters, ICMP type).
# These have large variance and outliers -> zero-mean unit-variance is correct.
AUTOENCODER_STD_COLS: Dict[str, List[str]] = {
    'icmp': ['Flow_duration', 'Icmp_type', 'Duration_per_packet', 'Avg_pkt_size', 'Port_dst', 'Bytes'],
    'tcp': ['Flow_duration', 'Port_dst', 'Duration_per_packet', 'Avg_pkt_size', 'Bytes'],
    'udp': ['Flow_duration', 'Port_dst', 'Duration_per_packet', 'Avg_pkt_size', 'Bytes']
}

# Columns to scale with MinMaxScaler (rate features).
# During a flood attack these go WAY above the training max -> land outside
# [0, 1] -> reconstruction error spikes -> anomaly detected. This is intentional.
AUTOENCODER_MM_COLS: Dict[str, List[str]] = {
    'icmp': ['Bytes_per_sec', 'Bytes_per_nsec'],
    'tcp': ['Bytes_per_sec', 'Bytes_per_nsec'],
    'udp': ['Bytes_per_sec', 'Bytes_per_nsec']
}

# ---------------------------------------------------------------------------
# Classifier feature configuration (unchanged)
# ---------------------------------------------------------------------------

# Feature columns expected by the Random Forest classifier.
RF_FEATURES: List[str] = [
    'Port_dst', 'Icmp', 'SYN', 'Ftp', 'Udp',
    'Flow_dur_nsec', 'Packet_count', 'Pkt_per_sec',
    'Same_ip', 'Duration_per_packet', 'Avg_pkt_size',
]

# Columns scaled with MinMaxScaler before RF inference.
RF_MINMAX_COLS: List[str] = ['Pkt_per_sec', 'Flow_dur_nsec', 'Port_dst']

# Columns scaled with StandardScaler before RF inference.
RF_STANDARD_COLS: List[str] = ['Packet_count'] #? Updated after scaling and training

# Feature columns expected by the SVM classifier.
SVM_FEATURES: List[str] = RF_FEATURES

# SVM requires all features on the same scale.
SVM_SCALE_COLS: List[str] = [
    'Port_dst', 'Flow_duration', 'Flow_dur_nsec',
    'Packet_count', 'Pkt_per_sec',
]

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
    """
    ip_proto = stat.match.get('ip_proto')
    if ip_proto not in PROTO_MAP:
        return None

    proto  = PROTO_MAP[ip_proto]
    src_ip = stat.match.get('ipv4_src', '')
    dst_ip = stat.match.get('ipv4_dst', '')
    same_ip = int(src_ip == dst_ip)

    (
        port_src, port_dst,
        icmp_flag, icmp_code, icmp_type,
        tcp_flag, udp_flag,
        http, ftp, smtp, dns,
        ack, psh, rst, syn, fin,
        proto_type_label,
    ) = _extract_proto_fields(stat, ip_proto)

    pkt_per_sec,   pkt_per_nsec   = _safe_rate(stat.packet_count, stat.duration_sec, stat.duration_nsec)
    bytes_per_sec, bytes_per_nsec = _safe_rate(stat.byte_count,   stat.duration_sec, stat.duration_nsec)
    duration_per_packet = (stat.duration_sec / (stat.packet_count + 1e-6))
    avg_pkt_size = (bytes_per_sec / (pkt_per_sec + 1e-6)) if pkt_per_sec > 1e-6 else 0.0
    avg_pkt_size = 0.0 if avg_pkt_size in (float('inf'), float('-inf')) else avg_pkt_size

    return {
        'Ip_src':         src_ip,
        'Ip_dst':         dst_ip,
        'Same_ip':        same_ip,
        'Port_src':       port_src,
        'Port_dst':       port_dst,
        'Ip_protocole':   proto,
        'Type_protocole': proto_type_label,

        'Icmp':      icmp_flag,
        'Icmp_code': icmp_code,
        'Icmp_type': icmp_type,
        'Tcp':       tcp_flag,
        'Udp':       udp_flag,

        'ACK': ack, 'PSH': psh, 'RST': rst, 'SYN': syn, 'FIN': fin,

        'Http': http, 'Ftp': ftp, 'Smtp': smtp, 'Dns': dns,

        'Flow_duration': stat.duration_sec,
        'Flow_dur_nsec': stat.duration_nsec,
        'Packet_count':  stat.packet_count,
        'Bytes':         stat.byte_count,

        'Pkt_per_sec':    pkt_per_sec,
        'Pkt_per_nsec':   pkt_per_nsec,
        'Bytes_per_sec':  bytes_per_sec,
        'Bytes_per_nsec': bytes_per_nsec,

        'Duration_per_packet': duration_per_packet,
        'Avg_pkt_size':        avg_pkt_size,
    }


def _extract_proto_fields(stat, ip_proto: int) -> Tuple:
    """Return protocol-specific features as a flat tuple.

    Parameters
    ----------
    stat     : OFPFlowStats - one flow stat entry
    ip_proto : int - 1 (ICMP), 6 (TCP), or 17 (UDP)

    Returns
    -------
    Tuple with 17 values (see inline comments for names).
    """
    # Defaults for all flags
    port_src = port_dst = 0
    icmp_code = icmp_type = -1
    icmp_flag = tcp_flag = udp_flag = 0
    http = ftp = smtp = dns = 0
    ack = psh = rst = syn = fin = -1
    proto_type_label = ''

    if ip_proto == 1:    # ICMP
        icmp_flag = 1
        port_src = port_dst = -1
        icmp_code = stat.match.get('icmpv4_code', -1)
        icmp_type = stat.match.get('icmpv4_type', -1)

    elif ip_proto == 6:  # TCP
        tcp_flag  = 1
        port_src  = stat.match.get('tcp_src', 0)
        port_dst  = stat.match.get('tcp_dst', 0)
        proto_type_label, http, ftp, smtp = _classify_tcp_service(port_src, port_dst)
        raw_flags = stat.match.get('tcp_flags', 0)
        flags_bin = bin(raw_flags)[2:].zfill(len(_TCP_FLAG_NAMES))
        flag_dict = dict(zip(_TCP_FLAG_NAMES, flags_bin))
        ack = int(flag_dict.get('ACK', '0'))
        psh = int(flag_dict.get('PSH', '0'))
        rst = int(flag_dict.get('RST', '0'))
        syn = int(flag_dict.get('SYN', '0'))
        fin = int(flag_dict.get('FIN', '0'))

    elif ip_proto == 17:  # UDP
        udp_flag  = 1
        port_src  = stat.match.get('udp_src', 0)
        port_dst  = stat.match.get('udp_dst', 0)
        proto_type_label, dns = _classify_udp_service(port_src, port_dst)

    return (
        port_src, port_dst,
        icmp_flag, icmp_code, icmp_type,
        tcp_flag, udp_flag,
        http, ftp, smtp, dns,
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
    tuple (label, http, ftp, smtp)
        label : human-readable service name or empty string
        http, ftp, smtp : binary flags (only one is 1)
    """
    ports = {src_port, dst_port}
    if   ports & {80}:      return 'Http', 1, 0, 0
    elif ports & {20, 21}:  return 'Ftp',  0, 1, 0
    elif ports & {25}:      return 'Smtp', 0, 0, 1
    return '', 0, 0, 0


def _classify_udp_service(src_port: int, dst_port: int) -> Tuple[str, int, int]:
    """Identify the application-layer service from UDP port numbers.

    Parameters
    ----------
    src_port : int
    dst_port : int

    Returns
    -------
    tuple (label, dns)
    """
    ports = {src_port, dst_port}
    if ports & {53}:  return 'DNS', 1
    return '', 0


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

def preprocess_for_autoencoder(records, protocol, scaler_std, scaler_mm) -> np.ndarray:
    """Prepare a window of flow records for autoencoder inference.

    Selects the protocol-specific feature subset, fills NaN with 0,
    applies port filtering, then scales with:
      - StandardScaler on AUTOENCODER_STD_COLS  (duration, count, Bytes)
      - MinMaxScaler   on AUTOENCODER_MM_COLS   (rate features)

    Parameters
    ----------
    records    : list of dict - raw feature dicts from extract_flow_features()
    protocol   : str - 'icmp' | 'tcp' | 'udp'
    scaler_std : fitted sklearn StandardScaler loaded from std_<proto>.json
    scaler_mm  : fitted sklearn MinMaxScaler   loaded from mm_<proto>.json

    Returns
    -------
    np.ndarray - shape (len(records), n_features), dtype float32
    """
    feature_cols = AUTOENCODER_FEATURES[protocol]
    std_cols     = [c for c in AUTOENCODER_STD_COLS[protocol] if c in feature_cols]
    mm_cols      = [c for c in AUTOENCODER_MM_COLS[protocol]  if c in feature_cols]

    df = pd.DataFrame(records)[feature_cols].copy().fillna(0)

    if 'Port_dst' in df.columns:
        df['Port_dst'] = df['Port_dst'].apply(filter_port)

    df[std_cols] = scaler_std.transform(df[std_cols].values)
    df[mm_cols]  = scaler_mm.transform(df[mm_cols].values)

    return df.values.astype(np.float32)


def preprocess_for_rf_classifier(
    records: List[Dict],
    scaler_mm: 'MinMaxScaler',
    scaler_std: 'StandardScaler',
) -> np.ndarray:
    """Prepare a window of flow records for RF/classifier inference.

    Parameters
    ----------
    records    : list of dict - raw feature dicts from extract_flow_features()
    scaler_mm  : fitted MinMaxScaler  loaded from rf_mm.json
    scaler_std : fitted StandardScaler loaded from rf_std.json

    Returns
    -------
    np.ndarray float32 - shape (len(records), len(RF_FEATURES))
    """
    df = pd.DataFrame(records)[RF_FEATURES].copy()
    df['Port_dst'] = df['Port_dst'].apply(filter_port)

    mm_cols  = [c for c in RF_MINMAX_COLS  if c in df.columns]
    std_cols = [c for c in RF_STANDARD_COLS if c in df.columns]

    df[mm_cols]  = scaler_mm.transform(df[mm_cols].values)
    df[std_cols] = scaler_std.transform(df[std_cols].values)

    return df.values.astype(np.float32)


def preprocess_for_svm_classifier(records: List[Dict]) -> np.ndarray:
    """[STUB] Prepare a window of flow records for SVM inference.

    SVM requires all features on the same scale, so ALL numeric columns
    are scaled with StandardScaler.

    Parameters
    ----------
    records : list of dict - raw feature dicts from extract_flow_features()

    Returns
    -------
    np.ndarray - shape (len(records), n_features), dtype float32
    """
    from sklearn.preprocessing import StandardScaler

    df = pd.DataFrame(records)[SVM_FEATURES].copy()
    df['Port_dst'] = df['Port_dst'].apply(filter_port)

    scaler = StandardScaler()
    return scaler.fit_transform(df[SVM_SCALE_COLS]).astype(np.float32)

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

    The autoencoder and classifier models were trained on a dataset where rare ports
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