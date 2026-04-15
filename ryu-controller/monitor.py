"""monitor.py - RYU monitoring app with autoencoder anomaly detection.

Architecture
------------
This app extends switch.SimpleSwitch13, inheriting all MAC-learning and
mitigation-policy logic, then layers two additional responsibilities
on top:

    1. Datapath tracking  - register/unregister switches as they connect.
    2. Periodic stat polling - every POLL_INTERVAL seconds, ask every known
       switch for its full flow table statistics.
    3. Feature extraction - convert raw OpenFlow stats into feature dicts
       using pipeline.extract_flow_features().
    4. Protocol buffering - accumulate ICMP / TCP / UDP records separately
       in fixed-size windows of BATCH_SIZE flows.
    5. Anomaly detection  - autoencoder RMSE vs threshold per protocol.
    6. Traffic persistence - write every flow record to CSV with label.

Classifier integration (COMING LATER)
--------------------------------------
    7. Attack classification via RF / SVM when anomaly is detected.
    8. Write attack events to History table + let switch mitigate.

Usage
-----
    source ~/ryu-env/bin/activate
    ryu-manager monitor.py
"""



import switch

import os
import sys
import json


from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types


import csv
import pandas as pd
from sklearn.preprocessing import StandardScaler
import numpy as np


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models import Session, History
import onnxruntime as rt
from pipeline import (
    extract_flow_features,
    preprocess_for_autoencoder,
    compute_rmse,
    ATTACK_LABELS,
    identify_attacker,
    identify_victim,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Set to True only during attack traffic collection
# Each detected attack window writes its timestamp to attack_log.json
COLLECTION_MODE = True
ATTACK_LOG_PATH = 'attack_log.json'

POLL_INTERVAL  = 10    # seconds between stat requests
BATCH_SIZE     = 30    # number of flows per protocol window before processing

# Autoencoder detection thresholds (RMSE)
THRESHOLD_ICMP = 0.1950
THRESHOLD_TCP  = 0.0602
THRESHOLD_UDP  = 0.0149

THRESHOLDS: Dict[str, float] = {
    'icmp': THRESHOLD_ICMP,
    'tcp':  THRESHOLD_TCP,
    'udp':  THRESHOLD_UDP,
}

SVM_THRESHOLD = 0.5  # Placeholder until SVM model is trained

# ---------------------------------------------------------------------------
# Monitor app
# ---------------------------------------------------------------------------

class MonitorApp(switch.SimpleSwitch13):
    """Extend the learning switch with periodic OpenFlow stat collection.

    Class responsibilities
    ----------------------
    * Track which datapaths are currently connected via EventOFPStateChange.
    * Run a background green thread (_poll_loop) that sends flow stat requests
      to every known switch every POLL_INTERVAL seconds.
    * Handle EventOFPFlowStatsReply by extracting features from each flow,
      routing records into per-protocol buffers, and draining full windows.

    AI integration
    --------------
    * _detect_anomaly()  - runs autoencoder, compares RMSE to threshold.
    * _classify_attack() - [stub] will run RF/SVM classifier.
    * _record_attack()   - writes attack event to History table.
    """

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # {dpid (int): datapath} - populated by EventOFPStateChange
        self.datapaths: Dict[int, object] = {}

        # Per-protocol accumulation buffers: {protocol: [feature_dict, ...]}
        self._buffers: Dict[str, List[dict]] = defaultdict(list)

        # Background polling thread
        self._poll_thread = hub.spawn(self._poll_loop)

        # Load autoencoders
        self._autoencoders = {
            proto: rt.InferenceSession(f'{proto}.onnx')
            for proto in ('icmp', 'tcp', 'udp')
        }

        # # Load fitted scalers
        # ! h5 files will cause an issue with python 3.8, so I converted them to json and will load them manually here. (see train_autoencoders.ipynb for the conversion process)
        # self._scalers = {}
        # for proto in ('icmp', 'tcp', 'udp'):
        #     with open(f'std_{proto}.pkl', 'rb') as f:
        #         self._scalers[proto] = pickle.load(f)
        self._scalers = {}
        for proto in ('icmp', 'tcp', 'udp'):
            with open(f'std_{proto}.json', 'r') as f:
                data = json.load(f)
            scaler = StandardScaler()
            scaler.mean_            = np.array(data['mean'])
            scaler.scale_           = np.array(data['scale'])
            scaler.var_             = np.array(data['var'])
            scaler.n_samples_seen_  = data['n_samples_seen']
            self._scalers[proto]    = scaler

        # CSV logging setup, for training data collection
        file_exists = os.path.exists('traffic_log.csv')
        self._csv_file = open('traffic_log.csv', 'a', newline='')
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=[
            'Timestamp', 'Ip_src', 'Ip_dst', 'Same_ip', 'Port_src', 'Port_dst',
            'Ip_protocole', 'Type_protocole',
            'Icmp', 'Icmp_code', 'Icmp_type',
            'Tcp', 'Udp',
            'ACK', 'PSH', 'RST', 'SYN', 'FIN',
            'Http', 'Ftp', 'Smtp', 'Dns',
            'Flow_duration', 'Flow_dur_nsec',
            'Packet_count', 'Bytes',
            'Pkt_per_sec', 'Pkt_per_nsec',
            'Bytes_per_sec', 'Bytes_per_nsec',
            'Traffic', 'Attack_type',
        ])
        if not file_exists:
            self._csv_writer.writeheader()
    

    # ------------------------------------------------------------------
    # Datapath tracking
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Register or deregister a datapath as its connection state changes.

        Called automatically by RYU. Keeping self.datapaths up to date ensures
        the polling loop only contacts live switches.
        """
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(
                    'Datapath registered: %016x  (total: %d)',
                    datapath.id, len(self.datapaths),
                )

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info(
                    'Datapath removed: %016x  (total: %d)',
                    datapath.id, len(self.datapaths),
                )

    # ------------------------------------------------------------------
    # Background polling
    # ------------------------------------------------------------------

    def _poll_loop(self):
        """Periodically request flow statistics from every known switch.

        Runs forever in a RYU green thread (hub.spawn). Sleeps for
        POLL_INTERVAL seconds between rounds. Uses hub.sleep (not time.sleep)
        to avoid blocking the RYU event loop.
        """
        while True:
            hub.sleep(POLL_INTERVAL)
            for datapath in list(self.datapaths.values()):
                self._request_flow_stats(datapath)

    def _request_flow_stats(self, datapath):
        """Send an OFPFlowStatsRequest to one switch.

        Parameters
        ----------
        datapath : ryu datapath - the target switch
        """
        parser = datapath.ofproto_parser
        req    = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        self.logger.debug('Flow stats requested from %016x', datapath.id)

    # ------------------------------------------------------------------
    # Flow stats reply handler
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Process one switch's flow stats reply.

        For every IPv4 flow with priority 1 (i.e. learned flows, not the
        table-miss rule):
            1. Extract a feature dictionary from the stat entry.
            2. Route the dict to the correct protocol buffer.
            3. If a buffer is full, drain it (_drain_buffer).
            4. Persist each flow record to the CSV file.

        Parameters
        ----------
        ev : EventOFPFlowStatsReply - delivered by RYU event dispatch
        """
        body      = ev.msg.body
        dpid      = ev.msg.datapath.id

        # Only look at priority-1 IPv4 flow entries (skip table-miss at p=0)
        ip_flows = [
            flow for flow in body
            if flow.priority == 1
            and flow.match.get('eth_type') == ether_types.ETH_TYPE_IP   # IPv4 only
        ]

        self.logger.debug(
            'Stats reply from %016x: %d IPv4 flows', dpid, len(ip_flows),
        )

        for stat in ip_flows:
            features = extract_flow_features(stat)
            if features is None:
                # Skip protocol if it is not ICMP/TCP/UDP
                continue

            proto = features['Ip_protocole']  # 'icmp' | 'tcp' | 'udp'

            # Buffer the record
            self._buffers[proto].append(features)

            # Check if we have a full window
            if len(self._buffers[proto]) >= BATCH_SIZE:
                self._drain_buffer(proto)

    # ------------------------------------------------------------------
    # Window processing
    # ------------------------------------------------------------------

    def _drain_buffer(self, proto: str):
        """Extract one BATCH_SIZE window from the protocol buffer and process it.

        Pops the first BATCH_SIZE records, converts to a DataFrame, calls the
        anomaly detection stub, and slides the buffer forward.

        Parameters
        ----------
        proto : str - 'icmp' | 'tcp' | 'udp'
        """
        window   = self._buffers[proto][:BATCH_SIZE]
        self._buffers[proto] = self._buffers[proto][BATCH_SIZE:]

        self.logger.info(
            'Processing %s window (%d flows). Buffer remaining: %d',
            proto.upper(), BATCH_SIZE, len(self._buffers[proto]),
        )

        self._process_window(proto, window)

    def _process_window(self, proto: str, records: List[dict]):
        """Run the anomaly detection pipeline on one completed window.

        Steps
        -----
        1. preprocess_for_autoencoder() -> X_array
        2. _detect_anomaly(X_array, proto) -> is_attack, rmse
        3. If attack: _classify_attack() [stub] -> attack_type
        4. _record_attack() -> History table

        Parameters
        ----------
        proto   : str - 'icmp' | 'tcp' | 'udp'
        records : list of dict - BATCH_SIZE feature dicts
        """
        is_attack, rmse = self._detect_anomaly(records, proto)
        attack_type = ''

        if is_attack:
            df          = pd.DataFrame(records)
            attack_type = self._classify_attack(records, proto)
            attacker    = identify_attacker(df)
            victim      = identify_victim(df)
            port        = 0 if proto == 'icmp' else df['Port_dst'].mode()[0]

            # log window timestamps for dataset labeling
            start = records[0].get('Timestamp', datetime.now().timestamp())
            end   = records[-1].get('Timestamp', datetime.now().timestamp())
            self._log_attack_window(proto, start, end)

            self.logger.warning(
                'ATTACK DETECTED  proto=%s  type=%s  attacker=%s  victim=%s  port=%s  rmse=%.4f',
                proto, attack_type, attacker, victim, port, rmse,
            )
            self._record_attack(proto, attack_type, attacker, victim, port)

        else:
            self.logger.info('Window verdict: Normal  proto=%s  rmse=%.4f', proto, rmse)

        for record in records:
            self._persist_packet(
                record,
                traffic='Attack' if is_attack else 'Normal',
                attack_type=attack_type if is_attack else '',
            )


    def _detect_anomaly(
        self, records: List[dict], proto: str
    ) -> Tuple[bool, float]:
        """Run autoencoder inference and compare RMSE to threshold.

        Parameters
        ----------
        records : list of dict
        proto   : str - 'icmp' | 'tcp' | 'udp'

        Returns
        -------
        tuple (is_attack: bool, rmse: float)
        """
        X = preprocess_for_autoencoder(records, proto, self._scalers[proto])
        session = self._autoencoders[proto]
        input_name  = session.get_inputs()[0].name
        X_reconstructed = session.run(None, {input_name: X})[0]
        mse  = np.mean(np.power(X - X_reconstructed, 2))
        rmse = float(np.sqrt(mse))
        self.logger.info('RMSE %s: %.4f (threshold: %.4f)', proto.upper(), rmse, THRESHOLDS[proto])
        return rmse > THRESHOLDS[proto], rmse

    # ------------------------------------------------------------------
    # AI stub (replace bodies when models are integrated)
    # ------------------------------------------------------------------

    def _classify_attack(
        self, records: List[dict], proto: str
    ) -> str:
        """[STUB] Run the Random Forest classifier on a detected attack window.

        Replace this body with:
            from pipeline import (preprocess_for_classifier,
                                  decode_attack_labels, majority_attack_type)
            df    = preprocess_for_classifier(records)
            preds = self._model_rf.predict(df)
            return majority_attack_type(decode_attack_labels(preds))

        Parameters
        ----------
        records : list of dict
        proto   : str

        Returns
        -------
        str - attack type label from ATTACK_LABELS
        """
        return 'Unknown'

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def _persist_packet(
        self,
        features: dict,
        traffic: str = 'Normal',
        attack_type: str = '',
    ):
        """Write one flow record to the CSV file.

        Opens and closes its own session so a single commit failure does not
        corrupt the long-running session used elsewhere.

        Parameters
        ----------
        features    : dict - output of extract_flow_features()
        traffic     : str  - 'Normal' or 'Attack'
        attack_type : str  - attack label, or '' for normal traffic
        """
        try:
            features['Timestamp'] = datetime.now().timestamp()
            features['Traffic'] = traffic
            features['Attack_type'] = attack_type
            self._csv_writer.writerow(features)
            self._csv_file.flush()
        except Exception as exc:
            self.logger.error('Failed to persist packet record: %s', exc)


    def _log_attack_window(self, proto: str, start: float, end: float):
        """Append a detected attack window timestamp to attack_log.json.

        Only active when COLLECTION_MODE is True. Used during dataset
        collection to map CSV timestamps to attack types automatically.

        Parameters
        ----------
        proto : str - protocol of detected attack window
        start : float - unix timestamp of first record in window
        end   : float - unix timestamp of last record in window
        """
        if not COLLECTION_MODE:
            return

        entry = {
            'proto': proto,
            'start': start,
            'end':   end,
        }

        # load existing log or start fresh
        log = []
        if os.path.exists(ATTACK_LOG_PATH):
            try:
                with open(ATTACK_LOG_PATH, 'r') as f:
                    content = f.read().strip()
                    if content:
                        log = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                log = []

        log.append(entry)
        print(
            f'[+] Attack window logged: proto={proto} start={start:.2f} end={end:.2f}'
        )

        with open(ATTACK_LOG_PATH, 'w') as f:
            json.dump(log, f, indent=2)


    def _record_attack(
        self,
        proto: str,
        attack_type: str,
        attacker: str,
        victim: str,
        port: int,
    ):
        """Write one detected attack event to the History table.

        After this write, switch's get_attackers() / get_attacked_ports() /
        get_banned_protocols() will pick up the new entry on the next PacketIn
        and apply mitigation automatically.

        Parameters
        ----------
        proto       : str - 'icmp' | 'tcp' | 'udp'
        attack_type : str - human-readable attack label
        attacker    : str - IP address or 'random' for multi-source attacks
        victim      : str - most common destination IP
        port        : int - destination port (0 for ICMP)
        """
        session = Session()
        try:
            if attacker == 'random' and proto == 'icmp':
                action = 'protocol_banned'
            elif attacker == 'random':
                action = 'port_blocked'
            else:
                action = 'ip_banned'
            
            row = History(
                Timestamp   = datetime.now().timestamp(),
                Attack_type = attack_type,
                Attacker    = attacker,
                Victim      = victim,
                Port        = str(port),
                Action      = action,   # still concerned about this 
                Protocole   = proto,
            )
            session.add(row)
            session.commit()
            self.logger.info(
                'Attack recorded in History: type=%s attacker=%s victim=%s port=%s proto=%s',
                attack_type, attacker, victim, port, proto,
            )
        except Exception as exc:
            session.rollback()
            self.logger.error('Failed to write History record: %s', exc)
        finally:
            session.close()
    
    def close(self):
        """Flush and close the CSV file when RYU shuts down."""
        self._csv_file.close()
        super().close()