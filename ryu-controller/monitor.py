"""monitor.py - RYU monitoring app (no AI models yet).

Architecture
------------
This app extends switch.SimpleSwitch13, inheriting all MAC-learning and
mitigation-policy logic, then layers two additional responsibilities
on top:

    1. Datapath tracking  - register/unregister switches as they connect.
    2. Periodic stat polling - every POLL_INTERVAL seconds, ask every known
       switch for its full flow table statistics.
    3. Feature extraction - convert raw OpenFlow stats into feature dicts
       using pipeline.extract_flow_features() (the pipeline module is the
       single source of truth for feature engineering).
    4. Protocol buffering - accumulate ICMP / TCP / UDP records separately
       in fixed-size windows of BATCH_SIZE flows.
    5. traffic persistence - write every processed flow record to the CSV file.

AI integration (COMING LATER)
------------------------------
When the models are trained, steps 6-9 will be added inside _process_window():
    6. Preprocessing via pipeline.preprocess_for_autoencoder()
    7. Anomaly detection with the autoencoder (RMSE vs threshold)
    8. Attack classification via pipeline.preprocess_for_classifier() + RF
    9. Write attack events to the History table + let switch mitigate

The stubs _detect_anomaly() and _classify_attack() already exist in this file
so the insertion points are clear. They currently return no-op values.

Usage
-----
    source ~/ryu-env/bin/activate
    ryu-manager monitor.py
"""


import switch

import os
import sys

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


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models import Session, History
from pipeline import (
    extract_flow_features,
    AUTOENCODER_FEATURES,
    RF_FEATURES,
    ATTACK_LABELS,
    identify_attacker,
    identify_victim,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL  = 10    # seconds between stat requests
BATCH_SIZE     = 30    # number of flows per protocol window before processing

# Autoencoder detection thresholds (RMSE). Placeholder until models are trained.
THRESHOLD_ICMP = 0.279
THRESHOLD_TCP  = 0.090
THRESHOLD_UDP  = 0.100   # TODO: confirm once UDP model is trained

THRESHOLDS: Dict[str, float] = {
    'icmp': THRESHOLD_ICMP,
    'tcp':  THRESHOLD_TCP,
    'udp':  THRESHOLD_UDP,
}

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

    AI hooks (stubs, not yet active)
    --------------------------------
    * _detect_anomaly()  - will call the autoencoder + pipeline preprocessing.
    * _classify_attack() - will call the RF classifier + pipeline preprocessing.
    * _record_attack()   - will write to the History table.
    These are already wired into _process_window() but return no-ops until the
    model files exist.
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

        # CSV logging setup, for training data collection
        file_exists = os.path.exists('traffic_log.csv')
        self._csv_file = open('traffic_log.csv', 'a', newline='')
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=[
            'Timestamp', 'Ip_src', 'Ip_dst', 'Port_src', 'Port_dst',
            'Ip_protocole', 'Type_protocole', 'Icmp_type',
            'Flow_duration', 'Packet_count', 'Byte_count',
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
                # Protocol not ICMP/TCP/UDP -> skip
                continue

            proto = features['Ip_protocole']  # 'icmp' | 'tcp' | 'udp'

            # Buffer the record
            self._buffers[proto].append(features)

            # Persist raw flow record to CSV file immediately (before windowing)
            self._persist_packet(features, traffic='Normal', attack_type='')

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
        """Run the full detection pipeline on one completed window.

        Current state (no models): logs 'Normal' for every window.
        Future state (with models):
            1. preprocess_for_autoencoder() → X_array
            2. _detect_anomaly(X_array, proto) → is_attack, rmse
            3. If attack:
                a. preprocess_for_classifier(records) → X_rf
                b. _classify_attack(X_rf) → attack_type
                c. _record_attack(records, proto, attack_type)

        Parameters
        ----------
        proto   : str - 'icmp' | 'tcp' | 'udp'
        records : list of dict - BATCH_SIZE feature dicts
        """
        # -----------------------------------------------------------
        # STUB: anomaly detection - replace when models are available
        # -----------------------------------------------------------
        is_attack, rmse = self._detect_anomaly(records, proto)

        if is_attack:
            # -----------------------------------------------------------
            # STUB: classification - replace when RF model is available
            # -----------------------------------------------------------
            df          = pd.DataFrame(records)
            attack_type = self._classify_attack(records, proto)
            attacker    = identify_attacker(df)
            victim      = identify_victim(df)
            port        = 0 if proto == 'icmp' else df['Port_dst'].mode()[0]

            self.logger.warning(
                'ATTACK DETECTED  proto=%s  type=%s  attacker=%s  victim=%s  port=%s  rmse=%.4f',
                proto, attack_type, attacker, victim, port, rmse,
            )

            self._record_attack(proto, attack_type, attacker, victim, port)
        else:
            self.logger.info('Window verdict: Normal  proto=%s  rmse=%.4f', proto, rmse)

    # ------------------------------------------------------------------
    # AI stubs (replace bodies when models are integrated)
    # ------------------------------------------------------------------

    def _detect_anomaly(
        self, records: List[dict], proto: str
    ) -> Tuple[bool, float]:
        """[STUB] Run autoencoder inference and compare RMSE to threshold.

        Replace this body with:
            from pipeline import preprocess_for_autoencoder, compute_rmse
            X = preprocess_for_autoencoder(records, proto, self._scalers[proto])
            loss, _ = self._autoencoders[proto].evaluate(X, X, verbose=0)
            rmse = compute_rmse(loss)
            return rmse > THRESHOLDS[proto], rmse

        Parameters
        ----------
        records : list of dict
        proto   : str - 'icmp' | 'tcp' | 'udp'

        Returns
        -------
        tuple (is_attack: bool, rmse: float)
        """
        # Always return normal until models are loaded
        return False, 0.0

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
            row = {
                "Timestamp"      : features.get('Timestamp', datetime.now().timestamp()),
                "Ip_src"         : features['Ip_src'],
                "Ip_dst"         : features['Ip_dst'],
                "Port_src"       : features['Port_src'],
                "Port_dst"       : features['Port_dst'],
                "Ip_protocole"   : features['Ip_protocole'],
                "Type_protocole" : features['Type_protocole'],
                "Icmp_type"      : features['Icmp_type'],
                "Flow_duration"  : features['Flow_duration'],
                "Packet_count"   : features['Packet_count'],
                "Byte_count"     : features['Bytes'],
                "Traffic"        : traffic,
                "Attack_type"    : attack_type,
            }
            self._csv_writer.writerow(row)
            self._csv_file.flush()
        except Exception as exc:
            self.logger.error('Failed to persist packet record: %s', exc)

    def _record_attack(
        self,
        proto: str,
        attack_type: str,
        attacker: str,
        victim: str,
        port,
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
            row = History(
                Timestamp   = datetime.now().timestamp(),
                Attack_type = attack_type,
                Attacker    = attacker,
                Victim      = victim,
                Port        = str(port),
                Action      = '',           # filled by switch after mitigation
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