"""switch2.py - OpenFlow 1.3 learning switch with DB-driven mitigation policy.

Responsibilities
----------------
* Learn MAC -> port mappings and install protocol-aware flow entries.
* Before committing forwarding actions, query the database for:
    - known attacker IPs   -> drop all their traffic
    - attacked ports       -> drop traffic on those ports
    - banned protocols     -> drop that protocol entirely
* Count dropped packets and flush the running total to the DB in chunks
  of DROP_FLUSH_THRESHOLD (avoids a DB write on every single drop).

This module is imported by monitor.py, which extends the class.
Run directly only for testing basic switching (no AI models needed).

Usage
-----
    ryu-manager switch2.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

# Packet parsing
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.packet import in_proto, ipv4, icmp, tcp, udp, arp

from models import Session, History, Packets_dropped

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

DROP_FLUSH_THRESHOLD = 40   # write to DB after this many locally-counted drops
FLOW_IDLE_TIMEOUT    = 60   # seconds before an inactive flow entry expires
FLOW_HARD_TIMEOUT    = 120  # absolute seconds before a flow entry expires


# ---------------------------------------------------------------------------
# Helper: protocol detection
# ---------------------------------------------------------------------------

def _parse_ip_layer(pkt, ip_proto, parser):
    """Extract protocol-specific fields from a parsed packet.

    Parameters
    ----------
    pkt      : ryu.lib.packet.packet.Packet - already-parsed packet object
    ip_proto : int - value of ip.proto (1=ICMP, 6=TCP, 17=UDP)
    parser   : datapath ofproto_parser - used only for OFPMatch construction

    Returns
    -------
    tuple \(proto_name, src_port, dst_port, match_kwargs\)
    - proto_name  : str  - 'icmp' | 'tcp' | 'udp'
    - src_port    : int  - 0 for ICMP (no ports)
    - dst_port    : int  - 0 for ICMP (no ports)
    - match_kwargs: dict - extra keyword args to pass to OFPMatch
    """
    if ip_proto == in_proto.IPPROTO_ICMP:
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        return (
            'icmp',
            0, 0,
            {'ip_proto': ip_proto,
             'icmpv4_type': pkt_icmp.type,
             'icmpv4_code': pkt_icmp.code},
        )

    if ip_proto == in_proto.IPPROTO_TCP:
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        return (
            'tcp',
            pkt_tcp.src_port,
            pkt_tcp.dst_port,
            {'ip_proto': ip_proto,
             'tcp_src': pkt_tcp.src_port,
             'tcp_dst': pkt_tcp.dst_port,
             'tcp_flags': pkt_tcp.bits},
        )

    if ip_proto == in_proto.IPPROTO_UDP:
        pkt_udp = pkt.get_protocol(udp.udp)
        return (
            'udp',
            pkt_udp.src_port,
            pkt_udp.dst_port,
            {'ip_proto': ip_proto,
             'udp_src': pkt_udp.src_port,
             'udp_dst': pkt_udp.dst_port},
        )

    # Unsupported protocol: caller should skip flow installation
    return None, 0, 0, {}


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

class SimpleSwitch13(app_manager.RyuApp):
    """OpenFlow 1.3 learning switch with runtime mitigation policy.

    Switching behaviour
    -------------------
    * On the first packet of each flow (PacketIn), learn src MAC -> in_port.
    * If the destination MAC is already known, install a specific flow entry
      so future packets of the same flow are handled entirely by the switch.
    * If the destination is unknown, flood.

    Mitigation policy
    -----------------
    Before installing a forwarding rule the handler checks three DB lists:
        1. Attacker IPs   - traffic from/to those IPs is dropped.
        2. Attacked ports - traffic on those ports is dropped.
        3. Banned protos  - that protocol is dropped globally.
    A drop rule (empty actions list) is installed instead of a forward rule,
    so subsequent packets in the same flow are dropped by the switch without
    involving the controller.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # MAC-address learning table: {dpid: {mac: port}}
        self.mac_to_port = {}
        # Local counter; flushed to DB every DROP_FLUSH_THRESHOLD drops
        self._drop_counter = 0

    # ------------------------------------------------------------------
    # OpenFlow event: switch connected
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install the table-miss rule when a switch first connects.

        The table-miss entry has priority 0 and matches every packet.
        Its action is to send the packet to the controller (PacketIn),
        which is how the learning process begins for new flows.
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        match   = parser.OFPMatch()     # empty means match all packets (table-miss)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info('Switch %016x connected - table-miss rule installed.', datapath.id)

    # ------------------------------------------------------------------
    # OpenFlow event: packet-in (core learning + policy logic)
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Learn MAC addresses and enforce mitigation policy on each new flow.

        Steps
        -----
        1. Parse Ethernet frame and learn src MAC -> port.
        2. Resolve output port (known dst MAC or FLOOD).
        3. For IP traffic with a known output port:
            a. Parse the IP/protocol layer.
            b. Check the three policy lists from the database.
            c. Build an OFPMatch and decide actions (forward or drop).
            d. Install the flow entry so the switch handles future packets.
        4. For ARP: install a specific ARP flow entry.
        5. Always send an OFPPacketOut for the current packet.
        """
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        # - Layer-2 parsing -----------------------------------------------
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP (topology discovery frames, not user traffic)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid    = datapath.id

        # - MAC learning --------------------------------------------------
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port   # src MAC -> port mapping learned/updated on every packet-in

        # - Port resolution -----------------------------------------------
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # - Flow installation (only when dst is known, i.e. not a flood) - 
        if out_port != ofproto.OFPP_FLOOD:

            # ---- IPv4 ----------------------------------------------------
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip       = pkt.get_protocol(ipv4.ipv4)
                src_ip   = ip.src
                dst_ip   = ip.dst
                ip_proto = ip.proto

                proto_name, src_port, dst_port, proto_match_kwargs = _parse_ip_layer(pkt, ip_proto, parser)

                if proto_name is None:
                    # Unrecognised protocol: let it flood without a matching rule
                    self._send_packet_out(datapath, msg, in_port, actions)
                    return

                # Build the match for this specific flow
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    **proto_match_kwargs,
                )

                # Apply mitigation policy
                actions = self._apply_policy(
                    actions, src_ip, dst_ip,
                    src_port, dst_port, proto_name,
                )

                # Track drops
                if not actions:
                    self._count_drop()

                # install the flow entry and forward the packet
                self._install_flow_and_forward(
                    datapath, msg, match, actions, in_port,
                )
                return

            # ---- ARP -----------------------------------------------------
            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                ar  = pkt.get_protocol(arp.arp)
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_op=ar.opcode,       # ARP request or reply
                    arp_spa=ar.src_ip,      # ARP sender protocol address (IP)
                    arp_tpa=ar.dst_ip,      # ARP target protocol address (IP)
                    arp_sha=ar.src_mac,     # ARP sender hardware address (MAC)
                    arp_tha=ar.dst_mac,     # ARP target hardware address (MAC)
                )
                self._install_flow_and_forward(
                    datapath, msg, match, actions, in_port,
                    idle=60, hard=140,
                )
                return

        # - Flood path (no flow rule installed) ----------------------------
        self._send_packet_out(datapath, msg, in_port, actions)

    # ------------------------------------------------------------------
    # Policy helpers
    # ------------------------------------------------------------------

    def _apply_policy(self, actions, src_ip, dst_ip, src_port, dst_port, proto):
        """Return the correct actions list after checking all three policy lists.

        Checks attacker IPs first (most severe), then attacked ports, then
        banned protocols. Returns an empty list (= drop) on first match.

        Parameters
        ----------
        actions   : list - the candidate forward actions
        src_ip    : str  - source IP of the flow
        dst_ip    : str  - destination IP of the flow
        src_port  : int  - source port (0 for ICMP)
        dst_port  : int  - destination port (0 for ICMP)
        proto     : str  - 'icmp' | 'tcp' | 'udp'

        Returns
        -------
        list - original actions (forward) or [] (drop)
        """
        attackers         = self._get_attackers()
        attacked_ports    = self._get_attacked_ports()
        banned_protocols  = self._get_banned_protocols()

        if attackers and (src_ip in attackers or dst_ip in attackers):
            self.logger.warning('DROP - banned IP: src=%s dst=%s', src_ip, dst_ip)
            return []

        if attacked_ports and (src_port in attacked_ports or dst_port in attacked_ports):
            self.logger.warning('DROP - attacked port: src_port=%s dst_port=%s', src_port, dst_port)
            return []

        if banned_protocols and proto in banned_protocols:
            self.logger.warning('DROP - banned protocol: %s', proto)
            return []

        return actions

    # ------------------------------------------------------------------
    # Database query helpers (each opens and closes its own session)
    # ------------------------------------------------------------------

    def _get_attackers(self):
        """Return a set of known attacker IP addresses from the history table.

        Only entries where Attacker is not 'random' are included (random means
        the attack source was distributed and no single IP can be blamed).

        Returns
        -------
        set[str]
        """
        session = Session()
        try:
            rows = (session.query(History.Attacker)
                    .filter(History.Attacker != 'random')
                    .distinct()
                    .all())
            return {row.Attacker for row in rows}
        finally:
            session.close()

    def _get_attacked_ports(self):
        """Return a set of destination ports targeted by distributed attackers.

        These are ports recorded in history rows where the attacker was listed
        as 'random' (no dominant source IP). The port is blocked to mitigate
        the attack even without knowing a single attacker IP.

        Returns
        -------
        set[int | str]
        """
        session = Session()
        try:
            rows = (session.query(History.Port)
                    .filter(History.Attacker == 'random')
                    .distinct()
                    .all())
            return {row.Port for row in rows}
        finally:
            session.close()

    def _get_banned_protocols(self):
        """Return a set of protocol names that are currently banned.

        Currently targets ICMP flood mitigation (protocol == 'icmp').
        Extend the filter to handle additional protocols as needed.

        Returns
        -------
        set[str]
        """
        session = Session()
        try:
            rows = (session.query(History.Protocole)
                    .filter(History.Protocole == 'icmp')
                    .distinct()
                    .all())
            return {row.Protocole for row in rows}
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Drop counter
    # ------------------------------------------------------------------

    def _count_drop(self):
        """Increment the local drop counter and flush to DB at threshold.

        Avoids one DB write per drop by batching updates in groups of
        DROP_FLUSH_THRESHOLD (default 40).
        """
        self._drop_counter += 1
        if self._drop_counter >= DROP_FLUSH_THRESHOLD:
            self._flush_drop_count()
            self._drop_counter = 0

    def _flush_drop_count(self):
        """Persist the current batch of DROP_FLUSH_THRESHOLD drops to the DB.

        Adds to the existing counter row if one exists, or creates a fresh one.
        Called automatically by _count_drop(); also safe to call manually at
        shutdown to flush any remainder.
        """
        session = Session()
        try:
            entry = session.query(Packets_dropped).first()
            if entry:
                entry.Count += DROP_FLUSH_THRESHOLD
            else:
                session.add(Packets_dropped(Count=DROP_FLUSH_THRESHOLD))
            session.commit()
            self.logger.debug('Flushed %d dropped packets to DB.', DROP_FLUSH_THRESHOLD)
        finally:
            session.close()

    # ------------------------------------------------------------------
    # OpenFlow utility helpers
    # ------------------------------------------------------------------

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, idle=0, hard=0):
        """Build and send an OFPFlowMod to install a flow entry on the switch.

        Parameters
        ----------
        datapath  : ryu datapath object
        priority  : int - higher number wins on conflict
        match     : OFPMatch
        actions   : list - empty list installs a drop rule
        buffer_id : int | None - if set, the switch releases the buffered packet
        idle      : int - idle timeout in seconds (0 = never)
        hard      : int - hard timeout in seconds (0 = never)
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        instructions = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions,
        )]

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle,
            hard_timeout=hard,
        )
        if buffer_id is not None:
            kwargs['buffer_id'] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def _install_flow_and_forward(self, datapath, msg, match, actions,
                                  in_port, idle=FLOW_IDLE_TIMEOUT,
                                  hard=FLOW_HARD_TIMEOUT):
        """Install a flow rule then forward the triggering packet.

        If the switch buffered the packet (buffer_id is valid), the FlowMod
        itself releases the buffer and no separate PacketOut is needed.
        Otherwise a PacketOut is sent with the raw packet bytes.

        Parameters
        ----------
        datapath : ryu datapath
        msg      : OFPPacketIn message
        match    : OFPMatch for the new flow rule
        actions  : list
        in_port  : int
        idle     : int - idle timeout (seconds)
        hard     : int - hard timeout (seconds)
        """
        ofproto = datapath.ofproto

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self._add_flow(datapath, priority=1, match=match, actions=actions,
                           buffer_id=msg.buffer_id, idle=idle, hard=hard)
        else:
            self._add_flow(datapath, priority=1, match=match, actions=actions,
                           idle=idle, hard=hard)
            self._send_packet_out(datapath, msg, in_port, actions)

    def _send_packet_out(self, datapath, msg, in_port, actions):
        """Send an OFPPacketOut to forward (or drop) the current packet.

        Used for the flood path and for the no-buffer case after a FlowMod.

        Parameters
        ----------
        datapath : ryu datapath
        msg      : OFPPacketIn message
        in_port  : int - original ingress port
        actions  : list - empty for drop, OFPActionOutput for forward
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        # If the switch did not buffer the packet, we need to include the raw data in the PacketOut message. 
        # If it did buffer, we can just reference the buffer_id and the switch will handle it.
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)