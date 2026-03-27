#!/usr/bin/env python3

"""
SDN + IDS + AI Topology
------------------------
Logical DMZ and LAN separation using SDN (no router)

           c0 (Ryu Controller)
                   |
                 s2 (Core / Monitoring)
                |       |
         (DMZ) s1 --- s3 (LAN)
                |       |-- h1
                http    |-- h2
                        |-- h3
                        |-- ftp
                        |-- smtp
                        |-- dns

Notes:
- DMZ subnet : 192.168.10.0/24 (http)
- LAN subnet : 192.168.20.0/24 (hosts + servers)
- s2 is the central monitoring point (IDS via Ryu flow stats)
- Inter-subnet traffic is handled via SDN rules (no default routing)
"""

from mininet.net import Mininet
from mininet.node import Host, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def myNetwork():
    net = Mininet(topo=None, build=False)

    info('*** Controller\n')
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip='127.0.0.1',
        protocol='tcp',
        port=6633
    )

    info('*** Switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)  # DMZ (supposedly)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)  # Core (monitoring)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)  # LAN

    info('*** DMZ host\n')
    http = net.addHost(
        'http',
        cls=Host,
        ip='192.168.10.10/24',
        mac='00:00:00:00:01:01'
    )

    info('*** LAN hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='192.168.20.101/24', mac='00:00:00:00:02:01')
    h2 = net.addHost('h2', cls=Host, ip='192.168.20.102/24', mac='00:00:00:00:02:02')
    h3 = net.addHost('h3', cls=Host, ip='192.168.20.103/24', mac='00:00:00:00:02:03')

    ftp = net.addHost('ftp', cls=Host, ip='192.168.20.10/24', mac='00:00:00:00:02:10')
    smtp = net.addHost('smtp', cls=Host, ip='192.168.20.11/24', mac='00:00:00:00:02:11')
    dns = net.addHost('dns', cls=Host, ip='192.168.20.12/24', mac='00:00:00:00:02:12')

    info('*** Links\n')
    # DMZ
    net.addLink(http, s1)

    # Core path (chain)
    net.addLink(s1, s2)
    net.addLink(s2, s3)

    # LAN
    net.addLink(s3, h1)
    net.addLink(s3, h2)
    net.addLink(s3, h3)
    net.addLink(s3, ftp)
    net.addLink(s3, smtp)
    net.addLink(s3, dns)

    # Redundant link to create loop for testing STP
    net.addLink(s1, s3)

    info('*** Build & start\n')
    net.build()

    for controller in net.controllers:
        controller.start()

    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    # Enable STP on all switches
    s1.cmd('ovs-vsctl set Bridge s1 stp_enable=true')
    s2.cmd('ovs-vsctl set Bridge s2 stp_enable=true')
    s3.cmd('ovs-vsctl set Bridge s3 stp_enable=true')

    info('*** Ready\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()