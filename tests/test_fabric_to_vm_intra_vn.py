#!/usr/bin/python

from topo_base.fabric_to_vm_intra_vn import FabricToVmIntraVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

'''
vif --list
-----------
Vrouter Interface Table

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3,
       L2=Layer 2, D=DHCP, Vp=Vhost Physical, Pr=Promiscuous,
       Vnt=Native Vlan Tagged, Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface,
       Rfl=Receive Filtering Offload, Mon=Interface is Monitored
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload,
       Df=Drop New Flows, L=MAC Learning Enabled,
       Proxy=MAC Requests Proxied Always, Er=Etree Root,
       Mn=Mirror without Vlan Tag, Ig=Igmp Trap Enabled

vif0/0      PCI: Mock
            Type:Physical HWaddr:00:1b:21:bb:f9:48 IPaddr:0.0.0.0
            Vrf:0 Mcast Vrf:65535 Flags:L3L2Vp QOS:0 Ref:7
            RX port   packets:1 errors:0 syscalls:1
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:88 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/1      PMD: vhost0 Mock
            Type:Host HWaddr:00:1b:21:bb:f9:48 IPaddr:8.0.0.2
            Vrf:0 Mcast Vrf:65535 Flags:L3D QOS:0 Ref:6
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/2      Socket: unix Mock
            Type:Agent HWaddr:00:00:5e:00:01:00 IPaddr:0.0.0.0
            Vrf:65535 Mcast Vrf:65535 Flags:L3 QOS:0 Ref:5
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/5      PMD: tapc2234cd0-55
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.3
            Vrf:5 Mcast Vrf:5 Flags:PL3L2D QOS:0 Ref:7
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:1  bytes:42 errors:0
            Drops:0
            TX port   packets:1 errors:0 syscalls:1

nh --list
---------
[root@090c8246aecd vtest_py]# $utils/nh --sock-dir $sock --list
Id:0          Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:1021  Vrf:0
              Flags:Valid,

Id:10         Type:Receive        Fmly: AF_INET  Rid:0  Ref_cnt:2     Vrf:1
              Flags:Valid, Policy(R), Etree Root,
              Oif:1

Id:21         Type:Tunnel         Fmly: AF_INET  Rid:0  Ref_cnt:1     Vrf:0
              Flags:Valid, MPLSoUDP, Etree Root,
              Oif:0 Len:14 Data:00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00
              Sip:8.0.0.2 Dip:8.0.0.3

Id:38         Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1     Vrf:5
              Flags:Valid, Policy, Etree Root,
              EncapFmly:0000 Oif:5 Len:14
              Encap Data: 02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00

Id:44         Type:Encap          Fmly:AF_BRIDGE  Rid:0  Ref_cnt:2    Vrf:5
              Flags:Valid, Policy, Etree Root,
              EncapFmly:0000 Oif:5 Len:14
              Encap Data: 02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00

flow -l
-------
[root@090c8246aecd vtest_py]# $utils/flow --sock-dir $sock -l
Flow table(size 80609280, entries 629760)

Entries: Created 0 Added 2 Deleted 0 Changed 1Processed 0 Used Overflow
entries 0
(Created Flows/CPU: 0 0 0 0 0 0 0 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT,
L=Link Local Port)
Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

    Index                Source:Port/Destination:Port               Proto(V)
-----------------------------------------------------------------------------
   255616<=>410748       1.1.1.3:4145                                1 (5)
                         1.1.1.5:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):38,  Stats:0/0,
SPort 60847, TTL 0, Sinfo 0.0.0.0)

   410748<=>255616       1.1.1.5:4145                                 1 (5)
                         1.1.1.3:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):21,  Stats:1/42,
SPort 50789, TTL 0, Sinfo 8.0.0.3)

rt --dump 0
-----------
[root@090c8246aecd vtest_py]#
$utils/rt --sock-dir $sock --dump 0 --family inet | grep "8.0.0.2 "\\">"
8.0.0.2/32             32            T          -             10        -

mpls --dump
-----------
[root@090c8246aecd vtest_py]# $utils/mpls --sock-dir $sock --dump
MPLS Input Label Map

   Label    NextHop
-------------------
      42        44

'''


class TestFabricToVmIntraVn(FabricToVmIntraVn):

    def test_fabric_to_vm_intra_vn(self):

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.3',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            icmp_type=constants.ECHO_REPLY)
        pkt = icmp_inner.get_packet()
        self.assertIsNotNone(pkt)

        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac='00:1b:21:bb:f9:46',
            dmac='00:1b:21:bb:f9:48',
            sport=53363,
            dport=6635,
            id=10,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        rcv_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, self.tenant_vif)
        self.assertIsNotNone(rcv_pkt)
        self.assertTrue(ICMP in rcv_pkt)
        self.assertEqual("1.1.1.5", rcv_pkt[IP].src)
        self.assertEqual("1.1.1.3", rcv_pkt[IP].dst)

        # Check if the packet was received at tenant vif
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())
