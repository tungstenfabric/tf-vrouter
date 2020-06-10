#!/usr/bin/python

from topo_base.vm_to_vm_intra_vn import VmToVmIntraVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

'''
vif --list
-----------

[root@090c8246aecd vtest_py]# $utils/vif --sock-dir $sock --list
Vrouter Interface Table

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3,
       L2=Layer 2, D=DHCP, Vp=Vhost Physical, Pr=Promiscuous,
       Vnt=Native Vlan Tagged, Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface,
       Rfl=Receive Filtering Offload, Mon=Interface is Monitored,
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload,
       Df=Drop New Flows, L=MAC Learning Enabled
       Proxy=MAC Requests Proxied Always, Er=Etree Root,
       Mn=Mirror without Vlan Tag, HbsL=HBS Left Intf
       HbsR=HBS Right Intf, Ig=Igmp Trap Enabled

vif0/3      PMD: tap88670c2e-11
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.4
            Vrf:2 Mcast Vrf:2 Flags:PL3L2D QOS:0 Ref:7
            RX port   packets:1 errors:0 syscalls:1
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:42 errors:0
            TX packets:1  bytes:42 errors:0
            Drops:0
            TX port   packets:1 errors:0 syscalls:1

vif0/4      PMD: tape703ea67-f1
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.5
            Vrf:2 Mcast Vrf:2 Flags:PL3L2D QOS:0 Ref:7
            RX port   packets:1 errors:0 syscalls:1
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:42 errors:0
            TX packets:1  bytes:42 errors:0
            Drops:0
            TX port   packets:1 errors:0 syscalls:1

rt --dump 2 --family bridge
----------------------------
[root@090c8246aecd vtest_py]# $utils/rt --sock-dir \
 $sock --dump 2 --family bridge
Flags: L=Label Valid, Df=DHCP flood, Mm=Mac Moved, L2c=L2 Evpn Control Word,
N=New Entry, Ec=EvpnControlProcessing
vRouter bridge table 0/2
Index       DestMac              Flags     Label/VNID      Nexthop       Stats
1256        2:e7:3:ea:67:f1                       -           32           1
7480        2:88:67:c:2e:11                       -           27           1
[root@090c8246aecd vtest_py]#

flow -l
-------
[root@090c8246aecd vtest_py]# $utils/flow --sock-dir $sock -l
Flow table(size 161218560, entries 629760)

Entries: Created 0 Added 2 Deleted 0 Changed 1Processed 0
Used Overflow entries 0
(Created Flows/CPU: 0 0 0 0 0 0 0 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT,
L=Link Local Port)
Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

Index                Source:Port/Destination:Port                      Proto(V)
-------------------------------------------------------------------------------
147464<=>239712       1.1.1.4:1136                                       1 (2)
                      1.1.1.5:0
(Gen: 1, K(nh):23, Action:F, Flags:, QOS:-1, S(nh):23,  Stats:1/42,
SPort 59275, TTL 0, Sinfo 3.0.0.0)

239712<=>147464       1.1.1.5:1136                                       1 (2)
                      1.1.1.4:0
(Gen: 1, K(nh):28, Action:F, Flags:, QOS:-1, S(nh):28,  Stats:1/42,
SPort 51988, TTL 0, Sinfo 4.0.0.0)

nh --list
---------
[root@090c8246aecd vtest_py]# $utils/nh --sock-dir $sock --list
Id:0      Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:1       Vrf:0
          Flags:Valid,

Id:23     Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1       Vrf:2
          Flags:Valid, Policy, Etree Root,
          EncapFmly:0000 Oif:3 Len:14
          Encap Data: 02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00

Id:27     Type:Encap          Fmly:AF_BRIDGE  Rid:0  Ref_cnt:2      Vrf:2
          Flags:Valid, Policy, Etree Root,
          EncapFmly:0000 Oif:3 Len:14
          Encap Data: 02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00

Id:28     Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1       Vrf:2
          Flags:Valid, Policy, Etree Root,
          EncapFmly:0000 Oif:4 Len:14
          Encap Data: 02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00

Id:32     Type:Encap          Fmly:AF_BRIDGE  Rid:0  Ref_cnt:2      Vrf:2
          Flags:Valid, Policy, Etree Root,
          EncapFmly:0000 Oif:4 Len:14
          Encap Data: 02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00
'''


class TestVmToVmIntraVn(VmToVmIntraVn):

    def test_vm_to_vm_intra_vn(self):

        self.vif3_nh_bridge.nhr_family = constants.AF_BRIDGE
        self.vif3_nh_bridge.sync()
        self.vif4_nh_bridge.nhr_family = constants.AF_BRIDGE
        self.vif4_nh_bridge.sync()

        # send ping request from vif3
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='1.1.1.5',
            smac='02:88:67:0c:2e:11',
            dmac='02:e7:03:ea:67:f1',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rec_pkt = self.vif3.send_and_receive_packet(pkt, self.vif4)

        # check if we got ICMP packet
        self.assertIsNotNone(rec_pkt)
        self.assertTrue(ICMP in rec_pkt)
        self.assertEqual("1.1.1.4", rec_pkt[IP].src)
        self.assertEqual("1.1.1.5", rec_pkt[IP].dst)

        # send ping request from vif4
        icmp = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.4',
            smac='02:e7:03:ea:67:f1',
            dmac='02:88:67:0c:2e:11',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rec_pkt = self.vif4.send_and_receive_packet(pkt, self.vif3)

        # check if we got ICMP packet
        self.assertIsNotNone(rec_pkt)
        self.assertTrue(ICMP in rec_pkt)
        self.assertEqual("1.1.1.5", rec_pkt[IP].src)
        self.assertEqual("1.1.1.4", rec_pkt[IP].dst)

        # Check if the packet was received at vif3 and vif4
        self.assertEqual(1, self.vif3.get_vif_opackets())
        self.assertEqual(1, self.vif3.get_vif_ipackets())

        self.assertEqual(1, self.vif4.get_vif_opackets())
        self.assertEqual(1, self.vif4.get_vif_ipackets())
