#!/usr/bin/python

from topo_base.vm_to_fabric_intra_vn import VmToFabricIntraVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


'''
vif --list
-----------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/vif \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir \
--list
Vrouter Interface Table

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3,
       L2=Layer 2, D=DHCP, Vp=Vhost Physical, Pr=Promiscuous,
       Vnt=Native Vlan Tagged,Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface,
       Rfl=Receive Filtering Offload,Mon=Interface is Monitored,
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload,
       Df=Drop New Flows, L=MAC Learning Enabled,
       Proxy=MAC Requests Proxied Always, Er=Etree Root,
       Mn=Mirror without Vlan Tag, Ig=Igmp Trap Enabled

vif0/0      PCI: Mock
            Type:Physical HWaddr:00:1b:21:bb:f9:48 IPaddr:0.0.0.0
            Vrf:0 Mcast Vrf:65535 Flags:L3L2Vp QOS:0 Ref:6
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:1  bytes:0 errors:0
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
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.0.0.3
            Vrf:5 Mcast Vrf:5 Flags:PL3L2D QOS:0 Ref:6
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

nh --list
---------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/nh \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir \
 --list
Id:0          Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:1      Vrf:0
              Flags:Valid,

Id:21         Type:Tunnel         Fmly: AF_INET  Rid:0  Ref_cnt:2      Vrf:0
              Flags:Valid, MPLSoUDP, Etree Root,
              Oif:1 Len:14 Data:00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00
              Sip:8.0.0.2 Dip:8.0.0.3

Id:38         Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1      Vrf:5
              Flags:Valid, Policy,
              EncapFmly:0000 Oif:5 Len:14
              Encap Data: 02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00

flow -l
-------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/flow \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir -l
Flow table(size 80609280, entries 629760)

Entries: Created 0 Added 2 Deleted 0 Changed 1Processed 0
Used Overflow entries 0
(Created Flows/CPU: 0 0 0 0 0 0 0 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop \
N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT, L=Link Local Port)
Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

Index                Source:Port/Destination:Port                  Proto(V)
---------------------------------------------------------------------------
55764<=>385300       1.0.0.3:4145                                        1 (5)
                         1.0.0.5:0
(Gen: 4, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):38, Stats:0/0, SPort 62755,
 TTL 0, Sinfo 0.0.0.0)

179020<=>429828       de:ad:be:ef::1:0                                    1 (5)
                         de:ad:be:ef::2:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):38, Stats:1/62, SPort 54627,
 TTL 0, Sinfo 5.0.0.0)

385300<=>55764        1.0.0.5:4145                                        1 (5)
                         1.0.0.3:0
(Gen: 4, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):21, Stats:0/0,  SPort 64861,
 TTL 0, Sinfo 0.0.0.0)

429828<=>179020       de:ad:be:ef::2:0                                    1 (5)
                         de:ad:be:ef::1:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):21, Stats:0/0, SPort 60497,
 TTL 0, Sinfo 0.0.0.0)

rt --dump 5
-----------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/rt \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir \
--dump 5 --family bridge
Flags: L=Label Valid, Df=DHCP flood, Mm=Mac Moved, L2c=L2 Evpn Control Word,
       N=New Entry, Ec=EvpnControlProcessing
vRouter bridge table 0/5
Index    DestMac              Flags       Label/VNID      Nexthop      Stats
92304    2:e7:3:ea:67:f1      LDf             27           21            1

For ipv6:
de:ad:be:ef::1/128    128                       -             38
    2:c2:23:4c:d0:55(190492)

'''


class TestVmToFabricIntraVn(VmToFabricIntraVn):

    # program inet route and bridge route, so that packet not trapped to agent.
    def test_macip_learning_send_fabric_arp(self):
        self.tenant_vif.reload()
        self.tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.0.0.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_MAC_IP_LEARNING)
        self.tenant_vif.sync()

        # add bridge route
        bridge_rt = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            nh_idx=38)
        # add inet route
        inet_rt = InetRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            prefix="1.0.0.3",
            prefix_len=32,
            nh_idx=38)
        # sync all objects
        ObjectBase.sync_all()

        # send ARP request from vif3
        arp = ArpPacket(
            src='02:c2:23:4c:d0:55',
            dst='02:e7:03:ea:67:f1',
            sip='1.0.0.3',
            dip='1.0.0.5')
        pkt = arp.get_packet()
        pkt.show()

        # send packet
        self.tenant_vif.send_packet(pkt)

        # Check if the packet was sent to tenant vif
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.fabric_vif.get_vif_opackets())

    # Verify packet send to agent for MAC-IP learning
    def test_macip_learning_trap_agent_arp(self):
        self.tenant_vif.reload()
        self.tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.0.0.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_MAC_IP_LEARNING)
        self.tenant_vif.sync()

        # add inet route
        inet_rt = InetRoute(
            vrf=5,
            prefix="1.0.0.3",
            prefix_len=32,
            nh_idx=0)
        inet_rt.sync()

        # send ARP request from vif3
        arp = ArpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            src='02:c2:23:4c:d0:55',
            dst='02:e7:03:ea:67:f1')
        pkt = arp.get_packet()
        pkt.show()

        # send packet
        self.tenant_vif.send_packet(pkt)

        self.tenant_vif.reload()
        # Check if the packet was sent to agent vif
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.agent_vif.get_vif_opackets())

    # Verify stitched MAC programmed with incorrect value other than src mac,
    # so trap pacekt for MAC-IP leanrning
    def test_macip_learning_verify_stitched_mac_arp(self):
        self.tenant_vif.reload()
        self.tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.0.0.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_MAC_IP_LEARNING)
        self.tenant_vif.sync()

        # add bridge route
        bridge_rt = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:56",
            nh_idx=38)
        # add inet route
        inet_rt = InetRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:56",
            prefix="1.0.0.3",
            prefix_len=32,
            nh_idx=38)
        # sync all objects
        ObjectBase.sync_all()

        # send ARP request from vif3
        arp = ArpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            src='02:c2:23:4c:d0:55',
            dst='02:e7:03:ea:67:f1')
        pkt = arp.get_packet()
        pkt.show()

        # send packet
        self.tenant_vif.send_packet(pkt)

        self.tenant_vif.reload()
        self.agent_vif.reload()
        # Check if the packet was sent to agent vif
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.agent_vif.get_vif_opackets())

    # Verify bridge route
    def test_macip_learning_verify_bridge_route(self):
        self.tenant_vif.reload()
        self.tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.0.0.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_MAC_IP_LEARNING |
            constants.VIF_FLAG_L2_ENABLED)
        self.tenant_vif.sync()

        # Add tenant vif4
        self.vif4 = VirtualVif(
            name="tape703ea67-f1",
            ipv4_str="1.0.0.5",
            mac_str="02:e7:03:ea:67:f1",
            idx=6,
            vrf=5,
            mcast_vrf=5,
            nh_idx=28)

        # Add vif4 NextHop (inet)
        self.vif4_nh = EncapNextHop(
            encap_oif_id=self.vif4.idx(),
            encap="02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00",
            nh_idx=28,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)

        # add bridge route
        bridge_rt = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            nh_idx=38)

        # add bridge route
        bridge_rt = BridgeRoute(
            vrf=5,
            mac_str="02:e7:03:ea:67:f1",
            nh_idx=28)
        # sync all objects
        ObjectBase.sync_all()

        # send ARP request from vif3
        arp = ArpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            src='02:c2:23:4c:d0:55',
            dst='02:e7:03:ea:67:f1')
        pkt = arp.get_packet()
        pkt.show()

        # send packet
        self.tenant_vif.send_packet(pkt)

        # Check if the packet was not trapped to agent
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(0, self.agent_vif.get_vif_opackets())

    def test_macip_learning_trap_agent_bridge_route(self):
        self.tenant_vif.reload()
        self.tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.0.0.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_MAC_IP_LEARNING |
            constants.VIF_FLAG_L2_ENABLED)
        self.tenant_vif.sync()

        # Add tenant vif4
        self.vif4 = VirtualVif(
            name="tape703ea67-f1",
            ipv4_str="1.0.0.5",
            mac_str="02:e7:03:ea:67:f1",
            idx=6,
            vrf=5,
            mcast_vrf=5,
            nh_idx=28)

        # Add vif4 NextHop (inet)
        self.vif4_nh = EncapNextHop(
            encap_oif_id=self.vif4.idx(),
            encap="02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00",
            nh_idx=28,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)

        # add bridge route
        bridge_rt = BridgeRoute(
            vrf=5,
            mac_str="02:e7:03:ea:67:f1",
            nh_idx=28)
        # sync all objects
        ObjectBase.sync_all()

        # send ARP request from vif3
        arp = ArpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            src='02:c2:23:4c:d0:55',
            dst='02:e7:03:ea:67:f1')
        pkt = arp.get_packet()
        pkt.show()

        # send packet
        self.tenant_vif.send_packet(pkt)

        # Check if the packet was trapped to agent vif
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.agent_vif.get_vif_opackets())

    def test_macip_learning_verify_gwless_fwd_arp(self):
        self.tenant_vif.reload()
        self.tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.0.0.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_MAC_IP_LEARNING)
        self.tenant_vif.sync()

        # add inet route
        inet_rt = InetRoute(
            vrf=5,
            prefix="1.0.0.3",
            prefix_len=32,
            nh_idx=38)
        # sync all objects
        ObjectBase.sync_all()

        # send ARP request from vif3
        arp = ArpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            src='02:c2:23:4c:d0:55',
            dst='02:e7:03:ea:67:f1')
        pkt = arp.get_packet()
        pkt.show()

        # send packet
        self.tenant_vif.send_packet(pkt)

        self.tenant_vif.reload()
        self.fabric_vif.reload()
        # Check if the packet was sent to agent vif
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.fabric_vif.get_vif_opackets())

        self.vif_nh.reload()
        # Invalid encap data, so trap packet to agent
        self.vif_nh = EncapNextHop(
                encap_oif_id=self.tenant_vif.idx(),
                encap="03 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
                nh_idx=38,
                nh_vrf=5,
                nh_flags=constants.NH_FLAG_POLICY_ENABLED)
        self.vif_nh.sync()

        self.tenant_vif.clear()
        # send packet
        self.tenant_vif.send_packet(pkt)

        self.tenant_vif.reload()
        self.agent_vif.reload()
        # Check if the packet was sent to agent vif
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.agent_vif.get_vif_opackets())


class Test_MACIP_LEARNT_FLAG(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_macip_learnt_flag(self):
        # add virtual vif
        vmi = VirtualVif(name="tap_5", ipv4_str="192.168.1.1",
                         mac_str="de:ad:be:ef:00:02")
        # add encap nh 1
        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00",
                           nh_family=constants.AF_BRIDGE)
        # add encap nh 2
        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")
        # add bridge route
        bridge_rt = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:02",
            nh_idx=nh1.idx())
        # add inet route
        inet_rt = InetRoute(
            vrf=0,
            prefix="192.168.1.1",
            prefix_len=32,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_MAC_IP_LEARNT_FLAG)
        # sync all objects
        ObjectBase.sync_all()

        # Query the objects back
        self.assertEqual("tap_5", vmi.get_vif_name())
        self.assertEqual(constants.VR_RT_MAC_IP_LEARNT_FLAG,
                         inet_rt.get_rtr_label_flags())
