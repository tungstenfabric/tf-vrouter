#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa
'''
vif --list
-------------
Vrouter Interface Table

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3, L2=Layer 2
       D=DHCP, Vp=Vhost Physical, Pr=Promiscuous, Vnt=Native Vlan Tagged
       Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface, Rfl=Receive Filtering Offload, Mon=Interface is Monitored
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload, Df=Drop New Flows, L=MAC Learning Enabled
       Proxy=MAC Requests Proxied Always, Er=Etree Root, Mn=Mirror without Vlan Tag, HbsL=HBS Left Intf
       HbsR=HBS Right Intf, Ig=Igmp Trap Enabled, Ml=MAC-IP Learning Enabled

vif0/0      PCI: Mock
            Type:Physical HWaddr:0c:e1:49:a5:00:01 IPaddr:0.0.0.0
            Vrf:0 Mcast Vrf:65535 Flags:L3L2Vp QOS:0 Ref:7
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/1      PMD: vhost0 Mock NH: 10
            Type:Host HWaddr:ac:1f:6b:a5:0f:f4 IPaddr:192.168.1.1
            Vrf:0 Mcast Vrf:65535 Flags:L3L2Er QOS:0 Ref:8
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:1  bytes:42 errors:0
            Drops:0
            TX port   packets:1 errors:0 syscalls:1

vif0/2      Socket: unix Mock
            Type:Agent HWaddr:00:00:5e:00:01:00 IPaddr:0.0.0.0
            Vrf:65535 Mcast Vrf:65535 Flags:L3 QOS:0 Ref:7
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0 

vif0/3      PMD: tap241dae96-44 NH: 23
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.4
            Vrf:0 Mcast Vrf:2 Flags:PL3L2DProxyEr QOS:0 Ref:8
            RX port   packets:1 errors:0 syscalls:1
            RX queue  packets:1 errors:0
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:42 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

rt --dump
-----------
Match 192.168.1.1/32 in vRouter inet4 table 0/0/unicast

Flags: L=Label Valid, P=Proxy ARP, T=Trap ARP, F=Flood ARP, Ml=MAC-IP learnt route
vRouter inet4 routing table 0/0/unicast
Destination           PPL        Flags        Label         Nexthop    Stitched MAC(Index)
192.168.1.1/32          0            T          -             10        -

Match 1.1.1.4/32 in vRouter inet4 table 0/2/unicast

Flags: L=Label Valid, P=Proxy ARP, T=Trap ARP, F=Flood ARP, Ml=MAC-IP learnt route
vRouter inet4 routing table 0/2/unicast
Destination           PPL        Flags        Label         Nexthop    Stitched MAC(Index)
1.1.1.4/32              0            L          0              0        0:0:0:0:0:0(0)

nh --outputs
-------------

nh --get 23
------------
Id:23         Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:2          Vrf:0
              Flags:Valid, Policy, Etree Root,
              EncapFmly:0806 Oif:3 Len:14
              Encap Data: 02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00

nh --get 10
------------

Id:10         Type:Receive        Fmly: AF_INET  Rid:0  Ref_cnt:3          Vrf:1
              Flags:Valid, Policy(R), Etree Root,
              Oif:1


'''

class VmVhostVn(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

        self.fabric_vif = FabricVif(
            name="eth1",
            mac_str="0c:e1:49:a5:00:01")

        # Add tenant vif3
        self.vif3 = VirtualVif(
            idx=3,
            name="tap241dae96-44",
            ipv4_str="1.1.1.4",
            mac_str="00:00:5e:00:01:00",
            vrf=0,
            mcast_vrf=2,
            nh_idx=23,
            flags=constants.VIF_FLAG_MAC_PROXY | constants.VIF_FLAG_POLICY_ENABLED | constants.VIF_FLAG_DHCP_ENABLED |constants.NH_FLAG_ETREE_ROOT)

        # Add vhost0 vif
        self.vhost0_vif = VhostVif(
            ipv4_str="192.168.1.1",
            mac_str="ac:1f:6b:a5:0f:f4",
            idx=1,
            nh_idx=10,
            flags=constants.NH_FLAG_ETREE_ROOT)

        agent_vif = AgentVif(idx=2, flags=constants.VIF_FLAG_L3_ENABLED)

        # Add L3 Recv NH for vhost0
        self.l3_rcv_nh = ReceiveNextHop(1, nh_idx=10, nh_vrf=1,nh_flags=constants.NH_FLAG_RELAXED_POLICY | constants.NH_FLAG_ETREE_ROOT)
        # Add encap Nexthop
        self.l3_encap_nh = EncapNextHop(
            encap_oif_id=self.vif3.idx(),
            nh_idx=23,
            encap="02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00",
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT      ),
            encap_family=constants.VR_ETH_PROTO_ARP)
        
        # Add route for vhost0
        self.vhost_rt = InetRoute(
            vrf=0,
            prefix="192.168.1.1",
            prefix_len=32,
            nh_idx=self.l3_rcv_nh.idx(),
            rtr_label_flags=constants.VR_RT_ARP_TRAP_FLAG)

        # Add route for fabric
        self.vif3_rt = InetRoute(
            vrf=0,
            prefix="1.1.1.4",
            nh_idx=self.l3_encap_nh.idx(),
            rtr_label_flags=constants.VR_RT_ARP_PROXY_FLAG)
        
        self.bridge_route = BridgeRoute(
            vrf=0,
            mac_str="00:00:5e:00:01:00",
            nh_idx=10)

        ObjectBase.sync_all()
         # Add forward and reverse flow
       
        self.f_flow = InetFlow(
            sip='192.168.1.1',
            dip='1.1.1.4',
            sport=1136,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=10,
            src_nh_idx=self.l3_rcv_nh.idx(),
            flow_vrf=0,
            rflow_nh_idx=self.l3_encap_nh.idx())

        self.r_flow = InetFlow(
            sip='1.1.1.4',
            dip='192.168.1.1',
            sport=1136,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=self.l3_encap_nh.idx(),
            src_nh_idx=self.l3_encap_nh.idx(),
            flags=constants.VR_RFLOW_VALID,
            flow_vrf=0,
            rflow_nh_idx=self.l3_rcv_nh.idx())
        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)
 
    def teardown_method(self, method):
        ObjectBase.tearDown()
