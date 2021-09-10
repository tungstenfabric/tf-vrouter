#!/usr/bin/python

import os
import sys
import pytest
import subprocess
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestL3MHTunnelNH(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        # do auto cleanup and auto idx allocation for vif and nh
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

        self.fabric_vif1 = FabricVif(
            name="eth0",
            mac_str="00:1b:21:bb:f9:48",
            idx=0,
            ipv4_str="10.1.1.4")

        self.fabric_vif2 = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:49",
            idx=1,
            ipv4_str="20.1.1.4")

        self.fabric_vif3 = FabricVif(
            name="eth2",
            mac_str="00:1b:21:bb:f9:50",
            idx=2,
            ipv4_str="30.1.1.4")

        # Add tenant vif3
        self.vif3 = VirtualVif(
            idx=3,
            name="tap1",
            ipv4_str="1.1.1.4",
            ipv6_str="de:ad:be:ef::1",
            mac_str="00:00:5e:00:01:00",
            vrf=0,
            mcast_vrf=0,
            flags=None,
            nh_idx=23)

        # Add tenant vif4
        self.vif4 = VirtualVif(
            idx=4,
            name="tap2",
            ipv4_str="2.2.2.4",
            mac_str="00:00:5e:00:01:01",
            vrf=0,
            mcast_vrf=0,
            flags=None,
            nh_idx=28)

        self.vif5 = VirtualVif(
            idx=5,
            name="tap3",
            ipv4_str="5.1.1.10",
            ipv6_str="de:ad:be:ef::2",
            mac_str="00:00:34:00:11:02",
            vrf=0,
            mcast_vrf=0,
            flags=None,
            nh_idx=35)

        ObjectBase.sync_all()

    def teardown_method(self, method):
        ObjectBase.tearDown()

    # data transfer in packet mode in case of l3mh with 2 physical interfaces,
    # then make one of the interfaces invald and verify tunnel update followed
    # by pkt send from vm which should be received on a valid physical vif
    def test_l3mh_tunnel_nh_mpls_udp(self):
        encap1 = "00 22 22 22 22 22 00 11 11 11 11 11 08 00"
        encap2 = "00 33 33 33 33 33 00 11 11 11 11 11 08 00"
        encapall = encap1+" "+encap2
        oif_id = str(self.fabric_vif1.idx())+","+str(self.fabric_vif2.idx())
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=oif_id,
            encap=encapall,
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=21,
            nh_flags=(
                constants.NH_FLAG_TUNNEL_UDP_MPLS |
                constants.NH_FLAG_ETREE_ROOT |
                constants.NH_FLAG_TUNNEL_UNDERLAY_ECMP))

        tunnel_nh.sync()

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="00:00:5e:00:01:01",
            nh_idx=21,
            rtr_label_flags=3,
            rtr_label=128)

        bridge_route.sync()

        udp = UdpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='00:00:5e:00:01:00',
            dmac='00:00:5e:00:01:01',
            sport=0,
            dport=1)
        pkt = udp.get_packet()
        pkt.show()

        recv_pkt = self.vif3.send_and_receive_packet(pkt, self.fabric_vif1)
        recv_pkt.show()
        self.assertEqual(1, self.fabric_vif1.get_vif_opackets())
        tunnel_nh_get_cmd1 = ObjectBase.get_cli_output("nh --get 21")
        self.assertEqual(1, tunnel_nh_get_cmd1.count("Data:NULL"))

        # update tunnel, oif_id[0] to invalid
        tunnel_nh.nhr_encap_valid = [0, 1, 0]
        tunnel_nh.nhr_encap_oif_id = [0, 1, -1]
        tunnel_nh.sync()

        tunnel_nh_get_cmd2 = ObjectBase.get_cli_output("nh --get 21")
        self.assertEqual(2, tunnel_nh_get_cmd2.count("Data:NULL"))

        # check pkt on other physical interface
        recv_pkt2 = self.vif3.send_and_receive_packet(pkt, self.fabric_vif2)
        recv_pkt2.show()
        self.assertEqual(1, self.fabric_vif2.get_vif_opackets())

    # Multicast packet transfer from VM on compute 1 to to VM on compute 2 when
    # the nexthop marked is a composite nexthop with a component as a tunnel nh
    # during the L3MH case when one of the physical interfaces in down
    def test_l3mh_composite_tunnel_nh_mpls_udp(self):
        encap1 = "00 22 22 22 22 22 00 11 11 11 11 11 08 00"
        encap2 = "00 33 33 33 33 33 00 11 11 11 11 11 08 00"
        encapall = encap1+" "+encap2
        oif_id = str(self.fabric_vif1.idx())+","+str(self.fabric_vif2.idx())
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=oif_id,
            encap=encapall,
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=21,
            nh_flags=(
                constants.NH_FLAG_VALID |
                constants.NH_FLAG_TUNNEL_UDP_MPLS |
                constants.NH_FLAG_ETREE_ROOT |
                constants.NH_FLAG_TUNNEL_UNDERLAY_ECMP))
        tunnel_nh.sync()

        comp_flags = (constants.NH_FLAG_VALID |
                      constants.NH_FLAG_ETREE_ROOT |
                      constants.NH_FLAG_COMPOSITE_FABRIC)
        comp_ecmp_nh = CompositeNextHop(
            nh_idx=51,
            nh_family=constants.AF_BRIDGE,
            nh_vrf=0,
            nh_flags=comp_flags)

        comp_ecmp_nh.add_nexthop(10, tunnel_nh.idx())
        comp_ecmp_nh.sync()

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="00:00:5e:00:01:01",
            nh_idx=51,
            rtr_label_flags=3,
            rtr_label=128)

        bridge_route.sync()

        udp = UdpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='00:00:5e:00:01:00',
            dmac='00:00:5e:00:01:01',
            sport=0,
            dport=1)
        pkt = udp.get_packet()
        pkt.show()

        recv_pkt = self.vif3.send_and_receive_packet(pkt, self.fabric_vif1)
        recv_pkt.show()
        self.assertEqual(1, self.fabric_vif1.get_vif_opackets())
        tunnel_nh_get_cmd1 = ObjectBase.get_cli_output("nh --get 21")
        self.assertEqual(1, tunnel_nh_get_cmd1.count("Data:NULL"))

        # update tunnel, oif_id[0] to invalid
        tunnel_nh.nhr_encap_valid = [0, 1, 0]
        tunnel_nh.nhr_encap_oif_id = [0, 1, -1]
        tunnel_nh.sync()

        tunnel_nh_get_cmd2 = ObjectBase.get_cli_output("nh --get 21")
        self.assertEqual(2, tunnel_nh_get_cmd2.count("Data:NULL"))

        # check pkt on other physical interface
        recv_pkt2 = self.vif3.send_and_receive_packet(pkt, self.fabric_vif2)
        recv_pkt2.show()
        self.assertEqual(1, self.fabric_vif2.get_vif_opackets())

    # no valid encap for the tunnel nh should result in pkt drop and dropstats
    # increment. Then set one valid encap and send the pkt again.
    # No drop this time
    def test_l3mh_tunnel_nh_all_encap_invalid_pkt_drop(self):
        encap1 = "00 22 22 22 22 22 00 11 11 11 11 11 08 00"
        encap2 = "00 33 33 33 33 33 00 11 11 11 11 11 08 00"
        encapall = encap1+" "+encap2
        oif_id = "-1,-1"
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=oif_id,
            encap=encapall,
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=21,
            nh_flags=(
                constants.NH_FLAG_TUNNEL_UDP_MPLS |
                constants.NH_FLAG_ETREE_ROOT |
                constants.NH_FLAG_TUNNEL_UNDERLAY_ECMP))

        tunnel_nh.sync()

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="00:00:5e:00:01:01",
            nh_idx=21,
            rtr_label_flags=3,
            rtr_label=128)

        bridge_route.sync()

        udp = UdpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='00:00:5e:00:01:00',
            dmac='00:00:5e:00:01:01',
            sport=0,
            dport=1)
        pkt = udp.get_packet()
        pkt.show()

        recv_pkt = self.vif3.send_and_receive_packet(pkt, self.fabric_vif1)
        dropstats_cmd_str = "dropstats"
        dropstats_cmd = ObjectBase.get_cli_output(dropstats_cmd_str)
        self.assertEqual(1, "No L2 Route                   1" in dropstats_cmd)

        # update nh tunnel with one valid encap
        tunnel_nh.nhr_encap_oif_id = [0, 1, -1]
        tunnel_nh.nhr_encap_valid = [0, 1, 0]
        tunnel_nh.sync()
        bridge_route.sync()

        recv_pkt2 = self.vif3.send_and_receive_packet(pkt, self.fabric_vif2)
        recv_pkt2.show()
        self.assertEqual(1, self.fabric_vif2.get_vif_opackets())

    # data transfer in packet mode in case of l3mh with 3 physical interfaces
    def test_l3mh_tunnel_nh_gre(self):
        encap1 = "00 22 22 22 22 22 00 11 11 11 11 11 08 00"
        encap2 = "00 33 33 33 33 33 00 11 11 11 11 11 08 00"
        encap3 = "00 44 44 44 44 44 00 11 11 11 11 11 08 00"
        encapall = encap1+" "+encap2+" "+encap3
        oif_id = str(self.fabric_vif1.idx())+","+str(self.fabric_vif2.idx())
        oif_id += ","+str(self.fabric_vif3.idx())

        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=oif_id,
            encap=encapall,
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=21,
            nh_flags=(
                constants.NH_FLAG_TUNNEL_GRE |
                constants.NH_FLAG_ETREE_ROOT |
                constants.NH_FLAG_TUNNEL_UNDERLAY_ECMP))

        tunnel_nh.sync()

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="00:00:34:00:11:02",
            nh_idx=21,
            rtr_label_flags=3,
            rtr_label=128)

        bridge_route.sync()

        udp = Udpv6Packet(
            sipv6="de:ad:be:ef::1",
            dipv6="de:ad:be:ef::2",
            smac='00:00:5e:00:01:00',
            dmac='00:00:34:00:11:02',
            sport=0,
            dport=1)
        pkt = udp.get_packet()
        pkt.show()

        recv_pkt = self.vif3.send_and_receive_packet(pkt, self.fabric_vif2)
        recv_pkt.show()
        self.assertEqual(1, self.fabric_vif2.get_vif_opackets())

    # data transfer in packet mode in case of l3mh with 3 physical interfaces
    # with one of these physical intercaes in error state
    def test_l3mh_tunnel_nh_vxlan(self):
        encap1 = "00 22 22 22 22 22 00 11 11 11 11 11 08 00"
        encap2 = "00 33 33 33 33 33 00 11 11 11 11 11 08 00"
        encap3 = "00 44 44 44 44 44 00 11 11 11 11 11 08 00"
        encapall = encap1+" "+encap2+" "+encap3
        oif_id = "-1,"
        oif_id += str(self.fabric_vif2.idx())+","+str(self.fabric_vif3.idx())
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=oif_id,
            encap=encapall,
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=21,
            nh_flags=(
                constants.NH_FLAG_VALID |
                constants.NH_FLAG_TUNNEL_VXLAN |
                constants.NH_FLAG_TUNNEL_UNDERLAY_ECMP))

        tunnel_nh.sync()

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="00:00:34:00:11:02",
            nh_idx=21,
            rtr_label_flags=3,
            rtr_label=128)

        bridge_route.sync()

        udp = UdpPacket(
            sip='1.1.1.4',
            dip='5.1.1.10',
            smac='00:00:5e:00:01:00',
            dmac='00:00:34:00:11:02',
            sport=0,
            dport=1)
        pkt = udp.get_packet()
        pkt.show()

        recv_pkt = self.vif3.send_and_receive_packet(pkt, self.fabric_vif2)
        recv_pkt.show()
        self.assertTrue(VXLAN in recv_pkt)
        self.assertEqual(1, self.fabric_vif2.get_vif_opackets())

    # data transfer in flow mode in case of l3mh with 3 physical interfaces
    def test_l3mh_tunnel_nh_flow_mode(self):
        vif5 = VirtualVif(
            name="tap4",
            idx=6,
            ipv4_str="3.1.1.4",
            mac_str="00:00:34:00:11:11",
            vrf=0,
            mcast_vrf=0,
            nh_idx=24)

        vif6 = VirtualVif(
            name="tap5",
            idx=7,
            ipv4_str="4.1.1.4",
            mac_str="00:00:34:00:11:21",
            vrf=0,
            mcast_vrf=0,
            nh_idx=25)

        vif5_nh = EncapNextHop(
            encap_oif_id=vif5.idx(),
            encap="02 88 67 0c 2e 11 00 00 34 00 11 11 08 00",
            nh_vrf=0,
            nh_idx=24,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        vif6_nh = EncapNextHop(
            encap_oif_id=vif6.idx(),
            encap="02 88 67 0c 2e 11 00 00 34 00 11 21 08 00",
            nh_vrf=0,
            nh_idx=25,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        encap1 = "00 22 22 22 22 22 00 11 11 11 11 11 08 00"
        encap2 = "00 33 33 33 33 33 00 11 11 11 11 11 08 00"
        encap3 = "00 44 44 44 44 44 00 11 11 11 11 11 08 00"
        encapall = encap1+" "+encap2+" "+encap3
        oif_id = str(self.fabric_vif1.idx())+","+str(self.fabric_vif2.idx())
        oif_id += ","+str(self.fabric_vif3.idx())
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=oif_id,
            encap=encapall,
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=21,
            nh_flags=(
                constants.NH_FLAG_TUNNEL_GRE |
                constants.NH_FLAG_ETREE_ROOT |
                constants.NH_FLAG_TUNNEL_UNDERLAY_ECMP))

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="00:00:34:00:11:21",
            nh_idx=21,
            rtr_label_flags=3,
            rtr_label=128)

        ObjectBase.sync_all()

        flow1 = InetFlow(sip='3.1.1.4', dip='4.1.1.4', sport=4145, dport=0,
                         proto=constants.VR_IP_PROTO_ICMP, flow_nh_idx=24,
                         src_nh_idx=24, flow_vrf=0, rflow_nh_idx=25)
        flow1.fr_underlay_ecmp_index = 2
        flow1.sync(resp_required=True)

        icmp = IcmpPacket(
            sip='3.1.1.4',
            dip='4.1.1.4',
            smac='00:00:34:00:11:11',
            dmac='00:00:34:00:11:21',
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()

        recv_pkt = vif5.send_and_receive_packet(pkt, self.fabric_vif3)
        recv_pkt.show()
        self.assertEqual(1, self.fabric_vif3.get_vif_opackets())
