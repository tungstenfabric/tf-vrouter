#!/usr/bin/python

import pytest
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class Test_Mpls_Ingress(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

        self.vif1 = VirtualVif(
            name="tap_1",
            idx=1,
            ipv4_str="1.1.1.4",
            ipv6_str="de:ad:be:ef::1",
            mac_str="de:ad:be:ef:00:02",
            mtu=2514,
            flags=None)

        self.vif2 = VirtualVif(
            name="tap_2",
            idx=2,
            ipv4_str="2.2.2.4",
            ipv6_str="de:ad:be:ef::2",
            mac_str="de:ad:be:ef:00:01",
            mtu=2514,
            flags=None)

        ObjectBase.sync_all()

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_mpls_bridge_route(self):
        tunnel_nh = MplsTunnelNextHop(
            encap_oif_id=self.vif2.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 88 47",
            nh_idx=12,
            transport_labels=[40],
            num_labels=1,
            nh_flags=constants.NH_FLAG_TUNNEL_MPLS |
            constants.NH_FLAG_ETREE_ROOT)

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:01",
            nh_idx=12,
            rtr_label=60,
            rtr_label_flags=3)

        ObjectBase.sync_all()

        icmp = IcmpPacket(
            sip="1.1.1.4",
            dip="2.2.2.4",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()
        recv_pkt = self.vif1.send_and_receive_packet(pkt, self.vif2)
        self.assertIsNotNone(recv_pkt)
        self.assertEqual("00:1b:21:bb:f9:48", recv_pkt[Ether].src)
        self.assertEqual("00:1b:21:bb:f9:46", recv_pkt[Ether].dst)
        self.assertEqual("0x8847", hex(recv_pkt[Ether].type))

        udp6 = Udpv6Packet(
            sipv6="de:ad:be:ef::1",
            dipv6="de:ad:be:ef::2",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            sport=0,
            dport=1)
        pkt = udp6.get_packet()
        pkt.show()
        recv_pkt = self.vif1.send_and_receive_packet(pkt, self.vif2)
        self.assertIsNotNone(recv_pkt)
        self.assertEqual("00:1b:21:bb:f9:48", recv_pkt[Ether].src)
        self.assertEqual("00:1b:21:bb:f9:46", recv_pkt[Ether].dst)
        self.assertEqual("0x8847", hex(recv_pkt[Ether].type))

    def test_mpls_inet_route(self):
        tunnel_nh = MplsTunnelNextHop(
            encap_oif_id=self.vif2.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 88 47",
            nh_idx=12,
            tansport_labels=[40],
            num_labels=1,
            nh_flags=constants.NH_FLAG_TUNNEL_MPLS |
            constants.NH_FLAG_ETREE_ROOT)

        inet_route = InetRoute(
            vrf=0,
            prefix="2.2.2.4",
            nh_idx=12,
            rtr_label=48,
            rtr_label_flags=1)

        inet6_route = Inet6Route(
            vrf=0,
            prefix="de:ad:be:ef::2",
            prefix_len=20,
            nh_idx=12,
            rtr_label=58,
            rtr_label_flags=1)

        nh_l2rcv = ReceiveL2NextHop(
            nh_idx=13,
            nh_family=0)

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:01",
            nh_idx=13,
            rtr_label_flags=0)

        ObjectBase.sync_all()

        icmp = IcmpPacket(
            sip="1.1.1.4",
            dip="2.2.2.4",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            id=4145)
        pkt1 = icmp.get_packet()
        pkt1.show()
        self.assertIsNotNone(pkt1)

        recv_pkt = self.vif1.send_and_receive_packet(pkt1, self.vif2)
        self.assertIsNotNone(recv_pkt)
        self.assertEqual("00:1b:21:bb:f9:48", recv_pkt[Ether].src)
        self.assertEqual("00:1b:21:bb:f9:46", recv_pkt[Ether].dst)
        self.assertEqual("0x8847", hex(recv_pkt[Ether].type))

        udp6 = Udpv6Packet(
            sipv6="de:ad:be:ef::1",
            dipv6="de:ad:be:ef::2",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            sport=0,
            dport=1)
        pkt = udp6.get_packet()
        pkt.show()
        recv_pkt = self.vif1.send_and_receive_packet(pkt, self.vif2)
        self.assertIsNotNone(recv_pkt)
        self.assertEqual("00:1b:21:bb:f9:48", recv_pkt[Ether].src)
        self.assertEqual("00:1b:21:bb:f9:46", recv_pkt[Ether].dst)
        self.assertEqual("0x8847", hex(recv_pkt[Ether].type))
