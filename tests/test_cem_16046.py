#!/usr/bin/python

import os
import sys
import pytest
import subprocess
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestDpdkFrag(unittest.TestCase):

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
            ipv4_str='1.1.1.4',
            mac_str="de:ad:be:ef:00:02",
            mtu=512,
            flags=None)

        self.vif2 = VirtualVif(
            name="tap_2",
            idx=2,
            ipv4_str='2.2.2.4',
            mac_str="de:ad:be:ef:00:01",
            mtu=512,
            flags=None)

        ObjectBase.sync_all()

        nh_tunnel = TunnelNextHopV4(
            encap_oif_id=self.vif2.idx(),
            encap="00 22 22 22 22 22 00 11 11 11 11 11 08 00",
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=12,
            nh_flags=65)

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:01",
            nh_idx=12,
            rtr_label=128,
            rtr_label_flags=3)

        ObjectBase.sync_all()

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_dpdk_frag(self):
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='de:ad:be:ef:00:02',
            dmac='de:ad:be:ef:00:01',
            id=1136,
            size=2000)
        pkt = icmp.get_packet()

        pkt.show()
        self.vif1.send_packet(pkt)

        dpdkinfo_cmd = 'dpdkinfo --mempool all'
        dpdkinfo_out = ObjectBase.get_cli_output(dpdkinfo_cmd).split()

        frag_indirect_size = dpdkinfo_out[
                             dpdkinfo_out.index('frag_indirect_mempool') + 2]
        self.assertEqual(0, int(frag_indirect_size))
