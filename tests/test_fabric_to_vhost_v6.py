#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestFabricVhostV6(unittest.TestCase):

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

    def test_fabric_vhost_v6_1(self):
        # Add fabric interface
        self.fabric_interface = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:44")

        # Add vhost0 vif with IPv6 address
        self.vhost0_vif = VhostVif(
            ipv4_str="",
            ipv6_str="2001::1",
            mac_str="00:1b:21:bb:f9:48",
            idx=1)

        # Add agent vif
        agent_vif = AgentVif(idx=2, flags=constants.VIF_FLAG_L3_ENABLED)
        ObjectBase.sync_all()

        ipv6_pkt = Ipv6Packet("3001::1", "2001::1", nh=17)
        e = Ether(src="00:00:01:00:00:25", dst="00:1b:21:bb:f9:44")
        pkt = e / ipv6_pkt.get_packet()
        pkt.show()
        self.fabric_interface.send_packet(pkt)
        # Check if fabric vif received the pkt
        self.assertEqual(1, self.fabric_interface.get_vif_ipackets())
