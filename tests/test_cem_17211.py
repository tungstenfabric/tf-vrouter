#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestCEM17211(unittest.TestCase):

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

    def test_inner_icmp(self):
        # Add tenant vif3
        self.vif3 = VirtualVif(
            name="tap88670c2e-11",
            ipv4_str="1.1.1.4",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=2,
            mcast_vrf=2,
            nh_idx=23)

        ObjectBase.sync_all()

        # Create an ICMP Dest unreachable, MTU exceeded pkt
        icmp_echo = IcmpPacket(
            sip='2.1.1.4',
            dip='1.1.1.7',
            smac='02:88:67:0c:2e:11',
            dmac='02:e7:03:ea:67:f1',
            id=1136)
        echo_pkt = icmp_echo.get_packet()
        echo_pkt.show()
        icmp_err = IcmpPacket(
            sip='1.1.1.4',
            dip='1.1.1.5',
            smac='02:88:67:0c:2e:11',
            dmac='02:e7:03:ea:67:f1',
            icmp_type=constants.DEST_UNREACH,
            id=0)
        err_pkt = icmp_err.get_packet()
        err_pkt.show()

        pkt = err_pkt / echo_pkt[IP]
        pkt.show()

        # Send the pkt via vif3
        self.vif3.send_packet(pkt)

        # Check the flow is created with sport 1136 which is the inner
        # ICMP Echo req id
        flow_output = ObjectBase.get_cli_output("flow -l")
        self.assertNotEqual(re.search("1.1.1.7:1136", flow_output), None)
        # Check the flow idx as well
        self.assertNotEqual(re.search("338668", flow_output), None)
