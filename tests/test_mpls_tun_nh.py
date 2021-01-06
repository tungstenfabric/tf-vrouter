#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test


class TestMplsTunnelNexthop(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        # do auto cleanup and auto idx allocation for vif and nh
        ObjectBase.set_auto_features(cleanup=True, vif_idx=True, nh_idx=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_mpls_tunnel_nh(self):
        # add fabric vif
        vmi = FabricVif(name="en0", ipv4_str="192.168.1.1",
                        mac_str="de:ad:be:ef:00:02")

        # add mpls tunnel nh
        nh = MplsTunnelNextHop(
            encap_oif_id=vmi.idx(),
            encap="de ad be ef 00 02 de ad be ef 00 01 88 47",
            transport_labels=[40, 50],
            num_labels=2,
            nh_flags=constants.NH_FLAG_TUNNEL_MPLS)
        ObjectBase.sync_all()

        # Check if mpls tunnel nh got added
        self.assertEqual(nh.idx(), nh.get_nh_idx())
