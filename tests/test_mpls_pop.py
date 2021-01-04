#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test


class TestMplsNH(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        # do auto cleanup
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_mpls_pop_nh1(self):
        # Add fabric vif
        fabric_vif = FabricVif(
            name='eth1',
            mac_str='00:1b:21:bb:f9:46')

        # Add vhost0 vif
        vhost_vif = VhostVif(
            idx=1,
            ipv4_str='192.168.1.1',
            mac_str='00:1b:21:bb:f9:46',
            nh_idx=5)

        # create a mpls pop nh
        pop_nh = MplsPopNextHop(vhost_vif.idx(), nh_idx=50)
        # sync all objects
        ObjectBase.sync_all()

        # check if pop nh got added
        self.assertEqual(pop_nh.idx(), pop_nh.get_nh_idx())

    def test_mpls_pop_nh2(self):
        # Add fabric vif
        fabric_vif = FabricVif(
            name='eth1',
            mac_str='00:1b:21:bb:f9:46')

        # Add vhost0 vif
        vhost_vif = VhostVif(
            idx=1,
            ipv4_str='192.168.1.1',
            mac_str='00:1b:21:bb:f9:46',
            nh_idx=5)

        # create a mpls pop nh
        pop_nh = MplsPopNextHop(vhost_vif.idx(), nh_idx=50)

        # Program regular label with pop nh
        self.mpls_entry = Mpls(
            mr_label=600,
            mr_nhid=pop_nh.idx())

        # Program explicit NULL label with pop nh
        self.mpls_entry2 = Mpls(
            mr_label=0,
            mr_nhid=pop_nh.idx())

        # sync all objects
        ObjectBase.sync_all()

        # Query label 600 back and check
        x = re.search(str(pop_nh.idx()),
                      self.mpls_entry.get("mr_nhid"))
        self.assertTrue(x is not None)

        # Query label 0 back and check
        x = re.search(str(pop_nh.idx()),
                      self.mpls_entry2.get("mr_nhid"))
        self.assertTrue(x is not None)
