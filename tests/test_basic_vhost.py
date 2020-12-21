#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test


class TestBasic(unittest.TestCase):

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

    # Test1 : Test with socket dir and socket filename
    def test_vif_vhost_0(self):
        vif = VirtualVif(name="vhost_0", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02",
                         vhostuser_mode=0,
                         vhostsocket_dir="/var/run/vrouter/",
                         vhostsocket_filename="vhost_sock0")
        vif.sync()
        self.assertEqual("vhost_0", vif.get_vif_name())

    # Test2 : Test with missing subdirectory vhost_0 in socket dir
    def test_vif_vhost_1(self):
        vif = VirtualVif(name="vhost_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02",
                         vhostuser_mode=0,
                         vhostsocket_dir="/var/run/vrouter/vhost_1/",
                         vhostsocket_filename="vhost_sock1")
        vif.sync()
        self.assertEqual("vhost_1", vif.get_vif_name())

    # Test3 : Test with socket filename and  without socket dir
    def test_vif_vhost_2(self):
        vif = VirtualVif(name="vhost_2", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02", vhostuser_mode=0,
                         vhostsocket_filename="vhost_sock2")
        vif.sync()
        self.assertEqual("vhost_2", vif.get_vif_name())

    # Test4 : Test with socket dir and without socket filename
    def test_vif_vhost_3(self):
        vif = VirtualVif(name="vhost_3", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02",
                         vhostuser_mode=0,
                         vhostsocket_dir="/var/run/vrouter/")
        vif.sync()
        self.assertEqual("vhost_3", vif.get_vif_name())
