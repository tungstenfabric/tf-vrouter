#!/usr/bin/python

from topo_base.fabric_to_vm_inter_vn import FabricToVmInterVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestVifL3MH(unittest.TestCase):

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

    def test_l3mh_vif_add(self):

        # Add Fabric vif1
        vif1 = FabricVif(
            name="eth0",
            mac_str="00:1b:21:bb:f9:46",
            idx=1,
            mtu=2514,
            flags=0)
        vif1.vifr_os_idx = vif1.vifr_idx
        vif1.sync()
        self.assertEqual("eth0", vif1.get_vif_name())

        # Add Fabric vif2
        vif2 = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:46",
            idx=2,
            mtu=2514,
            flags=1)
        vif2.vifr_os_idx = vif2.vifr_idx
        vif2.sync()
        self.assertEqual("eth1", vif2.get_vif_name())

        cross_connect_idx = [vif1.vifr_idx, vif2.vifr_idx, -1]
        # Add vhost0
        vhost_vif = VhostVif(
            idx=3,
            ipv4_str='8.0.0.3',
            mac_str='00:1b:21:bb:f9:46',
            xconnect_idx=cross_connect_idx)
        vhost_vif.vifr_os_idx = vhost_vif.vifr_idx
        vhost_vif.sync()
        self.assertEqual("vhost0", vhost_vif.get_vif_name())
