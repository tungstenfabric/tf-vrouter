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
        # Add Fabric vif
        self.fabric_vif = FabricVif(
            name="eth0",
            mac_str="00:1b:21:bb:f9:46",
            idx=1)
        self.fabric_vif.vifr_os_idx = self.fabric_vif.vifr_idx

        # Add Fabric vif 1
        self.fabric_vif_1 = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:46",
            idx=2)
        self.fabric_vif_1.vifr_os_idx = self.fabric_vif_1.vifr_idx

        cross_connect_idx = [self.fabric_vif.vifr_idx,
                             self.fabric_vif_1.vifr_idx, -1]
        # Add vhost0
        self.vhost_vif = VhostVif(
            idx=3,
            ipv4_str='10.1.1.1',
            mac_str='00:1b:21:bb:f9:46',
            xconnect_idx=cross_connect_idx)
        self.vhost_vif.vifr_os_idx = self.vhost_vif.vifr_idx

        # Add fabric vif nexthop
        fabric_vif_nh = EncapNextHop(
            encap_oif_id=self.fabric_vif.idx(),
            encap='90 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00',
            nh_idx=16)

        # Add receive nexthop
        receive_nh = ReceiveNextHop(
            encap_oif_id=self.vhost_vif.idx(),
            nh_vrf=1,
            nh_idx=10)

        # Add fabric route
        fabric_route = InetRoute(
            vrf=0,
            prefix='10.1.1.1',
            nh_idx=receive_nh.idx())

        # Add vhost route
        vhost_route = InetRoute(
            vrf=0,
            prefix='20.1.1.1',
            nh_idx=fabric_vif_nh.idx())

        ObjectBase.sync_all()

        icmp = IcmpPacket(
            sip='10.1.1.1',
            dip='20.1.1.1',
            smac='00:1b:21:bb:f9:46',
            dmac='90:e2:ba:84:48:88',
            id=1136)
        self.icmp_vhost_to_fabric_pkt = icmp.get_packet()
        self.icmp_vhost_to_fabric_pkt.show()

        icmp = IcmpPacket(
            sip='20.1.1.1',
            dip='10.1.1.1',
            smac='90:e2:ba:84:48:88',
            dmac='00:1b:21:bb:f9:46',
            id=1136)
        self.icmp_fabric_to_vhost_pkt = icmp.get_packet()
        self.icmp_fabric_to_vhost_pkt.show()

        ether = Ether(src='90:e2:ba:84:48:88', dst='00:1b:21:bb:f9:46',
                      type=0x0806)
        arp = ARP()
        self.arp_fabric_to_vhost_pkt = ether / arp
        self.arp_fabric_to_vhost_pkt.show()

        ether = Ether(src='00:1b:21:bb:f9:46', dst='90:e2:ba:84:48:88',
                      type=0x0806)
        arp = ARP()
        self.arp_vhost_to_fabric_pkt = ether / arp
        self.arp_vhost_to_fabric_pkt.show()

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_l3mh_vif_add(self):
        self.assertEqual("eth0", self.fabric_vif.get_vif_name())
        self.assertEqual("eth1", self.fabric_vif_1.get_vif_name())
        self.assertEqual("vhost0", self.vhost_vif.get_vif_name())

    def test_traffic_l3mh_xconnect(self):
        self.vhost_vif.send_packet(self.icmp_vhost_to_fabric_pkt)
        self.assertEqual(1, self.fabric_vif.get_vif_opackets())

        self.fabric_vif.send_packet(self.icmp_fabric_to_vhost_pkt)
        self.assertEqual(1, self.vhost_vif.get_vif_opackets())

        pkt = self.fabric_vif.send_and_receive_packet(
                self.arp_fabric_to_vhost_pkt, self.vhost_vif)
        pkt.show()
        self.assertTrue(ARP in pkt)

        pkt = self.vhost_vif.send_and_receive_packet(
                self.arp_vhost_to_fabric_pkt, self.fabric_vif)
        pkt.show()
        self.assertTrue(ARP in pkt)

    def test_traffic_l3mh_normal(self):
        # Add agent vif
        agent_vif = AgentVif(idx=4, flags=constants.VIF_FLAG_L3_ENABLED)
        agent_vif.sync()

        self.vhost_vif.send_packet(self.icmp_vhost_to_fabric_pkt)
        self.assertEqual(1, self.fabric_vif.get_vif_opackets())

        self.fabric_vif.send_packet(self.icmp_fabric_to_vhost_pkt)
        self.assertEqual(1, self.vhost_vif.get_vif_opackets())

        pkt = self.fabric_vif.send_and_receive_packet(
                self.arp_fabric_to_vhost_pkt, self.vhost_vif)
        pkt.show()
        self.assertTrue(ARP in pkt)

        pkt = self.vhost_vif.send_and_receive_packet(
                self.arp_vhost_to_fabric_pkt, self.fabric_vif)
        pkt.show()
        self.assertTrue(ARP in pkt)
