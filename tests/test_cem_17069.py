#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class Test_CEM_17069(unittest.TestCase):

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

    # Test to send a DHCPv6 advertisement pkt from pkt0 interface
    # and see if it gets properly switched to fabric
    def test_cem_17069(self):
        # Add fabric vif
        fabric_vif = FabricVif(
            name='eth0',
            mac_str='00:1b:21:bb:f9:46')

        # Add agent vif
        agent_vif = AgentVif(idx=2, flags=constants.VIF_FLAG_L3_ENABLED)

        # add a tunnel nh
        nh = TunnelNextHopV4(
            encap_oif_id=fabric_vif.idx(),
            encap="de ad be ef 00 02 de ad be ef 00 01 08 00",
            tun_sip="1.1.1.1",
            tun_dip="1.1.1.2",
            nh_flags=constants.NH_FLAG_TUNNEL_VXLAN)

        vmi_mac = '02:1e:3d:8f:60:9a'

        # add a bridge route for the vmi mac
        bridge_rt = BridgeRoute(2, vmi_mac, nh.idx(),
                                rtr_label=128, rtr_label_flags=10)

        # Sync all objects created above
        ObjectBase.sync_all()

        # create a DHCPv6 advertisement pkt
        ether = Ether(dst=vmi_mac, src='90:e2:ba:5e:99:94', type=0x86dd)
        ipv6 = IPv6(src="36ff:fa99:bbdc:9985:622:a849:0:2",
                    dst="fe80::1e:3dff:fe8f:609a")
        dhcpv6_adv = ether / ipv6 / UDP() / DHCP6_Advertise()

        # create a pkt encapsulating DHCPv6 Adv into agent hdr
        ether = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02',
                      type=0x0800)
        agent_hdr = '\x00\x00\x00\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00'\
                    '\x00\x00\x00\x69\x74\x79\x00\x05\x09\x00\x00'\
                    '\x00\x00\x00\x00\x00\x00'
        pkt = ether / agent_hdr / dhcpv6_adv

        pkt.show()

        # send packet through pkt0 interface
        agent_vif.send_packet(pkt)
        # check if the pkt is sent out via fabric interface
        self.assertEqual(1, fabric_vif.get_vif_opackets())
