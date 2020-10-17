#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class Test_IPv6_ND(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)
        # Add fabric vif
        self.fabric_vif = FabricVif(
            name='eth0',
            mac_str='00:1b:21:bb:f9:46')

        # Add vhost0 vif
        self.vhost_vif = VhostVif(
            idx=1,
            ipv4_str='10.1.1.1',
            mac_str='00:1b:21:bb:f9:46',
            nh_idx=5)

        # Add agent vif
        agent_vif = AgentVif(idx=2, flags=constants.VIF_FLAG_L3_ENABLED)

        # Add vhost0 vif nexthop
        vhost_vif_nh = EncapNextHop(
            encap_oif_id=self.vhost_vif.idx(),
            encap='00 1b 21 bb f9 46 00 1b 21 bb f9 46 08 00',
            nh_idx=5)

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

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def get_ipv6_nd_packet(self, s_mac, d_mac, s_addr, d_addr, nd_type,
                           tgt_addr=''):
        ether = Ether(src=s_mac, dst=d_mac, type=0x86dd)
        ipv6 = IPv6(src=s_addr, dst=d_addr)
        if (nd_type == 'NS'):
            icmp = ICMPv6ND_NS(tgt=tgt_addr)
        elif (nd_type == 'NA'):
            icmp = ICMPv6ND_NA(tgt=tgt_addr, R=0, S=1)
        elif (nd_type == 'RS'):
            icmp = ICMPv6ND_RS()
        elif (nd_type == 'RA'):
            icmp = ICMPv6ND_RA()
        else:
            return None
        src_ll_addr = ICMPv6NDOptSrcLLAddr(lladdr=s_mac)
        packet = ether/ipv6/icmp/src_ll_addr
        packet.show()
        return packet

    def test_vhost_to_fabric_NS_NA(self):
        packet = self.get_ipv6_nd_packet(
                s_mac='00:1b:21:bb:f9:46',
                d_mac='33:33:ff:a0:6e:09',
                s_addr='2001:44b8:41e1:cc00:acb0:7653:eabc:c180',
                d_addr='ff02::1:ff:a0:6e:09',
                nd_type='NS',
                tgt_addr='2001:44b8:41e1:cc00:843e:7b93:daa0:6e09')
        recv_pkt = self.vhost_vif.send_and_receive_packet(packet,
                                                          self.fabric_vif)
        recv_pkt.show()

        packet = self.get_ipv6_nd_packet(
                s_mac='90:e2:ba:84:48:88',
                d_mac='00:1b:21:bb:f9:46',
                s_addr='2001:44b8:41e1:cc00:843e:7b93:daa0:6e09',
                d_addr='2001:44b8:41e1:cc00:acb0:7653:eabc:c180',
                nd_type='NA',
                tgt_addr='2001:44b8:41e1:cc00:843e:7b93:daa0:6e09')

        recv_pkt = self.fabric_vif.send_and_receive_packet(packet,
                                                           self.vhost_vif)
        recv_pkt.show()

    def test_fabric_to_vhost_NS_NA(self):
        packet = self.get_ipv6_nd_packet(
                s_mac='90:e2:ba:84:48:88',
                d_mac='33:33:ff:bc:c1:80',
                s_addr='2001:44b8:41e1:cc00:843e:7b93:daa0:6e09',
                d_addr='ff02::1:ff:bc:c1:80',
                nd_type='NS',
                tgt_addr='2001:44b8:41e1:cc00:acb0:7653:eabc:c180')

        recv_pkt = self.fabric_vif.send_and_receive_packet(packet,
                                                           self.vhost_vif)
        recv_pkt.show()

        packet = self.get_ipv6_nd_packet(
                s_mac='00:1b:21:bb:f9:46',
                d_mac='90:e2:ba:84:48:88',
                s_addr='2001:44b8:41e1:cc00:acb0:7653:eabc:c180',
                d_addr='2001:44b8:41e1:cc00:843e:7b93:daa0:6e09',
                nd_type='NA',
                tgt_addr='2001:44b8:41e1:cc00:acb0:7653:eabc:c180')

        recv_pkt = self.vhost_vif.send_and_receive_packet(packet,
                                                          self.fabric_vif)
        recv_pkt.show()

    def test_vhost_to_fabric_RS_RA(self):
        packet = self.get_ipv6_nd_packet(
                s_mac='00:1b:21:bb:f9:46',
                d_mac='33:33:00:00:00:02',
                s_addr='fe80::ec4:7aff:fedc:4448',
                d_addr='ff02::2',
                nd_type='RS')

        recv_pkt = self.vhost_vif.send_and_receive_packet(packet,
                                                          self.fabric_vif)
        recv_pkt.show()

        packet = self.get_ipv6_nd_packet(
                s_mac='90:e2:ba:84:48:88',
                d_mac='33:33:00:00:00:01',
                s_addr='fe80::ec4:7aff:fedc:4448',
                d_addr='ff02::1',
                nd_type='RA')

        recv_pkt = self.vhost_vif.send_and_receive_packet(packet,
                                                          self.fabric_vif)
        recv_pkt.show()

    def test_fabric_to_vhost_RS_RA(self):
        packet = self.get_ipv6_nd_packet(
                s_mac='90:e2:ba:84:48:88',
                d_mac='33:33:00:00:00:02',
                s_addr='fe80::ec4:7aff:fedc:4448',
                d_addr='ff02::2',
                nd_type='RS')

        recv_pkt = self.fabric_vif.send_and_receive_packet(packet,
                                                           self.vhost_vif)
        recv_pkt.show()

        packet = self.get_ipv6_nd_packet(
                s_mac='00:1b:21:bb:f9:46',
                d_mac='33:33:00:00:00:01',
                s_addr='fe80::ec4:7aff:fedc:4448',
                d_addr='ff02::1',
                nd_type='RA')

        recv_pkt = self.vhost_vif.send_and_receive_packet(packet,
                                                          self.fabric_vif)
        recv_pkt.show()
