#!/usr/bin/python

from topo_base.fabric_to_vm_intra_vn import FabricToVmIntraVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test


class TestSrMplsEgress(FabricToVmIntraVn):

    # test with transport label and vpn label
    def test_sr_mpls_egress_1(self):
        # form the pkt
        label_stack = [100, 200]
        icmp = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.3',
            id=4145,
            icmp_type=constants.ECHO_REPLY)
        mp = MplsoEtherPacket("00:fe:fd:fc:fb:fa", "00:1b:21:bb:f9:46",
                              label_stack, icmp.get_packet())
        pkt = mp.get_packet()
        pkt.show()
        # Add pop NH for label 100
        pop_nh = MplsPopNextHop(self.vhost0_vif.idx(), nh_idx=500)
        # Program MPLS table with the NHs
        self.mpls_entry = Mpls(
            mr_label=100,
            mr_nhid=pop_nh.idx())
        self.mpls_entry = Mpls(
            mr_label=200,
            mr_nhid=self.vif_nh.idx())
        ObjectBase.sync_all()
        # Change the default src nh in flow so that pkt
        # is not dropped due to src nh validation checks
        # Once MPLS Tunnel NH is ready, this is not required
        # Hence, Delete the default flows and add new flows
        self.f_flow.delete()
        self.r_flow.delete()

        # Add forward and reverse flow
        self.f_flow = InetFlow(
            sip='1.1.1.3',
            dip='1.1.1.5',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            src_nh_idx=38,
            flow_vrf=5,
            rflow_nh_idx=10)

        self.r_flow = InetFlow(
            sip='1.1.1.5',
            dip='1.1.1.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flags=constants.VR_RFLOW_VALID,
            flow_nh_idx=38,
            src_nh_idx=10,
            flow_vrf=5,
            rflow_nh_idx=10)
        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)

        # send packet
        rcv_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, self.tenant_vif)
        self.assertIsNotNone(rcv_pkt)
        self.assertTrue(ICMP in rcv_pkt)
        self.assertEqual("1.1.1.5", rcv_pkt[IP].src)
        self.assertEqual("1.1.1.3", rcv_pkt[IP].dst)

        # Check if the packet was received at tenant vif
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())

    # test with only vpn label
    def test_sr_mpls_egress_2(self):
        # form the pkt
        label_stack = [300]
        icmp = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.3',
            id=4145,
            icmp_type=constants.ECHO_REPLY)
        mp = MplsoEtherPacket("00:fe:fd:fc:fb:fa", "00:1b:21:bb:f9:46",
                              label_stack, icmp.get_packet())
        pkt = mp.get_packet()
        pkt.show()
        # Program MPLS table with the NHs
        self.mpls_entry = Mpls(
            mr_label=300,
            mr_nhid=self.vif_nh.idx())
        ObjectBase.sync_all()
        self.f_flow.delete()
        self.r_flow.delete()

        # Add forward and reverse flow
        self.f_flow = InetFlow(
            sip='1.1.1.3',
            dip='1.1.1.5',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            src_nh_idx=38,
            flow_vrf=5,
            rflow_nh_idx=10)

        self.r_flow = InetFlow(
            sip='1.1.1.5',
            dip='1.1.1.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flags=constants.VR_RFLOW_VALID,
            flow_nh_idx=38,
            src_nh_idx=10,
            flow_vrf=5,
            rflow_nh_idx=10)
        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)

        # send packet
        rcv_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, self.tenant_vif)
        self.assertIsNotNone(rcv_pkt)
        self.assertTrue(ICMP in rcv_pkt)
        self.assertEqual("1.1.1.5", rcv_pkt[IP].src)
        self.assertEqual("1.1.1.3", rcv_pkt[IP].dst)

        # Check if the packet was received at tenant vif
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())

    # test with only vpn label and ipv6 inner pkt
    def test_sr_mpls_egress_3(self):
        # form the pkt
        label_stack = [600]
        ipv6 = Udpv6Packet(1000, 2000, "2001::2", "3001::2", nh=17)
        mp = MplsoEtherPacket("00:fe:fd:fc:fb:fa", "00:1b:21:bb:f9:46",
                              label_stack, ipv6.get_packet())
        pkt = mp.get_packet()
        pkt.show()
        # Program MPLS table with the NHs
        self.mpls_entry = Mpls(
            mr_label=600,
            mr_nhid=self.vif_nh.idx())
        ObjectBase.sync_all()
        # Delete the existing flows
        self.f_flow.delete()
        self.r_flow.delete()

        # Add forward and reverse flow
        self.f_flow = Inet6Flow(
            sip6_str="3001::2",
            dip6_str="2001::2",
            proto=17,
            sport=2000,
            dport=1000,
            flow_nh_idx=38,
            src_nh_idx=38,
            flow_vrf=5,
            rflow_nh_idx=10)

        self.r_flow = Inet6Flow(
            sip6_str="2001::2",
            dip6_str="3001::2",
            proto=17,
            sport=1000,
            dport=2000,
            flow_nh_idx=38,
            src_nh_idx=10,
            flow_vrf=5,
            rflow_nh_idx=10)

        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)

        # send packet
        rcv_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, self.tenant_vif)
        self.assertIsNotNone(rcv_pkt)
        self.assertTrue(UDP in rcv_pkt)
        self.assertEqual("2001::2", rcv_pkt[IPv6].src)
        self.assertEqual("3001::2", rcv_pkt[IPv6].dst)

        # Check if the packet was received at tenant vif
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())
