#!/usr/bin/python

import os
import sys
import pytest
import subprocess
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestFlowStickiness(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        # do auto cleanup and auto idx allocation for vif and nh
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)
        # Add tenant vif3
        self.vif3 = VirtualVif(
            idx=3,
            name="tap1",
            ipv4_str="1.1.1.4",
            mac_str="00:00:5e:00:01:00",
            vrf=3,
            mcast_vrf=3,
            nh_idx=23)

        # Add tenant vif4
        self.vif4 = VirtualVif(
            idx=4,
            name="tap2",
            ipv4_str="2.2.2.4",
            mac_str="00:00:5e:00:01:00",
            vrf=4,
            mcast_vrf=4,
            nh_idx=28)

        # Add vif3 encap nexthop (inet)
        self.vif3_nh = EncapNextHop(
            encap_oif_id=self.vif3.idx(),
            encap="02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00",
            nh_vrf=3,
            nh_idx=23,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        # Add vif4 encap nexthop (inet)
        self.vif4_nh = EncapNextHop(
            encap_oif_id=self.vif4.idx(),
            encap="02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00",
            nh_vrf=4,
            nh_idx=28,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        ObjectBase.sync_all()

    def teardown_method(self, method):
        ObjectBase.tearDown()

    # Create a flow with default(-1) and modified(>=0) Underlay ECMP idx
    def test_flow_stickiness_basic(self):
        flow1 = InetFlow(sip='1.1.1.4', dip='2.2.2.4', sport=1136, dport=0,
                         proto=constants.VR_IP_PROTO_ICMP, flow_nh_idx=23,
                         src_nh_idx=23, flow_vrf=3, rflow_nh_idx=28)
        flow2 = InetFlow(sip='2.2.2.6', dip='1.1.1.6', sport=0, dport=1136,
                         proto=constants.VR_IP_PROTO_ICMP, flow_nh_idx=23,
                         src_nh_idx=23, flow_vrf=3, rflow_nh_idx=28)
        flow2.fr_underlay_ecmp_index = 1
        flow1.sync(resp_required=True)
        flow2.sync(resp_required=True)
        self.assertGreater(flow1.get_fr_index(), 0)
        self.assertGreater(flow2.get_fr_index(), 0)
        check_flow_get_cmd1 = "flow --get " + str(flow1.get_fr_index())
        check_flow_get_cmd2 = "flow --get " + str(flow2.get_fr_index())
        flow_stats1 = ObjectBase.get_cli_output(check_flow_get_cmd1)
        flow_stats2 = ObjectBase.get_cli_output(check_flow_get_cmd2)
        self.assertEqual(1, ("Flow Underlay ECMP Index" not in flow_stats1))
        self.assertEqual(1, ("Flow Underlay ECMP Index:     1" in flow_stats2))

    # Create a flow with a Underlay ECMP idx>=0 and call sync and add rflow to
    # automatically generate a reverse flow
    def test_add_flow_sync_and_rflow(self):
        flow1 = InetFlow(sip='1.1.1.5', dip='2.2.2.5', sport=1136, dport=0,
                         proto=constants.VR_IP_PROTO_ICMP, flow_nh_idx=23,
                         src_nh_idx=23, flow_vrf=3, rflow_nh_idx=28)
        flow1.fr_underlay_ecmp_index = 2
        flow1.sync_and_add_reverse_flow()
        self.assertGreater(flow1.get_fr_index(), 0)
        check_flow_get_cmd1 = "flow --get " + str(flow1.fr_rindex)
        flow_stats1 = ObjectBase.get_cli_output(check_flow_get_cmd1)
        self.assertEqual(1, ("Flow Underlay ECMP Index" not in flow_stats1))

    # Create and send a tcp packet which inturn generates a flow
    def test_vrouter_packet_generation(self):
        ether_1 = Ether(src='02:88:67:0c:2e:11', dst='00:00:5e:00:01:00',
                        type=0x800)
        ip_1 = IP(src='1.1.1.4', dst='2.2.2.4', version=4, ihl=5,
                  id=1, ttl=64, proto='tcp')

        tcp = TCP(flags='S', seq=1, sport=1136, dport=500)
        syn_pkt = ether_1 / ip_1 / tcp
        syn_pkt.show()
        self.vif3.send_packet(syn_pkt)
        flow_stats = ObjectBase.get_cli_output('flow -l')
        self.assertEqual(1, ("UnderlayEcmpIdx" not in flow_stats))
