#!/usr/bin/python

import os
import sys
import pytest
import re
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestTcpSynDrop(unittest.TestCase):

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
        fabric_vif = FabricVif(
            name='phy',
            mac_str='00:15:4d:13:19:7e')

        # Add agent vif
        self.agent_vif = AgentVif(idx=2, flags=constants.VIF_FLAG_L3_ENABLED)

        # Add vhost vif
        self.vhost_vif = VhostVif(
            idx=3,
            ipv4_str="100.115.79.1",
            mac_str="00:15:4d:13:19:7e",
            vrf=3,
            mcast_vrf=3,
            nh_idx=23)

        # Add tenant vif
        self.tenant_vif = VirtualVif(
            idx=4,
            name="tape5053325-99",
            ipv4_str="169.254.255.254",
            mac_str="00:00:5e:00:01:00",
            vrf=4,
            mcast_vrf=4,
            nh_idx=28)

        # Add vhost encap nexthop (inet)
        self.vhost_vif_nh = EncapNextHop(
            encap_oif_id=self.vhost_vif.idx(),
            encap="02 88 67 0c 2e 11 00 15 4d 13 19 7e 08 00",
            nh_vrf=3,
            nh_idx=23,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        # Add tenant vif encap nexthop (inet)
        self.tenant_vif_nh = EncapNextHop(
            encap_oif_id=self.tenant_vif.idx(),
            encap="02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00",
            nh_vrf=4,
            nh_idx=28,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        # Add overlay L2 Receive NH
        self.l2_nh = ReceiveL2NextHop(
            nh_idx=3,
            nh_flags=constants.NH_FLAG_ETREE_ROOT)

        # Add vhost bridge Route with agent MAC
        self.vhost_vif_bridge_route = BridgeRoute(
            nh_idx=3, vrf=3, mac_str="00:00:5e:00:01:00")

        # Add tenant vif bridge Route with agent MAC
        self.tenant_vif_bridge_route = BridgeRoute(
            nh_idx=3, vrf=4, mac_str="00:00:5e:00:01:00")

        # Add vhost Route
        self.vhost_vif_inet_route = InetRoute(
            prefix="169.254.255.254",
            vrf=3,
            nh_idx=28)

        # Add second vhost Route pointing to Discard NH
        self.vhost_vif_inet_route_2 = InetRoute(
            prefix="10.1.1.4",
            vrf=0,
            nh_idx=0)

        # Add tenant_vif Route
        self.tenant_vif_inet_route = InetRoute(
            prefix="100.115.79.1",
            vrf=4,
            nh_idx=23)

        ObjectBase.sync_all()

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_tcp_syn_drop(self):
        ether_1 = Ether(src='02:88:67:0c:2e:11', dst='00:00:5e:00:01:00',
                        type=0x800)
        ip_1 = IP(src='100.115.79.1', dst='169.254.255.254', version=4, ihl=5,
                  id=1, ttl=64, proto='tcp')

        tcp = TCP(flags='S', seq=1, sport=1136, dport=500)
        syn_pkt = ether_1 / ip_1 / tcp
        syn_pkt.show()
        self.vhost_vif.send_packet(syn_pkt)

        # Getting flow index and flow id from forward flow
        flow_det = ObjectBase.get_cli_output('flow -l')
        for c in flow_det:
            if (c in ['-', ':', ',', '(', ')']):
                flow_det = flow_det.replace(c, '')
        flow_det = flow_det.split()

        fr_indx = int(flow_det[flow_det.index('Index') + 3])
        fr_genid = int(flow_det[flow_det.index('Gen') + 1])

        # Create flows after sending the packet
        f_flow = InetFlow(
            sip='100.115.79.1',
            dip='169.254.255.254',
            sport=1136,
            dport=500,
            proto=constants.VR_IP_PROTO_TCP,
            action=constants.VR_FLOW_ACTION_NAT,
            flags=constants.VR_FLOW_FLAG_DNAT,
            flow_nh_idx=23,
            src_nh_idx=23,
            flow_vrf=3,
            rflow_nh_idx=28)

        r_flow = InetFlow(
            sip='10.1.1.4',
            dip='100.115.79.1',
            sport=1136,
            dport=500,
            proto=constants.VR_IP_PROTO_TCP,
            flow_nh_idx=28,
            flags=constants.VR_RFLOW_VALID,
            src_nh_idx=28,
            flow_vrf=4,
            rflow_nh_idx=23)

        # Update reverse flow
        r_flow.fr_rindex = fr_indx
        r_flow.sync(resp_required=True)
        rfr_indx = r_flow.get_fr_index()

        # Update forward flow
        f_flow.fr_index = fr_indx
        f_flow.fr_rindex = int(rfr_indx)
        f_flow.fr_gen_id = int(fr_genid)
        f_flow.fr_flags |= constants.VR_RFLOW_VALID
        f_flow.sync()

        # Update reverse flow
        r_flow.fr_index = r_flow.get_fr_index()
        r_flow.fr_gen_id = r_flow.get_fr_gen_id()
        r_flow.sync()

        # Check if the packet is received at the VM Interface
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())
