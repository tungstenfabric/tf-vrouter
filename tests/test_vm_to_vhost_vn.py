#!/usr/bin/python

from topo_base.vm_to_vhost_vn import VmVhostVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestVmVhostVn(VmVhostVn):

    def test_vm_to_vhost(self):
        icmp = IcmpPacket(
            sip="1.1.1.4",
            dip="192.168.1.1",
            smac="02:88:67:0c:2e:11",
            dmac="00:00:5e:00:01:00",
            id=1136)

        icmp_pkt = icmp.get_packet()
        icmp_pkt.ttl = 1
        icmp_pkt.show()
        recv_pkt = self.vif3.send_and_receive_packet(icmp_pkt, self.vhost0_vif)
        flow_output = ObjectBase.get_cli_output("flow -l")
        print(flow_output)
        self.assertEqual(1, self.vhost0_vif.get_vif_opackets())
