#!/usr/bin/python

from topo_base.vm_to_vm_inter_vn import VmToVmInterVn
import os
import sys
import pytest
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestVmToVmInterVn(VmToVmInterVn):

    def test_vm_to_vm_inter_vn(self):
        # send ping request from vif4
        icmp = IcmpPacket(
            sip='2.2.2.4',
            dip='1.1.1.4',
            smac='02:e7:03:ea:67:f1',
            dmac='00:00:5e:00:01:00',
            icmp_type=0,
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rec_pkt = self.vif4.send_and_receive_packet(pkt, self.vif3)

        # Check if the packet was received at vif3 and vif4
        self.assertEqual(1, self.vif3.get_vif_opackets())
        self.assertEqual(1, self.vif4.get_vif_ipackets())

        Vif.clear_all_vif_stats()

        time.sleep(3)
        self.vif3.reload()
        self.vif4.reload()

        # After sending clear stats request
        self.assertEqual(0, self.vif3.get_vif_opackets())
        self.assertEqual(0, self.vif4.get_vif_ipackets())

        # send the packet once again
        self.vif4.send_and_receive_packet(pkt, self.vif3)

        # Clear vif stats only for tap1(vif_idx=3)
        self.vif3.clear()

        time.sleep(3)
        self.vif3.reload()
        self.vif4.reload()

        self.assertEqual(0, self.vif3.get_vif_opackets())
        self.assertEqual(1, self.vif4.get_vif_ipackets())
