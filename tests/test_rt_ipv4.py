#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test


class TestRTIPv4(unittest.TestCase):

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

    # Add route to all levels:8,16,24,32
    def test_rt_add_all(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 11")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=0,
            prefix="10.1.1.2",
            prefix_len=32,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=4)

        inet_rt2 = InetRoute(
            vrf=0,
            prefix="20.1.1.0",
            prefix_len=24,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt3 = InetRoute(
            vrf=0,
            prefix="30.1.0.0",
            prefix_len=16,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        inet_rt4 = InetRoute(
            vrf=0,
            prefix="40.0.0.0",
            prefix_len=8,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=7)

        ObjectBase.sync_all()

        # Query the objects back
        self.assertEqual("tap_1", vmi.get_vif_name())
        self.assertEqual(nh1.idx(), nh1.get_nh_idx())
        self.assertEqual(nh1.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt2.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet_rt3.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt4.get_rtr_nh_idx())

    # Add a route followed by a more specific route
    def test_rt_add_sub_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 11")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=1,
            prefix="10.2.0.0",
            prefix_len=16,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt2 = InetRoute(
            vrf=1,
            prefix="10.2.10.0",
            prefix_len=24,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        ObjectBase.sync_all()

        inet_query_obj = InetRoute(
            vrf=1,
            prefix="10.2.10.1",
            prefix_len=32,
            nh_idx=nh2.idx())

        # Query the objects back
        self.assertEqual(nh1.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt2.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_query_obj.get_rtr_nh_idx())

    # Add a specific route followed by a super route
    def test_rt_add_super_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 11")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=2,
            prefix="10.1.1.4",
            prefix_len=32,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt2 = InetRoute(
            vrf=2,
            prefix="10.1.1.0",
            prefix_len=24,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        ObjectBase.sync_all()

        inet_query_obj = InetRoute(
            vrf=2,
            prefix="10.1.1.10",
            prefix_len=32,
            nh_idx=nh2.idx())

        # Query the objects back
        self.assertEqual(nh1.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt2.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_query_obj.get_rtr_nh_idx())

    # Add a classless route with subnet mask=10
    def test_rt_add_classless_prefix(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        # add classless inet route
        inet_rt = InetRoute(
            vrf=3,
            prefix="1.1.0.0",
            prefix_len=10,
            nh_idx=nh1.idx(),
            rtr_label=5)

        ObjectBase.sync_all()

        # Query the objects back
        self.assertEqual(nh1.idx(), inet_rt.get_rtr_nh_idx())

    # Add routes at every level(8,16,24,32) and delete each one of them
    def test_rt_del_all(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=4,
            prefix="10.0.0.0",
            prefix_len=8,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt2 = InetRoute(
            vrf=4,
            prefix="20.10.0.0",
            prefix_len=16,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        inet_rt3 = InetRoute(
            vrf=4,
            prefix="30.1.10.0",
            prefix_len=24,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=7)

        inet_rt4 = InetRoute(
            vrf=4,
            prefix="40.1.1.10",
            prefix_len=32,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=8)

        ObjectBase.sync_all()

        inet_query_obj = InetRoute(
            vrf=4,
            prefix="30.1.10.0",
            prefix_len=24,
            nh_idx=nh1.idx())

        self.assertEqual(nh1.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt2.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet_rt3.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt4.get_rtr_nh_idx())

        # delete routes
        inet_rt1.rtr_nh_id = 0
        inet_rt1.rtr_label_flags = 0
        inet_rt1.delete()
        inet_rt2.rtr_nh_id = 0
        inet_rt2.rtr_label_flags = 0
        inet_rt2.delete()
        inet_rt3.rtr_nh_id = 0
        inet_rt3.rtr_label_flags = 0
        inet_rt3.delete()
        inet_rt4.rtr_nh_id = 0
        inet_rt4.rtr_label_flags = 0
        inet_rt4.delete()
        self.assertNotIn(inet_rt1.__obj_id__, ObjectBase.__obj_dict__)
        self.assertNotIn(inet_rt2.__obj_id__, ObjectBase.__obj_dict__)
        self.assertNotIn(inet_rt3.__obj_id__, ObjectBase.__obj_dict__)
        self.assertNotIn(inet_rt4.__obj_id__, ObjectBase.__obj_dict__)
        self.assertEqual(0, inet_query_obj.get_rtr_nh_idx())

    # Add super route followed by specific route and then delete the
    # specific route
    def test_rt_del_sub_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=5,
            prefix="10.2.0.0",
            prefix_len=16,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt2 = InetRoute(
            vrf=5,
            prefix="10.2.10.0",
            prefix_len=24,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        ObjectBase.sync_all()

        inet_query_obj = InetRoute(
           vrf=5,
           prefix="10.2.10.1",
           prefix_len=32,
           nh_idx=6)

        # Query the objects back
        self.assertEqual(nh1.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt2.get_rtr_nh_idx())

        # delete sub route
        inet_rt2.rtr_nh_id = nh1.idx()
        inet_rt2.rtr_replace_plen = 16
        inet_rt2.rtr_label_flags = inet_rt1.rtr_label_flags
        inet_rt2.rtr_label = inet_rt1.rtr_label
        inet_rt2.delete()
        self.assertEqual(nh1.idx(), inet_query_obj.get_rtr_nh_idx())
        self.assertNotIn(inet_rt2.__obj_id__, ObjectBase.__obj_dict__)

    # Add a super route(/16) followed by a specific route(/24) followed by a
    # classless super route(/18) and then delete the clasless route
    def test_rt_del_classless_super_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        nh3 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 04")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=6,
            prefix="10.2.0.0",
            prefix_len=16,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt2 = InetRoute(
            vrf=6,
            prefix="10.2.10.0",
            prefix_len=24,
            nh_idx=nh3.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        inet_rt3 = InetRoute(
            vrf=6,
            prefix="10.2.0.0",
            prefix_len=18,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=7)

        ObjectBase.sync_all()

        inet_query_obj = InetRoute(
            vrf=6,
            prefix="10.2.11.0",
            prefix_len=18,
            nh_idx=6)

        # Query the objects back
        self.assertEqual(nh2.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh3.idx(), inet_rt2.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet_rt3.get_rtr_nh_idx())

        # delete super route
        inet_rt3.rtr_nh_id = nh2.idx()
        inet_rt3.rtr_replace_plen = 16
        inet_rt3.rtr_label_flags = inet_rt1.rtr_label_flags
        inet_rt3.rtr_label = inet_rt1.rtr_label
        inet_rt3.delete()
        self.assertEqual(nh2.idx(), inet_query_obj.get_rtr_nh_idx())
        self.assertNotIn(inet_rt3.__obj_id__, ObjectBase.__obj_dict__)

    # Add a specific route followed by a super route and then delete the
    # specific route followed by deletion of super route
    def test_rt_del_all_sub_routes_and_super_bucket(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=7,
            prefix="10.2.10.0",
            prefix_len=24,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt2 = InetRoute(
            vrf=7,
            prefix="10.2.0.0",
            prefix_len=16,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        ObjectBase.sync_all()

        # Query the objects back
        self.assertEqual(nh1.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt2.get_rtr_nh_idx())

        # delete all routes
        inet_rt1.rtr_replace_plen = inet_rt2.rtr_prefix_len
        inet_rt1.rtr_nh_id = nh2.idx()
        # inet_rt1.rtr_label = inet_rt2.rtr_label
        inet_rt1.rtr_label_flags = inet_rt2.rtr_label_flags
        inet_rt1.delete()
        self.assertNotIn(inet_rt1.__obj_id__, ObjectBase.__obj_dict__)
        inet_rt2.rtr_nh_id = 0
        inet_rt2.rtr_label = 0
        inet_rt2.rtr_label_flags = 0
        inet_rt2.delete()
        self.assertNotIn(inet_rt2.__obj_id__, ObjectBase.__obj_dict__)

    # Add super route(/16) followed by specific mid level route(/24) followed
    # by a more specific route(/32) and then delete the mid level(/24) route
    def test_rt_del_mid_level(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        nh3 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 04")

        # add inet routes
        inet_rt1 = InetRoute(
            vrf=8,
            prefix="10.10.0.0",
            prefix_len=16,
            nh_idx=nh1.idx(),
            rtr_label_flags=5,
            rtr_label=5)

        inet_rt2 = InetRoute(
            vrf=8,
            prefix="10.10.4.0",
            prefix_len=24,
            nh_idx=nh2.idx(),
            rtr_label_flags=5,
            rtr_label=6)

        inet_rt3 = InetRoute(
            vrf=8,
            prefix="10.10.4.2",
            prefix_len=32,
            nh_idx=nh3.idx(),
            rtr_label_flags=5,
            rtr_label=7)

        ObjectBase.sync_all()

        # Query the objects back
        self.assertEqual(nh1.idx(), inet_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet_rt2.get_rtr_nh_idx())
        self.assertEqual(nh3.idx(), inet_rt3.get_rtr_nh_idx())

        # delete mid level route
        inet_rt2.rtr_nh_id = nh1.idx()
        inet_rt2.rtr_replace_plen = inet_rt1.rtr_prefix_len
        inet_rt2.rtr_label_flags = inet_rt1.rtr_label_flags
        inet_rt2.rtr_label = inet_rt1.rtr_label
        inet_rt2.delete()

        # deletion verification query
        self.assertNotIn(inet_rt2.__obj_id__, ObjectBase.__obj_dict__)
        for i in range(256):
            temp_prefix = "10.10.4." + str(i)
            temp_inet = InetRoute(
                vrf=8,
                prefix=temp_prefix,
                prefix_len=32,
                nh_idx=1)
            if(temp_inet.rtr_prefix == inet_rt3.rtr_prefix):
                self.assertEqual(nh3.idx(), temp_inet.get_rtr_nh_idx())
            else:
                self.assertEqual(nh1.idx(), temp_inet.get_rtr_nh_idx())
            del(temp_inet)
