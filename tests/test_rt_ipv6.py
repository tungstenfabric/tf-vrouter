#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test


class TestRTIPv6(unittest.TestCase):

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

    # Add route to random levels:8,32,64,128
    def test_rt_add(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 11")

        # add inet6 routes
        inet6_rt1 = Inet6Route(
            vrf=0,
            prefix="f00::00",
            prefix_len=8,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=0,
            prefix="a100:0011::",
            prefix_len=32,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        inet6_rt3 = Inet6Route(
            vrf=0,
            prefix="1000:0000:0000:11aa::",
            prefix_len=64,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=14)

        inet6_rt4 = Inet6Route(
            vrf=0,
            prefix="2000::1010",
            prefix_len=128,
            nh_idx=nh2.idx(),
            rtr_label_falgs=5,
            rtr_label=15)

        ObjectBase.sync_all()

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet6_rt3.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt4.get_rtr_nh_idx())

    # Add a route followed by a more specific route
    def test_rt_add_sub_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 11")

        # add inet6 routes
        inet6_rt1 = Inet6Route(
            vrf=1,
            prefix="ffaa::",
            prefix_len=16,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=1,
            prefix="ffaa::1100",
            prefix_len=120,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        ObjectBase.sync_all()

        inet6_query_obj1 = Inet6Route(
            vrf=1,
            prefix="ffaa::ff00",
            prefix_len=120,
            nh_idx=nh1.idx())

        inet6_query_obj2 = Inet6Route(
            vrf=1,
            prefix="ffaa::1120",
            prefix_len=128,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet6_query_obj1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_query_obj2.get_rtr_nh_idx())

    # Add a specific route followed by a super route
    def test_rt_add_super_route_inet6(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 11")

        # add inet6 routes
        inet6_rt1 = Inet6Route(
            vrf=2,
            prefix="1100::1100",
            prefix_len=120,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=2,
            prefix="1100::",
            prefix_len=8,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        ObjectBase.sync_all()

        inet6_query_obj = Inet6Route(
            vrf=2,
            prefix="1100::ff00",
            prefix_len=120,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_query_obj.get_rtr_nh_idx())
        self.assertEqual(13, int(inet6_query_obj.get('rtr_label')))

    # Add a classless route with subnet mask=50
    def test_rt_add_classless_prefix(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        # add classless inet route
        inet6_rt1 = Inet6Route(
            vrf=3,
            prefix="100:0:0:1100::",
            prefix_len=50,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        ObjectBase.sync_all()

        inet6_query_obj1 = Inet6Route(
            vrf=3,
            prefix="100:0:0:1200::",
            prefix_len=64,
            nh_idx=nh1.idx())

        inet6_query_obj2 = Inet6Route(
            vrf=3,
            prefix="100:0:0:fa00::",
            prefix_len=64,
            nh_idx=0)

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet6_query_obj1.get_rtr_nh_idx())
        self.assertEqual(0, inet6_query_obj2.get_rtr_nh_idx())

    # Add routes at random levels(8,32,64,128) and delete each one of them
    def test_rt_del_all(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        # add inet6 routes
        inet6_rt1 = Inet6Route(
            vrf=4,
            prefix="f00::",
            prefix_len=8,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=4,
            prefix="11:11::",
            prefix_len=32,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        inet6_rt3 = Inet6Route(
            vrf=4,
            prefix="1000:0000:0000:11aa::",
            prefix_len=64,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=14)

        inet6_rt4 = Inet6Route(
            vrf=4,
            prefix="2000::1010",
            prefix_len=128,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=15)

        ObjectBase.sync_all()

        inet6_query_obj = Inet6Route(
            vrf=4,
            prefix="2000::1010",
            prefix_len=128,
            nh_idx=nh2.idx())

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())

        # delete routes
        inet6_rt1.rtr_nh_id = 0
        inet6_rt1.rtr_label_flags = 0
        inet6_rt1.delete()
        inet6_rt2.rtr_nh_id = 0
        inet6_rt2.rtr_label_flags = 0
        inet6_rt2.delete()
        inet6_rt3.rtr_nh_id = 0
        inet6_rt3.rtr_label_flags = 0
        inet6_rt3.delete()
        inet6_rt4.rtr_nh_id = 0
        inet6_rt4.rtr_label_flags = 0
        inet6_rt4.delete()
        self.assertNotIn(inet6_rt1.__obj_id__, ObjectBase.__obj_dict__)
        self.assertNotIn(inet6_rt2.__obj_id__, ObjectBase.__obj_dict__)
        self.assertNotIn(inet6_rt3.__obj_id__, ObjectBase.__obj_dict__)
        self.assertNotIn(inet6_rt4.__obj_id__, ObjectBase.__obj_dict__)
        self.assertEqual(0, inet6_query_obj.get_rtr_nh_idx())

    # Add super route followed by specific route and then delete the
    # specific route
    def test_rt_del_sub_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        # add inet6 routes
        inet6_rt1 = Inet6Route(
            vrf=5,
            prefix="ff00::",
            prefix_len=8,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=5,
            prefix="ff00::1000",
            prefix_len=120,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        ObjectBase.sync_all()

        inet6_query_obj = Inet6Route(
            vrf=5,
            prefix="ff00::1000",
            prefix_len=120,
            nh_idx=6)

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())

        # delete sub route
        inet6_rt2.rtr_nh_id = nh1.idx()
        inet6_rt2.rtr_replace_plen = 8
        inet6_rt2.rtr_label = inet6_rt1.rtr_label
        inet6_rt2.delete()
        self.assertEqual(nh1.idx(), inet6_query_obj.get_rtr_nh_idx())
        self.assertNotIn(inet6_rt2.__obj_id__, ObjectBase.__obj_dict__)

    # Add a super route(/8) followed by a specific route(/114) followed by a
    # classless super route(/120) and then delete the classless route
    def test_rt_del_classless_super_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        nh3 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 04")

        inet6_rt1 = Inet6Route(
            vrf=6,
            prefix="ff00::",
            prefix_len=8,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=6,
            prefix="ff00::1:0",
            prefix_len=114,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        inet6_rt3 = Inet6Route(
            vrf=6,
            prefix="ff00::1:1000",
            prefix_len=120,
            nh_idx=nh3.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=14)

        ObjectBase.sync_all()

        inet6_query_obj = Inet6Route(
            vrf=6,
            prefix="ff00::1:2000",
            prefix_len=120,
            nh_idx=6,
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())
        self.assertEqual(nh3.idx(), inet6_rt3.get_rtr_nh_idx())

        # delete super route
        inet6_rt2.rtr_nh_id = nh1.idx()
        inet6_rt2.rtr_label = inet6_rt1.rtr_label
        inet6_rt2.rtr_replace_plen = 8
        inet6_rt2.delete()
        self.assertEqual(nh1.idx(), inet6_query_obj.get_rtr_nh_idx())
        self.assertEqual(12, int(inet6_query_obj.get('rtr_label')))
        self.assertNotIn(inet6_rt2.__obj_id__, ObjectBase.__obj_dict__)

    # Add a specific route followed by a super route and then delete the
    # specific route followed by deletion of super route
    def test_rt_del_all_sub_routes_and_super_route(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        # add inet routes
        inet6_rt1 = Inet6Route(
            vrf=7,
            prefix="1100:0:100::",
            prefix_len=40,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=7,
            prefix="1100:0:100:0:12::",
            prefix_len=80,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        ObjectBase.sync_all()

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())

        # delete all routes
        inet6_rt2.rtr_replace_plen = inet6_rt1.rtr_prefix_len
        inet6_rt2.rtr_nh_id = nh1.idx()
        inet6_rt2.rtr_label = inet6_rt1.rtr_label
        inet6_rt2.delete()
        self.assertNotIn(inet6_rt2.__obj_id__, ObjectBase.__obj_dict__)
        inet6_rt1.rtr_nh_id = 0
        inet6_rt1.rtr_label = 0
        inet6_rt1.rtr_label_flags = 0
        inet6_rt1.delete()
        self.assertNotIn(inet6_rt1.__obj_id__, ObjectBase.__obj_dict__)

    # Add super route(/8) followed by specific mid level route(/40) followed
    # by a more specific route(/128) and then delete the mid level(/40) route
    def test_rt_del_mid_level(self):
        vmi = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         ipv6_str="aa:1f00::2", mac_str="de:ad:be:ef:00:02")

        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")

        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 02")

        nh3 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 04")

        # add inet routes
        inet6_rt1 = Inet6Route(
            vrf=8,
            prefix="ff00::",
            prefix_len=8,
            nh_idx=nh1.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=12)

        inet6_rt2 = Inet6Route(
            vrf=8,
            prefix="ff00:0:f::",
            prefix_len=40,
            nh_idx=nh2.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=13)

        inet6_rt3 = Inet6Route(
            vrf=8,
            prefix="ff00:0:f::1",
            prefix_len=128,
            nh_idx=nh3.idx(),
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG,
            rtr_label=14)

        ObjectBase.sync_all()

        inet6_query_obj = Inet6Route(
            vrf=8,
            prefix="ff00:0:f::2",
            prefix_len=120,
            nh_idx=nh1.idx())

        # Query the objects back
        self.assertEqual(nh1.idx(), inet6_rt1.get_rtr_nh_idx())
        self.assertEqual(nh2.idx(), inet6_rt2.get_rtr_nh_idx())
        self.assertEqual(nh3.idx(), inet6_rt3.get_rtr_nh_idx())

        # delete mid level route
        inet6_rt2.rtr_nh_id = nh1.idx()
        inet6_rt2.rtr_replace_plen = inet6_rt1.rtr_prefix_len
        inet6_rt2.rtr_label = inet6_rt1.rtr_label
        inet6_rt2.delete()

        # deletion verification query
        self.assertNotIn(inet6_rt2.__obj_id__, ObjectBase.__obj_dict__)
        self.assertEqual(nh3.idx(), inet6_rt3.get_rtr_nh_idx())
        self.assertEqual(nh1.idx(), inet6_query_obj.get_rtr_nh_idx())
