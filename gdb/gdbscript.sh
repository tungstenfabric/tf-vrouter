#!/bin/sh
gdb -p $(pidof contrail-vrouter-dpdk) -batch -ex "set pr pr" -ex "source ./vrouter.gdb" -ex "dump_vif_all" -ex "dump_nh_all" -ex "dump_rtable_all" -ex quit
