#!/bin/sh
# This script is used to dump all the vifs, nexthops and route tables
echo "WARNING:This script may take several minutes to complete execution."
echo "The output of this script will be saved in the vrouter_all_minimal.txt file"
echo
out_all_file="vrouter_all_minimal.txt"
date > "$out_all_file"
gdb -p $(pidof contrail-vrouter-dpdk) -batch \
-ex "set pr pr" \
-ex "source ./vrouter.gdb" \
-ex "dump_vif_all" \
-ex "dump_nh_all" \
-ex "dump_rtable_all" \
-ex quit >> "$out_all_file"
