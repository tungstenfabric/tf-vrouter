#!/bin/sh
cmd_string = "dump_flow_index "
cmd_string += $1
gdb -p $(pidof contrail-vrouter-dpdk) -batch -ex "set pr pr" -ex "source ./vrouter.gdb" -ex "$cmd_string" -ex quit
