#!/bin/sh
# This script is used to dump a flow and it's reverse flow
usage()
{
    echo "One argument expected! Enter flow_index as argument."
    exit
}
if [ -z "$1" ]
    then
        usage
fi
cmd_string="dump_flow_index "
cmd_string+=$1
today=`date +%d_%m_%Y_%H_%M_%S`
out_file="flow_index_"
out_file+="$today"
out_file+=".txt"
echo "The output of this file is stored in "$out_file" file"
echo
gdb -p $(pidof contrail-vrouter-dpdk) -batch \
-ex "set pr pr" \
-ex "source ./vrouter.gdb" \
-ex "$cmd_string" \
-ex quit > "$out_file"
