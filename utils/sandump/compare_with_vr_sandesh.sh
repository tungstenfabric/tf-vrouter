#!/bin/bash
#Does a comparison with vr.sandesh file and checks if-
#1.Respective Sandesh object's lua script is present in sandump_wireshark_plugin dir
#2.Respective Sandesh object is defined in global_table in common.lua by the user
#3.Fields which are not mentioned in existing lua scripts of Sandesh objs
#This script can be run using "scons --add-opts=checkWiresharkPlugins vrouter" from top level dir in sandbox

PLUGIN_PATH="./vrouter/utils/sandump/sandump_wireshark_plugin/"
VR_SANDESH_PATH="./vrouter/sandesh/vr.sandesh"

was_errors=0
function err() {
  echo -e "$(date -u +"%Y-%m-%d %H:%M:%S,%3N"): ERROR: $@" >&2
  was_errors=1
}

vr_sandesh_objs=$(grep 'sandesh' $VR_SANDESH_PATH | awk '{print $3}' | grep -v ';\|{\|-')
abvs=$(grep -r 'abv' "$PLUGIN_PATH"common.lua"" | awk '{gsub("\"", " ", $3); print $3}')
abv_to_search=""
abvs_arr=( $abvs )
for abv in $abvs; do
    if [[ "$abv" != ${abvs_arr[-1]} ]]; then
        abv_to_search=($abv_to_search"$abv"_\\\|"")
    else
        abv_to_search=($abv_to_search"$abv"_"")
    fi
done

vr_sandesh_fields=$(grep $abv_to_search $VR_SANDESH_PATH | awk '{gsub(";", "", $3); print $3; gsub(";", "", $4); print $4}')
plugin_fields=$(grep -r 'field_name' $PLUGIN_PATH --exclude={main.lua,helpers.lua,common.lua,*.swp} | awk '{gsub("\"", "", $3); print $3}')
common_lua_objs=$(grep -r 'name' "$PLUGIN_PATH"common.lua"" | awk '{gsub("\"", "", $3); print $3}')

lua_scripts=()
for i in $vr_sandesh_objs; do # access each element of array
    if [[ "$i" == *"_req" ]]; then
        lua_scripts+=($PLUGIN_PATH"${i//_req/.lua}")
    else
        lua_scripts+=($PLUGIN_PATH"$i".lua"")
    fi
done

# check if lua script exists
LUA_SCRIPT_EXISTS=0
for FILE in "${lua_scripts[@]}";do
   if ( [ ! -f "$FILE" ] && [ $LUA_SCRIPT_EXISTS != 1 ] ); then
      LUA_SCRIPT_EXISTS=1
      err "Following Lua scripts are not present:-"
   fi

   if [ ! -f "$FILE" ]; then
      echo "$FILE"
   fi
done

# check if all objs are defined in common.lua
objs_not_defined_in_common=$(echo ${vr_sandesh_objs[@]} ${common_lua_objs[@]} | tr ' ' '\n' | sort | uniq -u)
if [[ $objs_not_defined_in_common ]]; then
    err "Following Sandesh objects not defined in common.lua :-\n$objs_not_defined_in_common"
fi

# check if all fields are defined in lua scripts
fields_not_defined_in_plugin=$(echo ${vr_sandesh_fields[@]} ${plugin_fields[@]} | tr ' ' '\n' | sort | uniq -u | grep -v -e ".._req" -e "h_op")
if [[ $fields_not_defined_in_plugin ]]; then
    err "Following fields are not defined in plugin :-\n$fields_not_defined_in_plugin"
fi

if [ $was_errors -ne 0 ]; then
  exit 1
fi
