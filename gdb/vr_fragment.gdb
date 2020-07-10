#   File: "vr_fragment.gdb"
#   This file contains the gdb macros to dump the vrouter fragment
#   table information.

set $fragment_table = (struct vr_htable *)(router.vr_fragment_table)

define dump_fragment_table
    printf "\nFragment Table(f_time, id, src, dst, sport, dport, port_info)\n\n"
    set $i = 0
    set $j = 0
    set $max_index = $fragment_table.ht_hentries + $fragment_table.ht_oentries - 1
    dump_fragment_range_internal 0 $max_index
end

document dump_fragment_table
Syntax:dump_fragment_table
No. of arguments:0
Description:This function dumps each entry in the fragment table

end

#arg0:start_index, arg1:end_index
define dump_fragment_range_internal
    set $temp_table_ptr = -1
    set $i = $arg0
    set $j = 0
    set $k = 0
    if($fragment_table)
        if($arg1>$fragment_table.ht_hentries)
            set $k = $arg1 - $fragment_table.ht_hentries
        end
        get_index_addr_btable $fragment_table.ht_htable $i $temp_table_ptr
        if($fragment_table.ht_used_entries)
            while(($i < $fragment_table.ht_hentries) && ($i < $arg1))
                dump_fragment_internal $temp_table_ptr $i
                set $i = $i + 1
                set $temp_table_ptr = $temp_table_ptr + $fragment_table.ht_entry_size
            end
        end
        get_index_addr_btable $fragment_table.ht_otable $j $temp_table_ptr
        if(($fragment_table.ht_used_oentries) && ($k))
            printf "Overflow Entries:\n\n"
            while(($j<$fragment_table.ht_oentries) && ($j<$k))
                dump_fragment_internal $temp_table_ptr $j
                set $j = $j + 1
                set $temp_table_ptr = $temp_table_ptr + $fragment_table.ht_entry_size
            end
        end
    end
    printf "\n"
end

#arg0:fragment_table_ptr, arg1:index
define dump_fragment_internal
    if($arg0 != -1)
        set $cur_fragment = (struct vr_fragment *)($arg0)
        printf "%llu", $cur_fragment.f_time
        printf "   %-12u", $cur_fragment.f_key.fk_id
        printf "   "
        set $ip6_flag = 0
        if($cur_fragment.f_key.fk_sip_u)
            set $ip6_flag = 1
            ipv6_hex_convert $cur_fragment.f_key.fk_sip_u
            printf ":"
            ipv6_hex_convert $cur_fragment.f_key.fk_sip_l
        else
            get_ipv4 $cur_fragment.f_key.fk_sip_l
        end
        printf "   "
        if($cur_fragment.f_key.fk_dip_u || $ip6_flag)
            ipv6_hex_convert $cur_fragment.f_key.fk_dip_u
            printf ":"
            ipv6_hex_convert $cur_fragment.f_key.fk_dip_l
        else
            get_ipv4 $cur_fragment.f_key.fk_dip_l
        end
        printf "   %-8hu", $cur_fragment.f_sport
        printf "   %-8hu", $cur_fragment.f_dport
        printf "   "
        if($cur_fragment.f_port_info_valid)
            printf "valid\n"
        else
            printf "invalid\n"
        end
        printf "\n"
    end
end

#arg0:uint64_t high or low
#Displays only half ip6 address. Called twice
define ipv6_hex_convert
    set $c1 = 0
    set $ip6 = $arg0
    while($c1<8)
        printf "%02x", $ip6 & 0xff
        if(($c1 & 1) && ($c1 != 7))
            printf ":"
        end
        set $ip6 = $ip6 >> 8
        set $c1 += 1
    end
end
