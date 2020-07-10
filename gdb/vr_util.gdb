#   File: "vr_util.gdb"
#   This file contains the utilities for vrouter gdb macros.

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

#arg0:ipv4 in decimal
define get_ipv4
    printf "%d.%d.", ($arg0 & 0xff), ($arg0 >> 8) & 0xff
    printf "%d.%d ", ($arg0 >> 16) & 0xff, ($arg0 >> 24)  & 0xff
end

#arg0:uint8_t *mac
define mac_address
    printf "%02x:%02x:%02x:", $arg0[0], $arg0[1], $arg0[2]
    printf "%02x:%02x:%02x ", $arg0[3], $arg0[4], $arg0[5]
end

#arg0:uint8_t *vif_ip6
define print_ipv6
    set $count = 0
    set $vif_ipv6 = $arg0
    while($count<16)
        if($count == 0)
            printf "%02x%02x",$vif_ipv6[$count], $vif_ipv6[$count+1]
        else
            printf ":%02x%02x",$vif_ipv6[$count], $vif_ipv6[$count+1]
        end
        set $count = $count + 2
    end
    printf "\n"
end
