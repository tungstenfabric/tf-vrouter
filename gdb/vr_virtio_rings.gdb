#   File: "vr_virtio_rings.gdb"
#   This file contains the gdb macros to dump the dpdk virtio tx and rx queues.


# arg0:vif_id, arg1:queue_id
define dump_virtio_rxq_index
    set $rxqs = vr_dpdk_virtio_rxqs[$arg0]
    printf "RX_Queue(id:%d)\n", $arg1
    print_rxtxqueue_internal $rxqs[$arg1]
end

document dump_virtio_rxq_index
Syntax: dump_virtio_rxq_index vif_id queue_id
This macro prints virtio rx queue details of queue:queue_id for vif:vif_id
end

# arg0:vif_id, arg1:queue_id
define dump_virtio_txq_index
    set $txqs = vr_dpdk_virtio_txqs[$arg0]
    printf "TX_Queue(id:%d)\n", $arg1
    print_rxtxqueue_internal $txqs[$arg1]
end

document dump_virtio_txq_index
Syntax: dump_virtio_txq_index vif_id queue_id
This macro prints virtio tx queue details of queue:queue_id for vif:vif_id
end

# arg0:struct vr_dpdk_virtioq object
define print_rxtxqueue_internal
    set $vq = (vr_dpdk_virtioq_t)($arg0)
    printf "vif_id:%u    ", $vq.vdv_vif_idx
    print_vq_ready_state $vq.vdv_ready_state
    printf "size:%u    hlen:%u    ", $vq.vdv_size, $vq.vdv_hlen
    printf "hash:%u\n", $vq.vdv_hash
    printf "callfd:%d    kickfd:%d\n", $vq.vdv_callfd, $vq.vdv_kickfd
    printf "last_used_idx: %d\n", $vq.vdv_last_used_idx
    printf "last_used_idx_res: %d\n", $vq.vdv_last_used_idx_res
    print_desc_vrings $vq.vdv_desc $vq.vdv_size
    printf "\n"
    print_avail_rings $vq.vdv_avail $vq.vdv_size
    print_used_rings $vq.vdv_used $vq.vdv_size
end

# arg0:vq.vdv_ready_state
define print_vq_ready_state
    printf "state:"
    if($arg0 == 0)
        printf "VQ_NOT_READY"
    end
    if($arg0 == 1)
        printf "VQ_READY"
    end
    printf "\n"
end

# arg0:vq.vdv_desc ptr, arg1:vq.vdv_size
define print_desc_vrings
    set $desc = (struct vring_desc *)($arg0)
    printf "Descriptor vRings:\n"
    printf "-----------------------------------------\n"
    printf "SNo.  addr         len    next    flags\n"
    printf "-----------------------------------------\n"
    set $vring_iter = 0
    while($vring_iter < $arg1)
	printf "%-6d", $vring_iter
        printf "0x%-10x ", $desc[$vring_iter].addr
        printf "%-7u", $desc[$vring_iter].len
        printf "%-8hu", $desc[$vring_iter].next
        print_desc_flags $desc[$vring_iter].flags
        printf "\n"
        set $vring_iter += 1
    end
end

# arg0:vq.vdv_avail ptr, arg1:vq.vdv_size
define print_avail_rings
    set $avail = (struct vring_avail *)($arg0)
    printf "Available vRings:\n"
    set $avail_flags = (void)(0)
    if($avail.flags & 1)
        set $avail_flags = "NO_INTERRUPT"
    else
	set $avail_flags = " "
    end
    printf "flags:%s    idx(mod q_size):%hu(%hu)\n", $avail_flags, $avail.idx, (($avail.idx)%($arg1))
    printf "---------\n"
    printf "SNo.  id\n"
    printf "---------\n"
    set $avail_iter = 0
    while($avail_iter < $arg1)
        printf "%-6d", $avail_iter
        printf "%hu\n", $avail.ring[$avail_iter]
        set $avail_iter += 1
    end
    printf "\n"
end

# arg0:vq.vdv_used ptr, arg1:vq.vdv_size
define print_used_rings
    set $used = (struct vring_used *)($arg0)
    printf "Used vRings:\n"
    set $used_flags = (void)(0)
    if($used.flags & 1)
        set $used_flags = "NO_NOTIFY"
    else
        set $avail_flags = " "
    end
    printf "flags:%s    idx(mod q_size):%hu(%hu)\n", $used_flags, $used.idx, (($used.idx)%($arg1))
    printf "---------------\n"
    printf "SNo.  id    len\n"
    printf "---------------\n"
    set $used_iter = 0
    while($used_iter < $arg1)
        set $used_ring_entry = (struct vring_used_elem)($used.ring[$used_iter])
        printf "%-6d", $used_iter
        printf "%-5u %u\n", $used_ring_entry.id, $used_ring_entry.len
        set $used_iter += 1
    end
    printf "\n"
end


# arg0:vdv_desc.flags
define print_desc_flags
    if($arg0 & 1)
        printf "NEXT, "
    end
    if($arg0 & 2)
        printf "WRITE, "
    end
    if($arg0 & 4)
        printf "INDIRECT"
    end
end
