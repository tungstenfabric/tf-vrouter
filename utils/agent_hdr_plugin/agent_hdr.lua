-- Dissects the agent header for pkts captured on pkt0 interface (DPDK and kernel mode)

agenthdr = DissectorTable.new("Agentheader")
agent_hdr_proto = Proto("ag_hdr", "Agent Header")

function agent_hdr_proto.init()
    DissectorTable.get("Agentheader"):add(147, agent_hdr_proto)
end

hdr_cmd_table = {}
hdr_cmd_table[0] =  "AGENT_CMD_SWITCH"
hdr_cmd_table[1] =  "AGENT_CMD_ROUTE"
hdr_cmd_table[2] = "AGENT_TRAP_ARP"
hdr_cmd_table[3] = "AGENT_TRAP_L2_PROTOCOLS"
hdr_cmd_table[4] = "AGENT_TRAP_NEXTHOP"
hdr_cmd_table[5] = "AGENT_TRAP_RESOLVE"
hdr_cmd_table[6] =  "AGENT_TRAP_FLOW_MISS"
hdr_cmd_table[7] =  "AGENT_TRAP_L3_PROTOCOLS"
hdr_cmd_table[8] =  "AGENT_TRAP_DIAG"
hdr_cmd_table[9] =  "AGENT_TRAP_ECMP_RESOLVE"
hdr_cmd_table[10] = "AGENT_TRAP_SOURCE_MISMATCH"
hdr_cmd_table[11] = "AGENT_TRAP_HANDLE_DF"
hdr_cmd_table[12] = "AGENT_TRAP_ZERO_TTL"
hdr_cmd_table[13] = "AGENT_TRAP_ICMP_ERROR"
hdr_cmd_table[14] = "AGENT_TRAP_TOR_CONTROL_PKT"
hdr_cmd_table[15] = "AGENT_TRAP_FLOW_ACTION_HOLD"
hdr_cmd_table[16] = "AGENT_TRAP_ROUTER_ALERT"
hdr_cmd_table[17] = "AGENT_TRAP_MAC_LEARN"
hdr_cmd_table[18] = "AGENT_TRAP_MAC_MOVE"
hdr_cmd_table[19] = "MAX_AGENT_HDR_COMMANDS"

agent_hdr_proto.fields = {}
agent_hdr_proto.fields["rewrite_info"] = ProtoField.bytes(
                                                        "rewrite_info",
                                                        "Rewrite Info")
agent_hdr_proto.fields["hdr_ifindex"] = ProtoField.uint16(
                                                        "hdr_ifindex",
                                                        "hdr_ifindex")
agent_hdr_proto.fields["hdr_vrf"] = ProtoField.uint16("hdr_vrf", "hdr_vrf")
agent_hdr_proto.fields["hdr_cmd"] = ProtoField.uint16("hdr_cmd", "hdr_cmd")
agent_hdr_proto.fields["hdr_cmd_param"] = ProtoField.uint32(
                                                          "hdr_cmd_param",
                                                          "hdr_cmd_param")
agent_hdr_proto.fields["hdr_cmd_param_1"] = ProtoField.uint32(
                                                           "hdr_cmd_param_1",
                                                           "hdr_cmd_param_1")
agent_hdr_proto.fields["hdr_cmd_param_2"] = ProtoField.uint32(
                                                           "hdr_cmd_param_2",
                                                           "hdr_cmd_param_2")
agent_hdr_proto.fields["hdr_cmd_param_3"] = ProtoField.uint32(
                                                           "hdr_cmd_param_3",
                                                           "hdr_cmd_param_3")
agent_hdr_proto.fields["hdr_cmd_param_4"] = ProtoField.uint32(
                                                           "hdr_cmd_param_4",
                                                           "hdr_cmd_param_4")
agent_hdr_proto.fields["hdr_cmd_param_5"] = ProtoField.uint8(
                                                          "hdr_cmd_param_5",
                                                          "hdr_cmd_param_5")
agent_hdr_proto.fields["hdr_cmd_param_5_pack"] = ProtoField.bytes(
                                                      "hdr_cmd_param_5_pack",
                                                      "hdr_cmd_param_5_pack")

function agent_hdr_proto.dissector(buffer, pinfo, tree)
      local offset = 0
      local f = agent_hdr_proto.fields
      tree:add(f["rewrite_info"], buffer(offset, 14))
      offset = offset + 14
      subtree = tree:add(agent_hdr_proto ,buffer(offset, 30))
      subtree:add(f["hdr_ifindex"], buffer(offset, 2))
      offset = offset + 2
      subtree:add(f["hdr_vrf"], buffer(offset, 2))
      offset = offset + 2
      subtree:add(f["hdr_cmd"], buffer(offset, 2)):append_text(
                  " (" .. hdr_cmd_table[buffer(offset, 2):uint()] .. ")")
      hdr_cmd_from_table = hdr_cmd_table[buffer(offset, 2):uint()]
      offset = offset + 2
      subtree:add(f["hdr_cmd_param"], buffer(offset, 4))
      offset = offset + 4
      subtree:add(f["hdr_cmd_param_1"], buffer(offset, 4))
      offset = offset + 4
      subtree:add(f["hdr_cmd_param_2"], buffer(offset, 4))
      offset = offset + 4
      subtree:add(f["hdr_cmd_param_3"], buffer(offset, 4))
      offset = offset + 4
      subtree:add(f["hdr_cmd_param_4"], buffer(offset, 4))
      offset = offset + 4
      subtree:add(f["hdr_cmd_param_5"], buffer(offset, 1))
      offset = offset + 1
      subtree:add(f["hdr_cmd_param_5_pack"], buffer(offset,3)):append_text(
                                  " [" .. buffer(offset, 1):uint() .. " " ..
                                            buffer(offset+1, 1):uint() .. " " ..
                                            buffer(offset+2, 1):uint() .. "]")
      offset = offset + 3

      ether = Dissector.get("eth_withoutfcs")
      ether:call(buffer(44):tvb(), pinfo, tree)
      pinfo.cols.info = hdr_cmd_from_table .. " " .. tostring(pinfo.cols.info)
end
