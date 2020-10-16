-- IP over MPLSoUDP protocol with a control word

-- declare our MPLS protocol
mpls_protocol = Proto("MPLSoUDP_CW", "IP over MPLSoUDP with Control Word dissector")

-- MPLS header fields
	--        0            1            2            3
	--    0000 0001    0010 0001    0010 ....    .... .... = MPLS Label: 4626
    --    .... ....    .... ....    .... 000.    .... .... = MPLS Experimental Bits: 0
    --    .... ....    .... ....    .... ...1    .... .... = MPLS Bottom Of Label Stack: 1
    --    .... ....    .... ....    .... ....    0100 0000 = MPLS TTL: 64

MPLS_HDR_LEN = 8
MPLS_LBL = ProtoField.uint32("Label", "Label", base.DEC, NULL, 0xFFFFF000)
MPLS_TC = ProtoField.uint32("TrafficClass", "Traffic Class", base.DEC, NULL, 0xE00)
MPLS_BOS = ProtoField.uint32("BottomofLabelStack", "Bottom of Label Stack", base.DEC, NULL, 0x100)
MPLS_TTL = ProtoField.uint32("TTL", "TTL", base.DEC, NULL, 0xFF)

mpls_protocol.fields = { MPLS_LBL, MPLS_TC, MPLS_BOS, MPLS_TTL }


-- create a function to dissect IP over a MPLS stack with a control word
function mpls_protocol.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "MPLS Protocol"

	-- process the MPLS SHIM header
	local MPLS_SHIM_raw = buffer(0,4)
    local MPLS_SHIM_int = MPLS_SHIM_raw:int()

    local raw_label = buffer(0,3):uint()
    masked_label = bit.band(raw_label, 0xFFFFF0)
    label = bit.rshift(masked_label,4)
    masked_tc = bit.band(raw_label, 0xE)
    tc = bit.rshift(masked_tc,1)
	bos = bit.band(raw_label, 0x1)
	ttl = buffer(3,1):uint()

    local subtree = tree:add(mpls_protocol,buffer(0,4),"MultiProtocol Label Switching Header, Label:", label .. ", TC:", tc .. ", S:", bos .. ", TTL:", ttl)
    subtree:add(MPLS_LBL, MPLS_SHIM_raw, MPLS_SHIM_int)
    subtree:add(MPLS_TC, MPLS_SHIM_raw, MPLS_SHIM_int)
    subtree:add(MPLS_BOS, MPLS_SHIM_raw, MPLS_SHIM_int)
    subtree:add(MPLS_TTL, MPLS_SHIM_raw, MPLS_SHIM_int)

	-- process the control word
	local subtree = tree:add(mpls_protocol,buffer(4,4),"Control Word, CW:", buffer(4,4):uint())
    subtree:add(buffer(4,4),"Control Word:", buffer(4,4):uint())

	-- process the IP protocol
	local ip_dissector_table = DissectorTable.get("ethertype")
    original_ip_dissector = ip_dissector_table:get_dissector(0x800)
	original_ip_dissector:call(buffer(MPLS_HDR_LEN,len):tvb(),pinfo,tree)

end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")

-- register our protocol to handle udp port 6635 (MPLS over UDP)
udp_table:add(6635,mpls_protocol)
