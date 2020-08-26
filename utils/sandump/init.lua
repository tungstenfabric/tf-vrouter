-- init.lua
--
-- initialize wireshark's lua
--
--  This file is going to be executed before any other lua script.
--  It can be used to load libraries, disable functions and more.
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- SPDX-License-Identifier: GPL-2.0-or-later

-- Set enable_lua to false to disable Lua support.
enable_lua = true

if not enable_lua then
    return
end

-- If set and Wireshark was started as (setuid) root, then the user
-- will not be able to execute custom Lua scripts from the personal
-- configuration directory, the -Xlua_script command line option or
-- the Lua Evaluate menu option in the GUI.
run_user_scripts_when_superuser = true


function typeof(obj)
    local mt = getmetatable(obj)
    return mt and mt.__typeof or obj.__typeof or type(obj)
end

-- the following function checks if a file exists
-- since 1.11.3
function file_exists(name)
   local f = io.open(name,"r")
   if f ~= nil then io.close(f) return true else return false end
end

-- the following function prepends the given directory name to
-- the package.path, so that a 'require "foo"' will work if 'foo'
-- is in the directory name given to this function. For example,
-- if your Lua file will do a 'require "foo"' and the foo.lua
-- file is in a local directory (local to your script) named 'bar',
-- then call this function before doing your 'require', by doing
--     package.prepend_path("bar")
-- and that will let Wireshark's Lua find the file "bar/foo.lua"
-- when you later do 'require "foo"'
--
-- Because this function resides here in init.lua, it does not
-- have the same environment as your script, so it has to get it
-- using the debug library, which is why the code appears so
-- cumbersome.
--
-- since 1.11.3
function package.prepend_path(name)
    -- get the function calling this package.prepend_path function
    local dt = debug.getinfo(2, "f")
    if not dt then
        error("could not retrieve debug info table")
    end
    -- get its upvalue
    local _, val = debug.getupvalue(dt.func, 1)
    if not val or type(val) ~= 'table' then
        error("No calling function upvalue or it is not a table")
    end
    -- get the __DIR__ field in its upvalue table
    local dir = val["__DIR__"]
    -- get the platform-specific directory separator character
    local sep = package.config:sub(1,1)
    -- prepend the dir and given name to path
    if dir and dir:len() > 0 then
        package.path = dir .. sep .. name .. sep .. "?.lua;" .. package.path
    end
    -- also prepend just the name as a directory
    package.path = name .. sep .. "?.lua;" .. package.path
end

-- Wiretap encapsulations XXX
wtap_encaps = {
	["PER_PACKET"] = -1,
	["UNKNOWN"] = 0,
	["ETHERNET"] = 1,
	["TOKEN_RING"] = 2,
	["SLIP"] = 3,
	["PPP"] = 4,
	["FDDI"] = 5,
	["FDDI_BITSWAPPED"] = 6,
	["RAW_IP"] = 7,
	["ARCNET"] = 8,
	["ARCNET_LINUX"] = 9,
	["ATM_RFC1483"] = 10,
	["LINUX_ATM_CLIP"] = 11,
	["LAPB"] = 12,
	["ATM_PDUS"] = 13,
	["ATM_PDUS_UNTRUNCATED"] = 14,
	["NULL"] = 15,
	["ASCEND"] = 16,
	["ISDN"] = 17,
	["IP_OVER_FC"] = 18,
	["PPP_WITH_PHDR"] = 19,
	["IEEE_802_11"] = 20,
	["IEEE_802_11_PRISM"] = 21,
	["IEEE_802_11_WITH_RADIO"] = 22,
	["IEEE_802_11_RADIOTAP"] = 23,
	["IEEE_802_11_AVS"] = 24,
	["SLL"] = 25,
	["FRELAY"] = 26,
	["FRELAY_WITH_PHDR"] = 27,
	["CHDLC"] = 28,
	["CISCO_IOS"] = 29,
	["LOCALTALK"] = 30,
	["OLD_PFLOG"] = 31,
	["HHDLC"] = 32,
	["DOCSIS"] = 33,
	["COSINE"] = 34,
	["WFLEET_HDLC"] = 35,
	["SDLC"] = 36,
	["TZSP"] = 37,
	["ENC"] = 38,
	["PFLOG"] = 39,
	["CHDLC_WITH_PHDR"] = 40,
	["BLUETOOTH_H4"] = 41,
	["MTP2"] = 42,
	["MTP3"] = 43,
	["IRDA"] = 44,
	["USER0"] = 45,
	["USER1"] = 46,
	["USER2"] = 47,
	["USER3"] = 48,
	["USER4"] = 49,
	["USER5"] = 50,
	["USER6"] = 51,
	["USER7"] = 52,
	["USER8"] = 53,
	["USER9"] = 54,
	["USER10"] = 55,
	["USER11"] = 56,
	["USER12"] = 57,
	["USER13"] = 58,
	["USER14"] = 59,
	["USER15"] = 60,
	["SYMANTEC"] = 61,
	["APPLE_IP_OVER_IEEE1394"] = 62,
	["BACNET_MS_TP"] = 63,
	["NETTL_RAW_ICMP"] = 64,
	["NETTL_RAW_ICMPV6"] = 65,
	["GPRS_LLC"] = 66,
	["JUNIPER_ATM1"] = 67,
	["JUNIPER_ATM2"] = 68,
	["REDBACK"] = 69,
	["NETTL_RAW_IP"] = 70,
	["NETTL_ETHERNET"] = 71,
	["NETTL_TOKEN_RING"] = 72,
	["NETTL_FDDI"] = 73,
	["NETTL_UNKNOWN"] = 74,
	["MTP2_WITH_PHDR"] = 75,
	["JUNIPER_PPPOE"] = 76,
	["GCOM_TIE1"] = 77,
	["GCOM_SERIAL"] = 78,
	["NETTL_X25"] = 79,
	["K12"] = 80,
	["JUNIPER_MLPPP"] = 81,
	["JUNIPER_MLFR"] = 82,
	["JUNIPER_ETHER"] = 83,
	["JUNIPER_PPP"] = 84,
	["JUNIPER_FRELAY"] = 85,
	["JUNIPER_CHDLC"] = 86,
	["JUNIPER_GGSN"] = 87,
	["LINUX_LAPD"] = 88,
	["CATAPULT_DCT2000"] = 89,
	["BER"] = 90,
	["JUNIPER_VP"] = 91,
	["USB_FREEBSD"] = 92,
	["IEEE802_16_MAC_CPS"] = 93,
	["NETTL_RAW_TELNET"] = 94,
	["USB_LINUX"] = 95,
	["MPEG"] = 96,
	["PPI"] = 97,
	["ERF"] = 98,
	["BLUETOOTH_H4_WITH_PHDR"] = 99,
	["SITA"] = 100,
	["SCCP"] = 101,
	["BLUETOOTH_HCI"] = 102,
	["IPMB_KONTRON"] = 103,
	["IEEE802_15_4"] = 104,
	["X2E_XORAYA"] = 105,
	["FLEXRAY"] = 106,
	["LIN"] = 107,
	["MOST"] = 108,
	["CAN20B"] = 109,
	["LAYER1_EVENT"] = 110,
	["X2E_SERIAL"] = 111,
	["I2C_LINUX"] = 112,
	["IEEE802_15_4_NONASK_PHY"] = 113,
	["TNEF"] = 114,
	["USB_LINUX_MMAPPED"] = 115,
	["GSM_UM"] = 116,
	["DPNSS"] = 117,
	["PACKETLOGGER"] = 118,
	["NSTRACE_1_0"] = 119,
	["NSTRACE_2_0"] = 120,
	["FIBRE_CHANNEL_FC2"] = 121,
	["FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS"] = 122,
	["JPEG_JFIF"] = 123,
	["IPNET"] = 124,
	["SOCKETCAN"] = 125,
	["IEEE_802_11_NETMON"] = 126,
	["IEEE802_15_4_NOFCS"] = 127,
	["RAW_IPFIX"] = 128,
	["RAW_IP4"] = 129,
	["RAW_IP6"] = 130,
	["LAPD"] = 131,
	["DVBCI"] = 132,
	["MUX27010"] = 133,
	["MIME"] = 134,
	["NETANALYZER"] = 135,
	["NETANALYZER_TRANSPARENT"] = 136,
	["IP_OVER_IB_SNOOP"] = 137,
	["MPEG_2_TS"] = 138,
	["PPP_ETHER"] = 139,
	["NFC_LLCP"] = 140,
	["NFLOG"] = 141,
	["V5_EF"] = 142,
	["BACNET_MS_TP_WITH_PHDR"] = 143,
	["IXVERIWAVE"] = 144,
	["SDH"] = 145,
	["DBUS"] = 146,
	["AX25_KISS"] = 147,
	["AX25"] = 148,
	["SCTP"] = 149,
	["INFINIBAND"] = 150,
	["JUNIPER_SVCS"] = 151,
	["USBPCAP"] = 152,
	["RTAC_SERIAL"] = 153,
	["BLUETOOTH_LE_LL"] = 154,
	["WIRESHARK_UPPER_PDU"] = 155,
	["STANAG_4607"] = 156,
	["STANAG_5066_D_PDU"] = 157,
	["NETLINK"] = 158,
	["BLUETOOTH_LINUX_MONITOR"] = 159,
	["BLUETOOTH_BREDR_BB"] = 160,
	["BLUETOOTH_LE_LL_WITH_PHDR"] = 161,
	["NSTRACE_3_0"] = 162,
	["LOGCAT"] = 163,
	["LOGCAT_BRIEF"] = 164,
	["LOGCAT_PROCESS"] = 165,
	["LOGCAT_TAG"] = 166,
	["LOGCAT_THREAD"] = 167,
	["LOGCAT_TIME"] = 168,
	["LOGCAT_THREADTIME"] = 169,
	["LOGCAT_LONG"] = 170,
	["PKTAP"] = 171,
	["EPON"] = 172,
	["IPMI_TRACE"] = 173,
	["LOOP"] = 174,
	["JSON"] = 175,
	["NSTRACE_3_5"] = 176,
	["ISO14443"] = 177,
	["GFP_T"] = 178,
	["GFP_F"] = 179,
	["IP_OVER_IB_PCAP"] = 180,
	["JUNIPER_VN"] = 181,
	["USB_DARWIN"] = 182,
	["LORATAP"] = 183,
	["3MB_ETHERNET"] = 184,
	["VSOCK"] = 185,
	["NORDIC_BLE"] = 186,
	["NETMON_NET_NETEVENT"] = 187,
	["NETMON_HEADER"] = 188,
	["NETMON_NET_FILTER"] = 189,
	["NETMON_NETWORK_INFO_EX"] = 190,
	["MA_WFP_CAPTURE_V4"] = 191,
	["MA_WFP_CAPTURE_V6"] = 192,
	["MA_WFP_CAPTURE_2V4"] = 193,
	["MA_WFP_CAPTURE_2V6"] = 194,
	["MA_WFP_CAPTURE_AUTH_V4"] = 195,
	["MA_WFP_CAPTURE_AUTH_V6"] = 196,
	["JUNIPER_ST"] = 197,
	["ETHERNET_MPACKET"] = 198,
	["DOCSIS31_XRA31"] = 199,
	["DPAUXMON"] = 200,
	["RUBY_MARSHAL"] = 201,
	["RFC7468"] = 202,
	["SYSTEMD_JOURNAL"] = 203,
	["EBHSCR"] = 204,
	["VPP"] = 205,
	["IEEE802_15_4_TAP"] = 206,
	["LOG_3GPP"] = 207,
	["USB_2_0"] = 208
}
wtap = wtap_encaps -- for bw compatibility


-- Wiretap file types
wtap_filetypes = {
	["UNKNOWN"] = 0,
	["PCAP"] = 1,
	["PCAPNG"] = 2,
	["PCAP_NSEC"] = 3,
	["PCAP_AIX"] = 4,
	["PCAP_SS991029"] = 5,
	["PCAP_NOKIA"] = 6,
	["PCAP_SS990417"] = 7,
	["PCAP_SS990915"] = 8,
	["5VIEWS"] = 9,
	["IPTRACE_1_0"] = 10,
	["IPTRACE_2_0"] = 11,
	["BER"] = 12,
	["HCIDUMP"] = 13,
	["CATAPULT_DCT2000"] = 14,
	["NETXRAY_OLD"] = 15,
	["NETXRAY_1_0"] = 16,
	["COSINE"] = 17,
	["CSIDS"] = 18,
	["DBS_ETHERWATCH"] = 19,
	["ERF"] = 20,
	["EYESDN"] = 21,
	["NETTL"] = 22,
	["ISERIES"] = 23,
	["ISERIES_UNICODE"] = 24,
	["I4BTRACE"] = 25,
	["ASCEND"] = 26,
	["NGSNIFFER_UNCOMPRESSED"] = 29,
	["NGSNIFFER_COMPRESSED"] = 30,
	["NETXRAY_1_1"] = 31,
	["NETWORK_INSTRUMENTS"] = 33,
	["LANALYZER"] = 34,
	["PPPDUMP"] = 35,
	["RADCOM"] = 36,
	["SNOOP"] = 37,
	["SHOMITI"] = 38,
	["VMS"] = 39,
	["K12"] = 40,
	["TOSHIBA"] = 41,
	["VISUAL_NETWORKS"] = 42,
	["PEEKCLASSIC_V56"] = 43,
	["PEEKCLASSIC_V7"] = 44,
	["PEEKTAGGED"] = 45,
	["MPEG"] = 46,
	["K12TEXT"] = 47,
	["NETSCREEN"] = 48,
	["COMMVIEW"] = 49,
	["BTSNOOP"] = 50,
	["TNEF"] = 51,
	["DCT3TRACE"] = 52,
	["PACKETLOGGER"] = 53,
	["DAINTREE_SNA"] = 54,
	["NETSCALER_1_0"] = 55,
	["NETSCALER_2_0"] = 56,
	["JPEG_JFIF"] = 57,
	["IPFIX"] = 58,
	["MIME"] = 59,
	["AETHRA"] = 60,
	["MPEG_2_TS"] = 61,
	["VWR_80211"] = 62,
	["VWR_ETH"] = 63,
	["CAMINS"] = 64,
	["STANAG_4607"] = 65,
	["NETSCALER_3_0"] = 66,
	["LOGCAT"] = 67,
	["LOGCAT_BRIEF"] = 68,
	["LOGCAT_PROCESS"] = 69,
	["LOGCAT_TAG"] = 70,
	["LOGCAT_THREAD"] = 71,
	["LOGCAT_TIME"] = 72,
	["LOGCAT_THREADTIME"] = 73,
	["LOGCAT_LONG"] = 74,
	["COLASOFT_CAPSA"] = 75,
	["COLASOFT_PACKET_BUILDER"] = 76,
	["JSON"] = 77,
	["NETSCALER_3_5"] = 78,
	["NETTRACE_3GPP_32_423"] = 79,
	["MPLOG"] = 80,
	["DPA400"] = 81,
	["RFC7468"] = 82,
	["RUBY_MARSHAL"] = 83,
	["SYSTEMD_JOURNAL"] = 84,
	["LOG_3GPP"] = 85,
	["TSPREC_SEC"] = 0,
	["TSPREC_DSEC"] = 1,
	["TSPREC_CSEC"] = 2,
	["TSPREC_MSEC"] = 3,
	["TSPREC_USEC"] = 6,
	["TSPREC_NSEC"] = 9
}


-- Wiretap timestamp precision types
wtap_tsprecs = {
	["SEC"] = 0,
	["DSEC"] = 1,
	["CSEC"] = 2,
	["MSEC"] = 3,
	["USEC"] = 6,
	["NSEC"] = 9
}


-- Wiretap file comment types
wtap_comments = {
	["PER_SECTION"] = 0x00000001,
	["PER_INTERFACE"] = 0x00000002,
	["PER_PACKET"] = 0x00000004
}


-- Field Types
ftypes = {
	["NONE"] = 0,
	["PROTOCOL"] = 1,
	["BOOLEAN"] = 2,
	["CHAR"] = 3,
	["UINT8"] = 4,
	["UINT16"] = 5,
	["UINT24"] = 6,
	["UINT32"] = 7,
	["UINT40"] = 8,
	["UINT48"] = 9,
	["UINT56"] = 10,
	["UINT64"] = 11,
	["INT8"] = 12,
	["INT16"] = 13,
	["INT24"] = 14,
	["INT32"] = 15,
	["INT40"] = 16,
	["INT48"] = 17,
	["INT56"] = 18,
	["INT64"] = 19,
	["IEEE_11073_SFLOAT"] = 20,
	["IEEE_11073_FLOAT"] = 21,
	["FLOAT"] = 22,
	["DOUBLE"] = 23,
	["ABSOLUTE_TIME"] = 24,
	["RELATIVE_TIME"] = 25,
	["STRING"] = 26,
	["STRINGZ"] = 27,
	["UINT_STRING"] = 28,
	["ETHER"] = 29,
	["BYTES"] = 30,
	["UINT_BYTES"] = 31,
	["IPv4"] = 32,
	["IPv6"] = 33,
	["IPXNET"] = 34,
	["FRAMENUM"] = 35,
	["PCRE"] = 36,
	["GUID"] = 37,
	["OID"] = 38,
	["EUI64"] = 39,
	["AX25"] = 40,
	["VINES"] = 41,
	["REL_OID"] = 42,
	["SYSTEM_ID"] = 43,
	["STRINGZPAD"] = 44,
	["FCWWN"] = 45
}


-- the following table is since 2.0
-- Field Type FRAMENUM Types
frametype = {
	["NONE"] = 0,
	["REQUEST"] = 1,
	["RESPONSE"] = 2,
	["ACK"] = 3,
	["DUP_ACK"] = 4,
	["RETRANS_PREV"] = 5,
	["RETRANS_NEXT"] = 6
}


-- the following table is since 1.12
-- Wiretap record_types
wtap_rec_types = {
	["PACKET"] = 0,  -- packet 
	["FT_SPECIFIC_EVENT"] = 1,  -- file-type-specific event 
	["FT_SPECIFIC_REPORT"] = 2,  -- file-type-specific report 
	["SYSCALL"] = 3,  -- system call 
}


-- the following table is since 1.11.3
-- Wiretap presence flags
wtap_presence_flags = {
	["TS"] = 1,  -- time stamp 
	["CAP_LEN"] = 2,  -- captured length separate from on-the-network length 
	["INTERFACE_ID"] = 4,  -- interface ID 
	["COMMENTS"] = 8,  -- comments 
	["DROP_COUNT"] = 16,  -- drop count 
	["PACK_FLAGS"] = 32,  -- packet flags 
}


-- Display Bases
base = {
	["NONE"] = 0,  -- none
	["DEC"] = 1,  -- decimal
	["HEX"] = 2,  -- hexadecimal
	["OCT"] = 3,  -- octal
	["DEC_HEX"] = 4,  -- decimal (hexadecimal)
	["HEX_DEC"] = 5,  -- hexadecimal (decimal)
	["CUSTOM"] = 6,  -- call custom routine (in ->strings) to format
	["ASCII"] = 0,  -- shows non-printable ASCII characters as C-style escapes
	["UNICODE"] = 7,  -- shows non-printable UNICODE characters as \\uXXXX (XXX for now non-printable characters display depends on UI)
	["DOT"] = 8,  -- hexadecimal bytes with a period (.) between each byte
	["DASH"] = 9,  -- hexadecimal bytes with a dash (-) between each byte
	["COLON"] = 10,  -- hexadecimal bytes with a colon (:) between each byte
	["SPACE"] = 11,  -- hexadecimal bytes with a space between each byte
	["NETMASK"] = 12,  -- Used for IPv4 address that shouldn't be resolved (like for netmasks)
	["PT_UDP"] = 13,  -- UDP port
	["PT_TCP"] = 14,  -- TCP port
	["PT_DCCP"] = 15,  -- DCCP port
	["PT_SCTP"] = 16,  -- SCTP port
	["OUI"] = 17,  -- OUI resolution
	["RANGE_STRING"] = 256,  -- Use the supplied range string to convert the field to text
	["UNIT_STRING"] = 4096,  -- Add unit text to the field value
	["LOCAL"] = 1000,  -- local time in our time zone, with month and day
	["UTC"] = 1001,  -- UTC, with month and day
	["DOY_UTC"] = 1002,  -- UTC, with 1-origin day-of-year
	["NTP_UTC"] = 1003,  -- UTC, with "NULL" when timestamp is all zeros
}


-- Encodings
ENC_BIG_ENDIAN = 0
ENC_LITTLE_ENDIAN = 2147483648
ENC_TIME_SECS_NSECS = 0
ENC_TIME_TIMESPEC = 0
ENC_TIME_NTP = 2
ENC_TIME_TOD = 4
ENC_TIME_RTPS = 8
ENC_TIME_NTP_BASE_ZERO = 8
ENC_TIME_SECS_USECS = 16
ENC_TIME_TIMEVAL = 16
ENC_TIME_SECS = 18
ENC_TIME_MSECS = 20
ENC_TIME_SECS_NTP = 24
ENC_TIME_RFC_3971 = 32
ENC_TIME_MSEC_NTP = 34
ENC_TIME_MIP6 = 36
ENC_ZIGBEE = 1073741824
ENC_CHARENCODING_MASK = 1073741822
ENC_ASCII = 0
ENC_ISO_646_IRV = 14
ENC_UTF_8 = 2
ENC_UTF_16 = 4
ENC_UCS_2 = 6
ENC_UCS_4 = 8
ENC_ISO_8859_1 = 10
ENC_ISO_8859_2 = 12
ENC_ISO_8859_3 = 14
ENC_ISO_8859_4 = 16
ENC_ISO_8859_5 = 18
ENC_ISO_8859_6 = 20
ENC_ISO_8859_7 = 22
ENC_ISO_8859_8 = 24
ENC_ISO_8859_9 = 26
ENC_ISO_8859_10 = 28
ENC_ISO_8859_11 = 30
ENC_ISO_8859_13 = 34
ENC_ISO_8859_14 = 36
ENC_ISO_8859_15 = 38
ENC_ISO_8859_16 = 40
ENC_WINDOWS_1250 = 42
ENC_3GPP_TS_23_038_7BITS = 44
ENC_EBCDIC = 46
ENC_MAC_ROMAN = 48
ENC_CP437 = 50
ENC_ASCII_7BITS = 52
ENC_T61 = 54
ENC_EBCDIC_CP037 = 56
ENC_WINDOWS_1252 = 58
ENC_WINDOWS_1251 = 60
ENC_CP855 = 62
ENC_CP866 = 64
ENC_ISO_646_BASIC = 66
ENC_NA = 0
ENC_STR_NUM = 16777216
ENC_STR_HEX = 33554432
ENC_STRING = 50331648
ENC_STR_MASK = 65534
ENC_NUM_PREF = 2097152
ENC_VARINT_PROTOBUF = 2
ENC_VARINT_QUIC = 4
ENC_VARINT_ZIGZAG = 8
ENC_SEP_NONE = 65536
ENC_SEP_COLON = 131072
ENC_SEP_DASH = 262144
ENC_SEP_DOT = 524288
ENC_SEP_SPACE = 1048576
ENC_SEP_MASK = 2031616
ENC_ISO_8601_DATE = 65536
ENC_ISO_8601_TIME = 131072
ENC_ISO_8601_DATE_TIME = 196608
ENC_RFC_822 = 262144
ENC_RFC_1123 = 524288
ENC_STR_TIME_MASK = 983040



-- Expert flags and facilities (deprecated - see 'expert' table below)
PI_SEVERITY_MASK = 15728640
PI_COMMENT = 1048576
PI_CHAT = 2097152
PI_NOTE = 4194304
PI_WARN = 6291456
PI_ERROR = 8388608
PI_GROUP_MASK = 4278190080
PI_CHECKSUM = 16777216
PI_SEQUENCE = 33554432
PI_RESPONSE_CODE = 50331648
PI_REQUEST_CODE = 67108864
PI_UNDECODED = 83886080
PI_REASSEMBLE = 100663296
PI_MALFORMED = 117440512
PI_DEBUG = 134217728
PI_PROTOCOL = 150994944
PI_SECURITY = 167772160
PI_COMMENTS_GROUP = 184549376
PI_DECRYPTION = 201326592
PI_ASSUMPTION = 218103808
PI_DEPRECATED = 234881024



-- the following table is since 1.11.3
-- Expert flags and facilities
expert = {
	-- Expert event groups
	group = {
		-- The protocol field has a bad checksum, usually uses PI_WARN severity
		["CHECKSUM"] = 16777216,
		-- The protocol field indicates a sequence problem (e.g. TCP window is zero)
		["SEQUENCE"] = 33554432,
		-- The protocol field indicates a bad application response code (e.g. HTTP 404), usually PI_NOTE severity
		["RESPONSE_CODE"] = 50331648,
		-- The protocol field indicates an application request (e.g. File Handle == xxxx), usually PI_CHAT severity
		["REQUEST_CODE"] = 67108864,
		-- The data is undecoded, the protocol dissection is incomplete here, usually PI_WARN severity
		["UNDECODED"] = 83886080,
		-- The protocol field indicates a reassemble (e.g. DCE/RPC defragmentation), usually PI_CHAT severity (or PI_ERROR)
		["REASSEMBLE"] = 100663296,
		-- The packet data is malformed, the dissector has "given up", usually PI_ERROR severity
		["MALFORMED"] = 117440512,
		-- A generic debugging message (shouldn't remain in production code!), usually PI_ERROR severity
		["DEBUG"] = 134217728,
		-- The protocol field violates a protocol specification, usually PI_WARN severity
		["PROTOCOL"] = 150994944,
		-- The protocol field indicates a security problem (e.g. insecure implementation)
		["SECURITY"] = 167772160,
		-- The protocol field indicates a packet comment
		["COMMENTS_GROUP"] = 184549376,
		-- The protocol field indicates a decryption problem
		["DECRYPTION"] = 201326592,
		-- The protocol field has incomplete data, decode based on assumed value
		["ASSUMPTION"] = 218103808,
		-- The protocol field has been deprecated, usually PI_NOTE severity
		["DEPRECATED"] = 234881024,
	},
	-- Expert severity levels
	severity = {
		-- Packet comment
		["COMMENT"] = 1048576,
		-- Usual workflow, e.g. TCP connection establishing
		["CHAT"] = 2097152,
		-- Notable messages, e.g. an application returned an "unusual" error code like HTTP 404
		["NOTE"] = 4194304,
		-- Warning, e.g. application returned an "unusual" error code
		["WARN"] = 6291456,
		-- Serious problems, e.g. a malformed packet
		["ERROR"] = 8388608,
	},
}



-- menu groups for register_menu
MENU_ANALYZE_UNSORTED = 0
MENU_ANALYZE_CONVERSATION = 1
MENU_STAT_UNSORTED = 2
MENU_STAT_GENERIC = 3
MENU_STAT_CONVERSATION = 4
MENU_STAT_ENDPOINT = 5
MENU_STAT_RESPONSE = 6
MENU_STAT_TELEPHONY = 7
MENU_STAT_TELEPHONY_ANSI = 8
MENU_STAT_TELEPHONY_GSM = 9
MENU_STAT_TELEPHONY_LTE = 10
MENU_STAT_TELEPHONY_MTP3 = 11
MENU_STAT_TELEPHONY_SCTP = 12
MENU_TOOLS_UNSORTED = 13


-- the possible values for Pinfo's p2p_dir attribute
P2P_DIR_UNKNOWN = -1
P2P_DIR_SENT    =  0
P2P_DIR_RECV    =  1


-- other useful constants
-- DATA_DIR and USER_DIR have a trailing directory separator.
GUI_ENABLED = gui_enabled()
DATA_DIR = Dir.global_config_path()..package.config:sub(1,1)
USER_DIR = Dir.personal_config_path()..package.config:sub(1,1)

-- deprecated function names
datafile_path = Dir.global_config_path
persconffile_path = Dir.personal_config_path

--[[
if not running_superuser or run_user_scripts_when_superuser then
    dofile(DATA_DIR.."console.lua")
end
]]--
--dofile(DATA_DIR.."dtd_gen.lua")
