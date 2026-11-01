-- Wireshark / TShark Custom Lua Dissector for Data Link Layer Protocol
-- Registers EtherType 0x88B5 (IEEE 802 Local Experimental 1)
-- Enables native Wireshark dissection of DLL header fields and display filters!

local dll_proto = Proto("dll", "Data Link Layer Protocol")

-- Protocol Fields
local f_type    = ProtoField.uint8("dll.type", "Frame Type", base.HEX, {
    [1] = "DATA",
    [2] = "ACK",
    [3] = "NAK",
    [4] = "JAM",
    [5] = "RTS",
    [6] = "CTS"
})
local f_seq     = ProtoField.uint16("dll.seq", "Sequence Number", base.DEC)
local f_ack     = ProtoField.uint16("dll.ack", "Cumulative ACK", base.DEC)
local f_window  = ProtoField.uint8("dll.window", "Advertised Window Size", base.DEC)
local f_flags   = ProtoField.uint8("dll.flags", "Control Flags", base.HEX)
local f_retx    = ProtoField.bool("dll.flags.retx", "Retransmission Flag", 8, nil, 0x01)
local f_corrupt = ProtoField.bool("dll.flags.corrupt", "Corrupted Noise Flag", 8, nil, 0x02)
local f_len     = ProtoField.uint16("dll.len", "Payload Length", base.DEC)
local f_payload = ProtoField.string("dll.payload", "Payload Data")
local f_fcs     = ProtoField.uint32("dll.fcs", "Frame Check Sequence (FCS)", base.HEX)

dll_proto.fields = { f_type, f_seq, f_ack, f_window, f_flags, f_retx, f_corrupt, f_len, f_payload, f_fcs }

-- Dissector Function
function dll_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "DLL"

    local buf_len = buffer:len()
    if buf_len < 9 + 4 then
        return -- Frame too short
    end

    local subtree = tree:add(dll_proto, buffer(), "Data Link Layer (DLL) Custom Protocol")

    local ftype   = buffer(0, 1):uint()
    local seq     = buffer(1, 2):uint()
    local ack     = buffer(3, 2):uint()
    local win     = buffer(5, 1):uint()
    local flags   = buffer(6, 1):uint()
    local plen    = buffer(7, 2):uint()

    subtree:add(f_type, buffer(0, 1))
    subtree:add(f_seq, buffer(1, 2))
    subtree:add(f_ack, buffer(3, 2))
    subtree:add(f_window, buffer(5, 1))
    
    local flag_tree = subtree:add(f_flags, buffer(6, 1))
    flag_tree:add(f_retx, buffer(6, 1))
    flag_tree:add(f_corrupt, buffer(6, 1))

    subtree:add(f_len, buffer(7, 2))

    local type_name = "DATA"
    if ftype == 2 then type_name = "ACK"
    elseif ftype == 4 then type_name = "JAM"
    elseif ftype == 3 then type_name = "NAK" end

    -- Payload
    local offset = 9
    if plen > 0 and buf_len >= offset + plen then
        subtree:add(f_payload, buffer(offset, plen))
        offset = offset + plen
    end

    -- FCS (Last 4 bytes)
    if buf_len >= offset + 4 then
        subtree:add(f_fcs, buffer(offset, 4))
    end

    -- Wireshark Info column formatting
    if ftype == 1 then
        pinfo.cols.info = string.format("[%s] Seq=%d Ack=%d Win=%d", type_name, seq, ack, win)
    elseif ftype == 2 then
        pinfo.cols.info = string.format("[%s] CumulativeAck=%d Win=%d", type_name, ack, win)
    elseif ftype == 4 then
        pinfo.cols.info = "[JAM] Collision Jam Signal (32-bit)"
    else
        pinfo.cols.info = string.format("[%s] Seq=%d Ack=%d", type_name, seq, ack)
    end
end

-- Bind dissector to EtherType 0x88B5
local eth_table = DissectorTable.get("ethertype")
eth_table:add(0x88B5, dll_proto)

