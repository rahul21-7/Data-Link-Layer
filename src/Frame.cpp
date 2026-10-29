#include "Frame.h"
#include "Crc.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

DLLFrame::DLLFrame()
    : src_mac("00:00:00:00:00:00"),
      dst_mac("00:00:00:00:00:00"),
      frame_type(FRAME_DATA),
      seq_num(0),
      ack_num(0),
      window_size(4),
      flags(FLAG_NONE),
      fcs(0) {}

DLLFrame::DLLFrame(const std::string& src, const std::string& dst, uint8_t type,
                   uint16_t seq, uint16_t ack, uint8_t win, uint8_t flg,
                   const std::vector<uint8_t>& pld)
    : src_mac(src), dst_mac(dst), frame_type(type), seq_num(seq), ack_num(ack),
      window_size(win), flags(flg), payload(pld) {
    fcs = compute_fcs();
}

DLLFrame::DLLFrame(const std::string& src, const std::string& dst, uint8_t type,
                   uint16_t seq, uint16_t ack, uint8_t win, uint8_t flg,
                   const std::string& pld_str)
    : src_mac(src), dst_mac(dst), frame_type(type), seq_num(seq), ack_num(ack),
      window_size(win), flags(flg),
      payload(pld_str.begin(), pld_str.end()) {
    fcs = compute_fcs();
}

std::array<uint8_t, 6> DLLFrame::mac_to_bytes(const std::string& mac_str) {
    std::array<uint8_t, 6> bytes = {0};
    std::stringstream ss(mac_str);
    std::string item;
    int idx = 0;
    while (std::getline(ss, item, ':') && idx < 6) {
        bytes[idx++] = static_cast<uint8_t>(std::stoul(item, nullptr, 16));
    }
    return bytes;
}

std::string DLLFrame::bytes_to_mac(const uint8_t* bytes) {
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::vector<uint8_t> DLLFrame::get_crc_subject_bytes() const {
    std::vector<uint8_t> buffer;
    buffer.reserve(sizeof(EthernetHeader) + sizeof(DLLHeader) + payload.size());

    EthernetHeader eth;
    auto dst_b = mac_to_bytes(dst_mac);
    auto src_b = mac_to_bytes(src_mac);
    std::memcpy(eth.dst_mac, dst_b.data(), 6);
    std::memcpy(eth.src_mac, src_b.data(), 6);
    eth.ethertype = htons(ETHERTYPE_DLL_PROTO);

    DLLHeader dll;
    dll.type = frame_type;
    dll.seq = htons(seq_num);
    dll.ack = htons(ack_num);
    dll.window = window_size;
    dll.flags = flags;
    dll.len = htons(static_cast<uint16_t>(payload.size()));

    const uint8_t* eth_ptr = reinterpret_cast<const uint8_t*>(&eth);
    buffer.insert(buffer.end(), eth_ptr, eth_ptr + sizeof(EthernetHeader));

    const uint8_t* dll_ptr = reinterpret_cast<const uint8_t*>(&dll);
    buffer.insert(buffer.end(), dll_ptr, dll_ptr + sizeof(DLLHeader));

    buffer.insert(buffer.end(), payload.begin(), payload.end());
    return buffer;
}

uint32_t DLLFrame::compute_fcs() const {
    std::vector<uint8_t> subject = get_crc_subject_bytes();
    return CRC::compute_crc32(subject);
}

bool DLLFrame::verify_integrity(uint32_t* computed_out) const {
    uint32_t computed = compute_fcs();
    if (computed_out) *computed_out = computed;
    return computed == fcs;
}

std::vector<uint8_t> DLLFrame::serialize() const {
    std::vector<uint8_t> raw = get_crc_subject_bytes();
    uint32_t fcs_be = htonl(fcs);
    const uint8_t* fcs_ptr = reinterpret_cast<const uint8_t*>(&fcs_be);
    raw.insert(raw.end(), fcs_ptr, fcs_ptr + 4);
    return raw;
}

DLLFrame DLLFrame::deserialize(const uint8_t* raw, size_t length) {
    size_t min_len = sizeof(EthernetHeader) + sizeof(DLLHeader) + 4;
    if (length < min_len) {
        throw std::runtime_error("Serialized frame length is too short.");
    }

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(raw);
    const DLLHeader* dll = reinterpret_cast<const DLLHeader*>(raw + sizeof(EthernetHeader));

    std::string dst = bytes_to_mac(eth->dst_mac);
    std::string src = bytes_to_mac(eth->src_mac);

    uint8_t ftype = dll->type;
    uint16_t seq = ntohs(dll->seq);
    uint16_t ack = ntohs(dll->ack);
    uint8_t win = dll->window;
    uint8_t flg = dll->flags;
    uint16_t plen = ntohs(dll->len);

    size_t payload_offset = sizeof(EthernetHeader) + sizeof(DLLHeader);
    if (payload_offset + plen + 4 > length) {
        throw std::runtime_error("Payload length exceeds frame boundary.");
    }

    std::vector<uint8_t> pld(raw + payload_offset, raw + payload_offset + plen);

    uint32_t fcs_raw = *reinterpret_cast<const uint32_t*>(raw + payload_offset + plen);
    uint32_t fcs_val = ntohl(fcs_raw);

    DLLFrame frame(src, dst, ftype, seq, ack, win, flg, pld);
    frame.fcs = fcs_val;
    return frame;
}

DLLFrame DLLFrame::deserialize(const std::vector<uint8_t>& raw) {
    return deserialize(raw.data(), raw.size());
}

std::string DLLFrame::type_name() const {
    switch (frame_type) {
        case FRAME_DATA: return "DATA";
        case FRAME_ACK:  return "ACK";
        case FRAME_NAK:  return "NAK";
        case FRAME_JAM:  return "JAM";
        case FRAME_RTS:  return "RTS";
        case FRAME_CTS:  return "CTS";
        default:         return "UNKNOWN";
    }
}

std::string DLLFrame::payload_as_string() const {
    return std::string(payload.begin(), payload.end());
}

std::string DLLFrame::summary() const {
    std::stringstream ss;
    std::string flag_info = "";
    if (flags & FLAG_RETRANSMISSION) flag_info += "[RETX] ";
    if (flags & FLAG_CORRUPTED)      flag_info += "[CORRUPTED] ";

    if (frame_type == FRAME_DATA) {
        ss << "[" << type_name() << "] Seq=" << std::setw(2) << std::setfill('0') << seq_num
           << " Ack=" << std::setw(2) << std::setfill('0') << ack_num
           << " Win=" << static_cast<int>(window_size) << " " << flag_info
           << "FCS=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << fcs
           << " Payload='" << payload_as_string() << "'";
    } else if (frame_type == FRAME_ACK) {
        ss << "[" << type_name() << "] CumulativeAck=" << std::setw(2) << std::setfill('0') << ack_num
           << " AdvertisedWin=" << static_cast<int>(window_size) << " " << flag_info
           << "FCS=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << fcs;
    } else if (frame_type == FRAME_JAM) {
        ss << "[" << type_name() << "] Collision Jam Signal (32-bit pattern) from " << src_mac;
    } else {
        ss << "[" << type_name() << "] Seq=" << seq_num << " Ack=" << ack_num
           << " " << flag_info << "FCS=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << fcs;
    }
    return ss.str();
}

