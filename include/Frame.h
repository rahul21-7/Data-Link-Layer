#ifndef FRAME_H
#define FRAME_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>

#define FRAME_DATA 0x01
#define FRAME_ACK  0x02
#define FRAME_NAK  0x03
#define FRAME_JAM  0x04
#define FRAME_RTS  0x05
#define FRAME_CTS  0x06

#define FLAG_NONE           0x00
#define FLAG_RETRANSMISSION 0x01
#define FLAG_CORRUPTED      0x02
#define FLAG_SYN            0x04
#define FLAG_FIN            0x08

#define ETHERTYPE_DLL_PROTO 0x88B5

#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct DLLHeader {
    uint8_t type;
    uint16_t seq;
    uint16_t ack;
    uint8_t window;
    uint8_t flags;
    uint16_t len;
};

#pragma pack(pop)

class DLLFrame {
public:
    std::string src_mac;
    std::string dst_mac;
    uint8_t frame_type;
    uint16_t seq_num;
    uint16_t ack_num;
    uint8_t window_size;
    uint8_t flags;
    std::vector<uint8_t> payload;
    uint32_t fcs;

    DLLFrame();
    DLLFrame(const std::string& src, const std::string& dst, uint8_t type,
             uint16_t seq, uint16_t ack, uint8_t win = 4, uint8_t flg = FLAG_NONE,
             const std::vector<uint8_t>& pld = {});
    DLLFrame(const std::string& src, const std::string& dst, uint8_t type,
             uint16_t seq, uint16_t ack, uint8_t win, uint8_t flg,
             const std::string& pld_str);

    std::vector<uint8_t> get_crc_subject_bytes() const;
    uint32_t compute_fcs() const;
    bool verify_integrity(uint32_t* computed_out = nullptr) const;

    std::vector<uint8_t> serialize() const;
    static DLLFrame deserialize(const uint8_t* raw, size_t length);
    static DLLFrame deserialize(const std::vector<uint8_t>& raw);

    std::string type_name() const;
    std::string summary() const;
    std::string payload_as_string() const;

    static std::array<uint8_t, 6> mac_to_bytes(const std::string& mac_str);
    static std::string bytes_to_mac(const uint8_t* bytes);
};

#endif // FRAME_H
