#ifndef FRAME_H
#ifndef FRAME_H
#define FRAME_H

#include <cstdint>
#include <vector>
#include <string>

#define FRAME_DATA 0x01
#define FRAME_ACK 0x02

#pragma pack(push, 1)

struct FrameHeader{
    uint8_t type;
    uint16_t seq;
    uint16_t ack;
    uint16_t len;
};

#pragma pack(pop)

uint32_t compute_crc32(const uint8_t *data, size_t length);
std::vector<uint8_t> pack_frame(uint8_t type, uint16_t seq, uint16_t ack, const std::string &payload);
bool unpack_frame(const std::vector<uint8_t> &raw, FrameHeader& hdr, std::string &payload);

#endif