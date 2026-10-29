#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <string>
#include <fstream>
#include <cstdint>
#include "Frame.h"

#pragma pack(push, 1)

struct PcapGlobalHeader {
    uint32_t magic_number;  // 0xA1B2C3D4
    uint16_t version_major; // 2
    uint16_t version_minor; // 4
    int32_t  thiszone;      // GMT to local correction
    uint32_t sigfigs;       // accuracy of timestamps
    uint32_t snaplen;       // max length of captured packets (65535)
    uint32_t network;       // data link type (1 = Ethernet)
};

struct PcapPacketHeader {
    uint32_t ts_sec;   // timestamp seconds
    uint32_t ts_usec;  // timestamp microseconds
    uint32_t incl_len; // number of octets of packet saved in file
    uint32_t orig_len; // actual length of packet
};

#pragma pack(pop)

class PcapWriter {
private:
    std::string filepath;
    std::ofstream file;
    size_t packet_count;

public:
    PcapWriter();
    explicit PcapWriter(const std::string& path);
    ~PcapWriter();

    bool open(const std::string& path);
    void close();

    bool write_frame(const DLLFrame& frame, double timestamp = -1.0);
    bool write_raw(const uint8_t* data, size_t length, double timestamp = -1.0);

    size_t get_packet_count() const { return packet_count; }
    const std::string& get_filepath() const { return filepath; }
};

#endif // PCAP_WRITER_H

