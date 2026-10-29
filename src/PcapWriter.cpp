#include "PcapWriter.h"
#include <chrono>

PcapWriter::PcapWriter() : packet_count(0) {}

PcapWriter::PcapWriter(const std::string& path) : packet_count(0) {
    open(path);
}

PcapWriter::~PcapWriter() {
    close();
}

bool PcapWriter::open(const std::string& path) {
    close();
    filepath = path;
    file.open(filepath, std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        return false;
    }

    PcapGlobalHeader hdr;
    hdr.magic_number  = 0xA1B2C3D4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone      = 0;
    hdr.sigfigs       = 0;
    hdr.snaplen       = 65535;
    hdr.network       = 1; // LINKTYPE_ETHERNET

    file.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    file.flush();
    packet_count = 0;
    return true;
}

void PcapWriter::close() {
    if (file.is_open()) {
        file.flush();
        file.close();
    }
}

bool PcapWriter::write_frame(const DLLFrame& frame, double timestamp) {
    std::vector<uint8_t> raw = frame.serialize();
    return write_raw(raw.data(), raw.size(), timestamp);
}

bool PcapWriter::write_raw(const uint8_t* data, size_t length, double timestamp) {
    if (!file.is_open()) return false;

    uint32_t sec, usec;
    if (timestamp < 0.0) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto micros = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
        sec = static_cast<uint32_t>(micros / 1000000ULL);
        usec = static_cast<uint32_t>(micros % 1000000ULL);
    } else {
        sec = static_cast<uint32_t>(timestamp);
        usec = static_cast<uint32_t>((timestamp - sec) * 1000000.0);
    }

    PcapPacketHeader pkt_hdr;
    pkt_hdr.ts_sec = sec;
    pkt_hdr.ts_usec = usec;
    pkt_hdr.incl_len = static_cast<uint32_t>(length);
    pkt_hdr.orig_len = static_cast<uint32_t>(length);

    file.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
    file.write(reinterpret_cast<const char*>(data), length);
    file.flush();
    packet_count++;
    return true;
}

