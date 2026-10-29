#ifndef CRC_H
#define CRC_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

// Standard IEEE 802.3 32-bit Ethernet polynomial (reversed):
// x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
constexpr uint32_t CRC32_POLYNOMIAL = 0xEDB88320;

// CRC-16 CCITT polynomial: x^16 + x^12 + x^5 + 1
constexpr uint16_t CRC16_POLYNOMIAL = 0x1021;

class CRC {
private:
    static uint32_t table32[256];
    static bool table_initialized;
    static void init_table();

public:
    // Pure bit-by-bit modulo-2 polynomial division
    static uint32_t compute_crc32_bitwise(const uint8_t* data, size_t length);

    // Fast 256-entry table-driven CRC-32 (standard IEEE 802.3 Ethernet)
    static uint32_t compute_crc32(const uint8_t* data, size_t length);
    static uint32_t compute_crc32(const std::vector<uint8_t>& data);

    // 16-bit CRC-CCITT
    static uint16_t compute_crc16(const uint8_t* data, size_t length);

    // CRC Verification
    static bool verify_crc32(const uint8_t* data, size_t length, uint32_t expected_crc);
    static bool verify_crc32(const std::vector<uint8_t>& data, uint32_t expected_crc);

    // Error Injection
    static std::vector<uint8_t> inject_bit_flip(const std::vector<uint8_t>& data, size_t bit_index);
    static std::vector<uint8_t> inject_burst_error(const std::vector<uint8_t>& data, size_t start_bit, size_t length);

    // Educational modulo-2 step-by-step text trace
    static std::string demonstrate_modulo2_division(const std::string& dividend, const std::string& divisor);
};

#endif // CRC_H

