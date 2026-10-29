#include "Crc.h"
#include <sstream>

uint32_t CRC::table32[256];
bool CRC::table_initialized = false;

void CRC::init_table() {
    if (table_initialized) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            if (c & 1) {
                c = (c >> 1) ^ CRC32_POLYNOMIAL;
            } else {
                c >>= 1;
            }
        }
        table32[i] = c;
    }
    table_initialized = true;
}

uint32_t CRC::compute_crc32_bitwise(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];
        for (int bit = 0; bit < 8; ++bit) {
            uint8_t b = (byte >> bit) & 1;
            if ((crc ^ b) & 1) {
                crc = ((crc >> 1) ^ CRC32_POLYNOMIAL) & 0xFFFFFFFF;
            } else {
                crc = (crc >> 1) & 0xFFFFFFFF;
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}

uint32_t CRC::compute_crc32(const uint8_t* data, size_t length) {
    if (!table_initialized) {
        init_table();
    }
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        uint8_t table_idx = static_cast<uint8_t>((crc ^ data[i]) & 0xFF);
        crc = ((crc >> 8) ^ table32[table_idx]) & 0xFFFFFFFF;
    }
    return crc ^ 0xFFFFFFFF;
}

uint32_t CRC::compute_crc32(const std::vector<uint8_t>& data) {
    return compute_crc32(data.data(), data.size());
}

uint16_t CRC::compute_crc16(const uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc ^= (static_cast<uint16_t>(data[i]) << 8);
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x8000) {
                crc = ((crc << 1) ^ CRC16_POLYNOMIAL) & 0xFFFF;
            } else {
                crc = (crc << 1) & 0xFFFF;
            }
        }
    }
    return crc;
}

bool CRC::verify_crc32(const uint8_t* data, size_t length, uint32_t expected_crc) {
    return compute_crc32(data, length) == expected_crc;
}

bool CRC::verify_crc32(const std::vector<uint8_t>& data, uint32_t expected_crc) {
    return verify_crc32(data.data(), data.size(), expected_crc);
}

std::vector<uint8_t> CRC::inject_bit_flip(const std::vector<uint8_t>& data, size_t bit_index) {
    if (data.empty()) return data;
    std::vector<uint8_t> corrupted = data;
    size_t byte_pos = (bit_index / 8) % corrupted.size();
    size_t bit_pos = bit_index % 8;
    corrupted[byte_pos] ^= (1 << bit_pos);
    return corrupted;
}

std::vector<uint8_t> CRC::inject_burst_error(const std::vector<uint8_t>& data, size_t start_bit, size_t length) {
    if (data.empty()) return data;
    std::vector<uint8_t> corrupted = data;
    for (size_t i = 0; i < length; ++i) {
        size_t bit_idx = start_bit + i;
        size_t byte_pos = (bit_idx / 8) % corrupted.size();
        size_t bit_pos = bit_idx % 8;
        corrupted[byte_pos] ^= (1 << bit_pos);
    }
    return corrupted;
}

std::string CRC::demonstrate_modulo2_division(const std::string& dividend, const std::string& divisor) {
    std::stringstream ss;
    std::string cur = dividend;
    size_t poly_len = divisor.length();

    ss << "Initial Dividend: " << cur << "\n";
    ss << "Divisor (Poly)  : " << divisor << "\n";
    ss << "----------------------------------------\n";

    for (size_t i = 0; i + poly_len <= dividend.length(); ++i) {
        if (cur[i] == '1') {
            for (size_t j = 0; j < poly_len; ++j) {
                cur[i + j] = (cur[i + j] == divisor[j]) ? '0' : '1';
            }
            ss << "Step " << (i + 1) << ": XOR with " << divisor << " at bit " << i << "\n";
            ss << "  Current Remainder: " << cur << "\n";
        }
    }
    std::string remainder = cur.substr(dividend.length() - (poly_len - 1));
    ss << "----------------------------------------\n";
    ss << "Final Remainder (CRC bits): " << remainder << "\n";
    return ss.str();
}

