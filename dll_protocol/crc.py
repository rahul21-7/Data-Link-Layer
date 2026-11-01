"""
Cyclic Redundancy Check (CRC) Module
Implemented from first principles without external libraries.
Supports standard CRC-32 (IEEE 802.3 Ethernet) and CRC-16 (CCITT).
Includes both bit-by-bit modulo-2 polynomial division and precomputed table acceleration,
along with bit-level error injection and syndrome verification.
"""

from typing import Tuple, List

# IEEE 802.3 32-bit Ethernet polynomial:
# x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
CRC32_POLYNOMIAL = 0xEDB88320  # Reflected representation
CRC32_NORMAL_POLY = 0x04C11DB7

# CRC-16 CCITT polynomial: x^16 + x^12 + x^5 + 1
CRC16_POLYNOMIAL = 0x1021


class CRC:
    """Cyclic Redundancy Check implementation from first principles."""

    _crc32_table: List[int] = []

    @classmethod
    def _init_crc32_table(cls):
        """Generate the standard 256-entry lookup table from scratch."""
        if cls._crc32_table:
            return
        cls._crc32_table = [0] * 256
        for i in range(256):
            c = i
            for _ in range(8):
                if c & 1:
                    c = (c >> 1) ^ CRC32_POLYNOMIAL
                else:
                    c >>= 1
            cls._crc32_table[i] = c

    @staticmethod
    def compute_crc32_bitwise(data: bytes) -> int:
        """
        Compute CRC-32 using bit-by-bit modulo-2 polynomial division.
        Demonstrates the exact mathematical operation of the shift register.
        """
        crc = 0xFFFFFFFF
        for byte in data:
            for bit in range(8):
                b = (byte >> bit) & 1
                if (crc ^ b) & 1:
                    crc = ((crc >> 1) ^ CRC32_POLYNOMIAL) & 0xFFFFFFFF
                else:
                    crc = (crc >> 1) & 0xFFFFFFFF
        return crc ^ 0xFFFFFFFF

    @classmethod
    def compute_crc32(cls, data: bytes) -> int:
        """
        Fast CRC-32 computation using the precomputed 256-entry table.
        Mathematically identical to compute_crc32_bitwise.
        """
        if not cls._crc32_table:
            cls._init_crc32_table()
        crc = 0xFFFFFFFF
        for byte in data:
            table_idx = (crc ^ byte) & 0xFF
            crc = ((crc >> 8) ^ cls._crc32_table[table_idx]) & 0xFFFFFFFF
        return crc ^ 0xFFFFFFFF

    @staticmethod
    def compute_crc16(data: bytes) -> int:
        """Compute 16-bit CRC-CCITT (polynomial 0x1021)."""
        crc = 0xFFFF
        for byte in data:
            crc ^= (byte << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ CRC16_POLYNOMIAL) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    @classmethod
    def verify_crc32(cls, data: bytes, expected_crc: int) -> Tuple[bool, int, int]:
        """
        Verify the CRC of data against the expected CRC.
        Returns: (is_valid, computed_crc, expected_crc)
        """
        computed = cls.compute_crc32(data)
        return (computed == expected_crc, computed, expected_crc)

    @staticmethod
    def inject_bit_flip(data: bytes, bit_index: int = 0) -> bytes:
        """
        Simulate transmission noise by flipping a single bit at bit_index.
        """
        byte_arr = bytearray(data)
        if not byte_arr:
            return data
        byte_pos = (bit_index // 8) % len(byte_arr)
        bit_pos = bit_index % 8
        byte_arr[byte_pos] ^= (1 << bit_pos)
        return bytes(byte_arr)

    @staticmethod
    def inject_burst_error(data: bytes, start_bit: int = 0, length: int = 5) -> bytes:
        """
        Simulate an electrical burst error flipping a sequence of bits.
        """
        byte_arr = bytearray(data)
        if not byte_arr:
            return data
        for offset in range(length):
            idx = start_bit + offset
            byte_pos = (idx // 8) % len(byte_arr)
            bit_pos = idx % 8
            byte_arr[byte_pos] ^= (1 << bit_pos)
        return bytes(byte_arr)

    @staticmethod
    def demonstrate_modulo2_division(dividend_bits: str, divisor_bits: str) -> str:
        """
        Detailed text trace of modulo-2 division for educational demonstration.
        """
        steps = []
        cur = list(dividend_bits)
        divisor = list(divisor_bits)
        poly_len = len(divisor)
        steps.append(f"Initial Dividend: {''.join(cur)}")
        steps.append(f"Divisor (Poly)  : {''.join(divisor)}")
        steps.append("-" * 40)

        for i in range(len(dividend_bits) - poly_len + 1):
            if cur[i] == '1':
                sub_step = [" "] * i
                for j in range(poly_len):
                    cur[i + j] = '1' if cur[i + j] != divisor[j] else '0'
                    sub_step.append(divisor[j])
                steps.append(f"Step {i+1}: XOR with {divisor_bits} at bit {i}")
                steps.append(f"  Current remainder: {''.join(cur)}")
        remainder = ''.join(cur[-(poly_len - 1):])
        steps.append("-" * 40)
        steps.append(f"Final Remainder (CRC bits): {remainder}")
        return "\n".join(steps)


# Initialize table on module import
CRC._init_crc32_table()
