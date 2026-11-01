"""
Data Link Layer Frame Definition and Bit-Packing Specification.
Encapsulates MAC addressing, frame types (DATA, ACK, JAM, RTS, CTS),
sequence/ack numbers, flow control window size, payload, and CRC-32 FCS.
"""

import struct
from typing import Optional, Tuple
from dll_protocol.crc import CRC

# Frame Types
FRAME_DATA = 0x01
FRAME_ACK  = 0x02
FRAME_NAK  = 0x03
FRAME_JAM  = 0x04
FRAME_RTS  = 0x05
FRAME_CTS  = 0x06

FRAME_TYPE_NAMES = {
    FRAME_DATA: "DATA",
    FRAME_ACK:  "ACK",
    FRAME_NAK:  "NAK",
    FRAME_JAM:  "JAM",
    FRAME_RTS:  "RTS",
    FRAME_CTS:  "CTS",
}

# Control Flags
FLAG_NONE           = 0x00
FLAG_RETRANSMISSION = 0x01
FLAG_CORRUPTED      = 0x02
FLAG_SYN            = 0x04
FLAG_FIN            = 0x08

ETHERTYPE_DLL_PROTO = 0x88B5  # IEEE 802 Local Experimental Protocol 1


def mac_to_bytes(mac_str: str) -> bytes:
    """Convert '00:11:22:33:44:55' to 6 bytes."""
    parts = mac_str.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address format: {mac_str}")
    return bytes(int(p, 16) for p in parts)


def bytes_to_mac(b: bytes) -> str:
    """Convert 6 bytes to '00:11:22:33:44:55'."""
    return ":".join(f"{x:02x}" for x in b[:6])


class DLLFrame:
    """
    Data Link Layer Frame Structure:
    [Src MAC (6B)] [Dst MAC (6B)] [EtherType (2B)]
    [Frame Type (1B)] [Seq Num (2B)] [Ack Num (2B)] [Window (1B)] [Flags (1B)] [Len (2B)]
    [Payload (Len bytes)]
    [FCS / CRC32 (4B)]
    """

    # Format of Ethernet Header: Dst MAC (6s), Src MAC (6s), EtherType (H)
    ETH_HDR_FMT = "!6s6sH"
    ETH_HDR_LEN = struct.calcsize(ETH_HDR_FMT)  # 14 bytes

    # Format of DLL Control Header: Type (B), Seq (H), Ack (H), Window (B), Flags (B), Len (H)
    DLL_HDR_FMT = "!BHHBBH"
    DLL_HDR_LEN = struct.calcsize(DLL_HDR_FMT)  # 9 bytes

    def __init__(
        self,
        src_mac: str = "00:11:22:33:44:55",
        dst_mac: str = "00:11:22:33:44:66",
        frame_type: int = FRAME_DATA,
        seq_num: int = 0,
        ack_num: int = 0,
        window_size: int = 4,
        flags: int = FLAG_NONE,
        payload: bytes = b"",
        fcs: Optional[int] = None,
    ):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.frame_type = frame_type
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.window_size = window_size
        self.flags = flags
        self.payload = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        self.fcs = fcs if fcs is not None else self.compute_fcs()

    @property
    def type_name(self) -> str:
        return FRAME_TYPE_NAMES.get(self.frame_type, f"UNKNOWN(0x{self.frame_type:02X})")

    def _get_crc_subject_bytes(self) -> bytes:
        """Returns the bytes over which CRC is calculated (Ethernet + DLL Header + Payload)."""
        eth_hdr = struct.pack(
            self.ETH_HDR_FMT,
            mac_to_bytes(self.dst_mac),
            mac_to_bytes(self.src_mac),
            ETHERTYPE_DLL_PROTO,
        )
        dll_hdr = struct.pack(
            self.DLL_HDR_FMT,
            self.frame_type,
            self.seq_num,
            self.ack_num,
            self.window_size,
            self.flags,
            len(self.payload),
        )
        return eth_hdr + dll_hdr + self.payload

    def compute_fcs(self) -> int:
        """Compute CRC-32 over header and payload."""
        return CRC.compute_crc32(self._get_crc_subject_bytes())

    def serialize(self) -> bytes:
        """Serialize frame to binary byte stream including 32-bit FCS."""
        body = self._get_crc_subject_bytes()
        fcs_bytes = struct.pack("!I", self.fcs)
        return body + fcs_bytes

    @classmethod
    def deserialize(cls, raw: bytes) -> "DLLFrame":
        """Deserialize raw byte stream into a DLLFrame object."""
        min_len = cls.ETH_HDR_LEN + cls.DLL_HDR_LEN + 4
        if len(raw) < min_len:
            raise ValueError(f"Frame length {len(raw)} is shorter than minimum {min_len} bytes")

        dst_mac_bytes, src_mac_bytes, eth_type = struct.unpack_from(cls.ETH_HDR_FMT, raw, 0)
        offset = cls.ETH_HDR_LEN

        ftype, seq, ack, win, flags, plen = struct.unpack_from(cls.DLL_HDR_FMT, raw, offset)
        offset += cls.DLL_HDR_LEN

        payload = raw[offset : offset + plen]
        offset += plen

        fcs = struct.unpack_from("!I", raw, offset)[0]

        frame = cls(
            src_mac=bytes_to_mac(src_mac_bytes),
            dst_mac=bytes_to_mac(dst_mac_bytes),
            frame_type=ftype,
            seq_num=seq,
            ack_num=ack,
            window_size=win,
            flags=flags,
            payload=payload,
            fcs=fcs,
        )
        return frame

    def verify_integrity(self) -> Tuple[bool, int, int]:
        """
        Verify frame integrity against its own FCS.
        Returns: (is_valid, computed_fcs, frame_fcs)
        """
        computed = self.compute_fcs()
        return (computed == self.fcs, computed, self.fcs)

    def to_dict(self) -> dict:
        is_valid, comp, exp = self.verify_integrity()
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "type": self.type_name,
            "seq_num": self.seq_num,
            "ack_num": self.ack_num,
            "window_size": self.window_size,
            "flags": f"0x{self.flags:02X}",
            "payload_len": len(self.payload),
            "payload_text": self.payload.decode("utf-8", errors="replace"),
            "fcs": f"0x{self.fcs:08X}",
            "fcs_valid": is_valid,
        }

    def summary(self) -> str:
        flags_str = ""
        if self.flags & FLAG_RETRANSMISSION:
            flags_str += "[RETX] "
        if self.flags & FLAG_CORRUPTED:
            flags_str += "[CORRUPTED] "

        if self.frame_type == FRAME_DATA:
            return (
                f"[{self.type_name}] Seq={self.seq_num:02d} Ack={self.ack_num:02d} "
                f"Win={self.window_size} {flags_str}FCS=0x{self.fcs:08X} "
                f"Payload='{self.payload.decode('utf-8', errors='replace')}'"
            )
        elif self.frame_type == FRAME_ACK:
            return (
                f"[{self.type_name}] CumulativeAck={self.ack_num:02d} "
                f"AdvertisedWin={self.window_size} {flags_str}FCS=0x{self.fcs:08X}"
            )
        elif self.frame_type == FRAME_JAM:
            return f"[{self.type_name}] Collision Jam Signal (32-bit pattern) from {self.src_mac}"
        else:
            return (
                f"[{self.type_name}] Seq={self.seq_num} Ack={self.ack_num} "
                f"{flags_str}FCS=0x{self.fcs:08X}"
            )

    def __repr__(self) -> str:
        return f"<DLLFrame {self.summary()}>"
