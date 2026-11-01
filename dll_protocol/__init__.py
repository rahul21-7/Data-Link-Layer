"""
Data Link Layer Protocol Package.
Provides implementation of Go-Back-N ARQ, CRC-32/16 Error Control,
and CSMA / CSMA-CD Multiple Access mechanisms with PyShark packet inspection.
"""

from dll_protocol.crc import CRC
from dll_protocol.frame import (
    DLLFrame,
    FRAME_DATA,
    FRAME_ACK,
    FRAME_NAK,
    FRAME_JAM,
    FRAME_RTS,
    FRAME_CTS,
    FLAG_NONE,
    FLAG_RETRANSMISSION,
    FLAG_CORRUPTED,
)

__all__ = [
    "CRC",
    "DLLFrame",
    "FRAME_DATA",
    "FRAME_ACK",
    "FRAME_NAK",
    "FRAME_JAM",
    "FRAME_RTS",
    "FRAME_CTS",
    "FLAG_NONE",
    "FLAG_RETRANSMISSION",
    "FLAG_CORRUPTED",
]
