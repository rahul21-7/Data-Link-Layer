"""
PCAP Binary Writer Module.
Generates standard libpcap capture files compatible with Wireshark, TShark, and PyShark.
Allows raw Data Link Layer frames to be captured with microsecond resolution timestamps.
"""

import os
import struct
import time
from typing import Optional, List
from dll_protocol.frame import DLLFrame


class PCAPWriter:
    """Writes Ethernet/DLL frames to standard Libpcap .pcap files."""

    PCAP_GLOBAL_HDR_FMT = "<IHHiIII"
    PCAP_PACKET_HDR_FMT = "<IIII"

    MAGIC_NUMBER = 0xA1B2C3D4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    LINKTYPE_ETHERNET = 1  # Standard Ethernet (10Mb, 100Mb, 1000Mb, and up)
    MAX_SNAPLEN = 65535

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = None
        self.packet_count = 0
        self._ensure_dir()
        self.open()

    def _ensure_dir(self):
        dir_name = os.path.dirname(self.filepath)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

    def open(self):
        """Open file and write standard 24-byte libpcap global header."""
        self._file = open(self.filepath, "wb")
        global_hdr = struct.pack(
            self.PCAP_GLOBAL_HDR_FMT,
            self.MAGIC_NUMBER,
            self.VERSION_MAJOR,
            self.VERSION_MINOR,
            0,  # GMT to local correction
            0,  # Accuracy of timestamps
            self.MAX_SNAPLEN,
            self.LINKTYPE_ETHERNET,
        )
        self._file.write(global_hdr)
        self._file.flush()

    def write_frame(self, frame: DLLFrame, timestamp: Optional[float] = None):
        """Write a DLLFrame instance into the PCAP file."""
        raw_bytes = frame.serialize()
        self.write_raw(raw_bytes, timestamp)

    def write_raw(self, raw_bytes: bytes, timestamp: Optional[float] = None):
        """Write raw Ethernet frame bytes with timestamp."""
        if self._file is None or self._file.closed:
            raise IOError("PCAP writer is closed.")

        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        pkt_len = len(raw_bytes)

        packet_hdr = struct.pack(
            self.PCAP_PACKET_HDR_FMT,
            ts_sec,
            ts_usec,
            pkt_len,
            pkt_len,
        )
        self._file.write(packet_hdr + raw_bytes)
        self._file.flush()
        self.packet_count += 1

    def close(self):
        """Flush and close the PCAP file."""
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
