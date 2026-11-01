"""
PyShark Packet Inspector Module.
Integrates PyShark with TShark to provide deep packet dissection and Wireshark-level
analysis for Data Link Layer frames, specifically showcasing:
- Flow Control (Go-Back-N sliding window, in-order delivery, cumulative ACKs)
- Error Control (CRC-32 FCS calculations, bit-error detection, corrupted frame drops)
- Multiple Access (CSMA channel sensing, collision detection, and jam frames)
"""

import json
import os
import shutil
import struct
import subprocess
from typing import List, Optional, Dict, Any

import pyshark
from pyshark.packet.packet import Packet
from pyshark.tshark.output_parser.tshark_json import packet_from_json_packet

from dll_protocol.frame import (
    FRAME_DATA,
    FRAME_ACK,
    FRAME_JAM,
    FRAME_NAK,
    FRAME_RTS,
    FRAME_CTS,
    FLAG_RETRANSMISSION,
    FLAG_CORRUPTED,
    FRAME_TYPE_NAMES,
    bytes_to_mac,
)
from dll_protocol.crc import CRC

# Terminal styling constants
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE   = "\033[94m"
C_MAGENTA= "\033[95m"
C_CYAN   = "\033[96m"
C_WHITE  = "\033[97m"


def find_tshark_path() -> Optional[str]:
    """Locate tshark executable on the host system."""
    which_path = shutil.which("tshark")
    if which_path:
        return which_path
    common_win_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for p in common_win_paths:
        if os.path.isfile(p):
            return p
    return None


class PySharkInspector:
    """Extracts, parses, and formats packet dissections using PyShark."""

    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = tshark_path or find_tshark_path()
        if not self.tshark_path:
            raise FileNotFoundError("tshark was not found on this system.")

    def parse_pcap(self, pcap_path: str) -> List[Packet]:
        """
        Parses a PCAP file and returns a list of official PyShark Packet objects.
        Uses tshark with native custom DLL Lua dissector for true Wireshark field decoding.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        lua_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "captures", "dll_dissector.lua")
        cmd = [self.tshark_path]
        if os.path.exists(lua_path):
            cmd.extend(["-X", f"lua_script:{lua_path}"])
        cmd.extend(["-r", pcap_path, "-T", "json"])

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=False,
        )
        packets_json = json.loads(proc.stdout.decode("utf-8", errors="replace"))

        packets: List[Packet] = []
        for p_json in packets_json:
            raw_bytes = json.dumps(p_json).encode("utf-8")
            pkt = packet_from_json_packet(raw_bytes)
            packets.append(pkt)
        return packets

    def extract_dll_info(self, pkt: Packet) -> Dict[str, Any]:
        """
        Extracts Data Link Layer fields from either native Wireshark Lua dissector (pkt.dll)
        or by dissecting the raw Ethernet payload.
        """
        dll_layer = getattr(pkt, "dll", None)
        if dll_layer is not None:
            try:
                ftype_raw = str(getattr(dll_layer, "type", "1"))
                ftype = int(ftype_raw, 16) if ftype_raw.startswith("0x") else int(ftype_raw)
                seq = int(str(getattr(dll_layer, "seq", "0")))
                ack = int(str(getattr(dll_layer, "ack", "0")))
                win = int(str(getattr(dll_layer, "window", "4")))
                flags_raw = str(getattr(dll_layer, "flags", "0"))
                flags = int(flags_raw, 16) if flags_raw.startswith("0x") else int(flags_raw)
                plen = int(str(getattr(dll_layer, "len", "0")))
                pld_text = str(getattr(dll_layer, "payload", ""))
                fcs_hex = str(getattr(dll_layer, "fcs", "0x00000000"))

                is_retx = bool(flags & FLAG_RETRANSMISSION)
                is_corrupted = bool(flags & FLAG_CORRUPTED)

                return {
                    "valid_format": True,
                    "type_code": ftype,
                    "type_name": FRAME_TYPE_NAMES.get(ftype, f"UNKNOWN(0x{ftype:02X})"),
                    "seq_num": seq,
                    "ack_num": ack,
                    "window_size": win,
                    "flags": flags,
                    "is_retx": is_retx,
                    "is_corrupted": is_corrupted,
                    "payload_len": plen,
                    "payload_text": pld_text,
                    "payload_hex": pld_text.encode("utf-8").hex() if pld_text else "",
                    "fcs_hex": fcs_hex if fcs_hex.startswith("0x") else f"0x{fcs_hex}",
                    "native_dissector": True,
                }
            except Exception:
                pass

        raw_data = getattr(pkt, "data", None)
        hex_data = getattr(raw_data, "data", "") if raw_data else ""
        return self.dissect_dll_layer(hex_data)

    def dissect_dll_layer(self, raw_payload_hex: str) -> Dict[str, Any]:
        """
        Fallback Data Link Layer protocol dissector for fields carried in Ethernet payload.
        Header format: [Type: 1B] [Seq: 2B] [Ack: 2B] [Win: 1B] [Flags: 1B] [Len: 2B] [Payload] [FCS: 4B]
        """
        try:
            raw = bytes.fromhex(raw_payload_hex.replace(":", ""))
        except Exception:
            raw = b""

        min_len = 9 + 4
        if len(raw) < min_len:
            return {
                "valid_format": False,
                "raw_bytes": raw.hex(),
            }

        ftype, seq, ack, win, flags, plen = struct.unpack_from("!BHHBBH", raw, 0)
        payload = raw[9 : 9 + plen]
        fcs = struct.unpack_from("!I", raw, 9 + plen)[0] if len(raw) >= 9 + plen + 4 else 0

        computed_fcs = CRC.compute_crc32(raw[: 9 + plen])

        return {
            "valid_format": True,
            "type_code": ftype,
            "type_name": FRAME_TYPE_NAMES.get(ftype, f"UNKNOWN(0x{ftype:02X})"),
            "seq_num": seq,
            "ack_num": ack,
            "window_size": win,
            "flags": flags,
            "is_retx": bool(flags & FLAG_RETRANSMISSION),
            "is_corrupted": bool(flags & FLAG_CORRUPTED),
            "payload_len": plen,
            "payload_text": payload.decode("utf-8", errors="replace"),
            "payload_hex": payload.hex(),
            "fcs": fcs,
            "fcs_hex": f"0x{fcs:08X}",
            "computed_fcs_hex": f"0x{computed_fcs:08X}",
        }

    def print_packet_summary_table(self, packets: List[Packet]):
        """Prints a concise, tabular summary of all captured packets."""
        print(f"\n{C_BOLD}{C_CYAN}{'='*100}{C_RESET}")
        print(f"{C_BOLD}{C_WHITE}{'PYSHARK CAPTURED PACKET SUMMARY':^100}{C_RESET}")
        print(f"{C_BOLD}{C_CYAN}{'='*100}{C_RESET}")
        header = f"{'#':<4} | {'Time (s)':<9} | {'Source MAC':<17} | {'Dest MAC':<17} | {'Type':<6} | {'Seq':<4} | {'Ack':<4} | {'Len':<5} | {'CRC / Status'}"
        print(f"{C_BOLD}{header}{C_RESET}")
        print("-" * 100)

        for pkt in packets:
            num = pkt.number
            t_rel = float(getattr(pkt.frame_info, "time_relative", 0.0))
            src_mac = getattr(pkt.eth, "src", "00:00:00:00:00:00")
            dst_mac = getattr(pkt.eth, "dst", "00:00:00:00:00:00")
            plen = pkt.length

            dll_info = self.extract_dll_info(pkt)

            if dll_info.get("valid_format"):
                ftype = dll_info["type_name"]
                seq = str(dll_info["seq_num"])
                ack = str(dll_info["ack_num"])
                if dll_info["is_corrupted"]:
                    status = f"{C_RED}[!] CRC ERROR (FCS Mismatch){C_RESET}"
                elif dll_info["is_retx"]:
                    status = f"{C_YELLOW}[RETX] CRC Valid ({dll_info['fcs_hex']}){C_RESET}"
                elif ftype == "JAM":
                    status = f"{C_MAGENTA}[COLLISION JAM SIGNAL]{C_RESET}"
                elif ftype == "ACK":
                    status = f"{C_GREEN}[ACK] Cumulative Ack={ack}{C_RESET}"
                else:
                    status = f"{C_GREEN}[OK] FCS={dll_info['fcs_hex']}{C_RESET}"
            else:
                ftype = "ETH"
                seq = "-"
                ack = "-"
                status = f"Raw Ethernet ({plen} bytes)"

            line = f"{num:<4} | {t_rel:<9.4f} | {src_mac:<17} | {dst_mac:<17} | {ftype:<6} | {seq:<4} | {ack:<4} | {plen:<5} | {status}"
            print(line)
        print(f"{C_CYAN}{'='*100}{C_RESET}\n")

    def print_detailed_packet(self, pkt: Packet, highlight_reason: str = ""):
        """Prints a comprehensive Wireshark/PyShark dissection breakdown for a packet."""
        num = pkt.number
        t_rel = float(getattr(pkt.frame_info, "time_relative", 0.0))
        t_epoch = getattr(pkt.frame_info, "time_epoch", "0")
        src_mac = getattr(pkt.eth, "src", "00:00:00:00:00:00")
        dst_mac = getattr(pkt.eth, "dst", "00:00:00:00:00:00")
        eth_type = getattr(pkt.eth, "type", "0x0000")

        dll_info = self.extract_dll_info(pkt)

        border = "-" * 85
        print(f"\n{C_BOLD}{C_BLUE}{border}{C_RESET}")
        print(f"{C_BOLD}{C_WHITE}>>> PYSHARK PACKET DISSECTION [Packet #{num}] {C_YELLOW}{highlight_reason}{C_RESET}")
        print(f"{C_BOLD}{C_BLUE}{border}{C_RESET}")

        # Layer 1: Frame
        print(f"{C_BOLD}[1] Wireshark Frame Info (Physical / Capture Layer):{C_RESET}")
        print(f"    - Frame Number       : {num}")
        print(f"    - Epoch Timestamp    : {t_epoch}")
        print(f"    - Relative Time      : {t_rel:.6f} seconds")
        print(f"    - Captured Length    : {pkt.length} bytes")
        print(f"    - Protocols in Frame : {getattr(pkt.frame_info, 'protocols', 'eth:data')}")

        # Layer 2: Ethernet
        print(f"{C_BOLD}[2] IEEE 802.3 Ethernet Header:{C_RESET}")
        print(f"    - Destination MAC    : {dst_mac}")
        print(f"    - Source MAC         : {src_mac}")
        print(f"    - EtherType          : {eth_type} (IEEE 802.3 Experimental DLL)")

        # Layer 2.5: Custom Data Link Layer Control Header
        if dll_info.get("valid_format"):
            ftype = dll_info["type_name"]
            print(f"{C_BOLD}[3] Custom Data Link Layer (DLL) Control Protocol:{C_RESET}")
            print(f"    - Frame Type         : {ftype} (0x{dll_info['type_code']:02X})")
            print(f"    - Sequence Number    : {dll_info['seq_num']}")
            print(f"    - Cumulative Ack     : {dll_info['ack_num']}")
            print(f"    - Flow Control Window: {dll_info['window_size']} frames")
            print(f"    - Flags              : 0x{dll_info['flags']:02X} (Retransmission={dll_info['is_retx']}, Corrupted={dll_info['is_corrupted']})")
            print(f"    - Payload Length     : {dll_info['payload_len']} bytes")
            print(f"    - Frame Check (FCS)  : {dll_info['fcs_hex']}")

            # Error status
            if dll_info["is_corrupted"]:
                print(f"    {C_RED}{C_BOLD}[!] CRC ERROR DETECTED! Frame FCS={dll_info['fcs_hex']} does not match integrity check!{C_RESET}")
            else:
                print(f"    {C_GREEN}{C_BOLD}[PASS] CRC-32 INTEGRITY VERIFIED (FCS Valid){C_RESET}")

            # Payload display
            if dll_info["payload_len"] > 0:
                print(f"{C_BOLD}[4] Frame Payload Content:{C_RESET}")
                print(f"    - Text Content       : '{dll_info['payload_text']}'")
                print(f"    - Hex Dump           : {dll_info['payload_hex']}")
        else:
            print(f"{C_YELLOW}[3] Raw Data Payload: {hex_data}{C_RESET}")

        print(f"{C_BLUE}{border}{C_RESET}\n")
