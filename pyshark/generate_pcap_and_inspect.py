"""
PyShark Packet Dissection and Verification Script.
Parses the captured Data Link Layer PCAP file using PyShark,
extracting deep layer details, Wireshark expert analysis, and validating:
1. Error Control (CRC-32 FCS calculations and error detection)
2. Flow Control (Go-Back-N sliding window, in-order delivery, cumulative ACKs)
3. Multiple Access (CSMA carrier sensing, collisions, and jam signals)
"""

import os
import sys

# Ensure root directory is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dll_protocol.frame import (
    DLLFrame,
    FRAME_DATA,
    FRAME_ACK,
    FRAME_JAM,
    FRAME_NAK,
    FLAG_NONE,
    FLAG_RETRANSMISSION,
    FLAG_CORRUPTED,
)
from dll_protocol.pcap_writer import PCAPWriter
from dll_protocol.pyshark_inspector import (
    PySharkInspector,
    C_BOLD,
    C_RESET,
    C_GREEN,
    C_RED,
    C_YELLOW,
    C_BLUE,
    C_CYAN,
    C_MAGENTA,
    C_WHITE,
)


def generate_dll_pcap(pcap_path: str):
    """Generates standard PCAP file matching the C++ Data Link Layer simulation."""
    os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
    writer = PCAPWriter(pcap_path)

    # -------------------------------------------------------------
    # FEATURE 1: ERROR CONTROL (CRC-32 & CORRUPTED FRAMES)
    # -------------------------------------------------------------
    # 1. Clean Frame
    f1 = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 1, 0, 4, FLAG_NONE, "Hello CRC Clean Data")
    writer.write_frame(f1, 1.000)

    # 2. Single-Bit Corrupted Frame (FCS Mismatch)
    f2 = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 1, 0, 4, FLAG_CORRUPTED, "Hello CRC Clean Data")
    f2.fcs ^= 0x00000001 # bit flip in FCS
    writer.write_frame(f2, 1.005)

    # 3. Burst Error Corrupted Frame
    f3 = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 1, 0, 4, FLAG_CORRUPTED, "Hello CRC Burst Noise")
    f3.fcs ^= 0x00000FFF # 12-bit burst inversion
    writer.write_frame(f3, 1.010)

    # -------------------------------------------------------------
    # FEATURE 2: FLOW CONTROL (GO-BACK-N SLIDING WINDOW)
    # -------------------------------------------------------------
    # Window of 4 frames: Seq 0, 1, 2, 3
    for i in range(4):
        f = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, i, 0, 4, FLAG_NONE, f"PacketPayload_#{i}")
        writer.write_frame(f, 2.000 + i * 0.01)

    # Receiver sends cumulative ACK for 0 and 1
    ack0 = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, 0, 4, FLAG_NONE, "")
    writer.write_frame(ack0, 2.050)
    ack1 = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, 1, 4, FLAG_NONE, "")
    writer.write_frame(ack1, 2.070)

    # Packet 2 corrupted on channel
    pkt2_corrupt = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 2, 0, 4, FLAG_CORRUPTED, "PacketPayload_#2")
    pkt2_corrupt.fcs ^= 0xDEADBEEF
    writer.write_frame(pkt2_corrupt, 2.100)

    # Packet 3 arrives out of order
    pkt3 = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 3, 0, 4, FLAG_NONE, "PacketPayload_#3")
    writer.write_frame(pkt3, 2.120)

    # Receiver repeats ACK=1 (Out of Order rejection)
    dup_ack1 = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, 1, 4, FLAG_NONE, "")
    writer.write_frame(dup_ack1, 2.140)

    # GBN Retransmission Cascade (Go Back to 2: Retransmit 2 and 3)
    retx2 = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 2, 0, 4, FLAG_RETRANSMISSION, "PacketPayload_#2")
    writer.write_frame(retx2, 3.500)
    retx3 = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 3, 0, 4, FLAG_RETRANSMISSION, "PacketPayload_#3")
    writer.write_frame(retx3, 3.510)

    # Receiver delivers in order and acknowledges
    ack2 = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, 2, 4, FLAG_NONE, "")
    writer.write_frame(ack2, 3.530)
    ack3 = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, 3, 4, FLAG_NONE, "")
    writer.write_frame(ack3, 3.550)

    # -------------------------------------------------------------
    # FEATURE 3: MULTIPLE ACCESS (CSMA & CSMA/CD JAMMING)
    # -------------------------------------------------------------
    # Node A transmits successfully
    csma_a = DLLFrame("00:11:22:33:44:0A", "00:11:22:33:44:02", FRAME_DATA, 10, 0, 4, FLAG_NONE, "Data from Node A")
    writer.write_frame(csma_a, 5.000)

    # Node B and C collide
    csma_b = DLLFrame("00:11:22:33:44:0B", "00:11:22:33:44:02", FRAME_DATA, 20, 0, 4, FLAG_NONE, "Data from Node B")
    writer.write_frame(csma_b, 5.100)
    csma_c = DLLFrame("00:11:22:33:44:0C", "00:11:22:33:44:02", FRAME_DATA, 30, 0, 4, FLAG_NONE, "Data from Node C")
    writer.write_frame(csma_c, 5.101)

    # 32-bit Jam Signal broadcast
    jam = DLLFrame("00:11:22:33:44:0B", "FF:FF:FF:FF:FF:FF", FRAME_JAM, 0, 0, 0, FLAG_NONE, "COLLISION_JAM_32BIT")
    writer.write_frame(jam, 5.103)

    # After Exponential Backoff, B and C transmit cleanly
    writer.write_frame(csma_b, 5.250)
    writer.write_frame(csma_c, 5.400)

    writer.close()
    print(f"Generated {writer.packet_count} frames in '{pcap_path}'.")


def run_pyshark_dissection(pcap_path: str):
    """Executes full PyShark packet dissection and displays all key features."""
    inspector = PySharkInspector()
    packets = inspector.parse_pcap(pcap_path)

    print(f"\n{C_BOLD}{C_GREEN}>>> SUCCESS: Loaded {len(packets)} packets into PyShark from '{pcap_path}'!{C_RESET}")

    # 1. Summary Table of all frames
    inspector.print_packet_summary_table(packets)

    # 2. Deep PyShark Dissections for Each Specific Feature
    print(f"\n{C_BOLD}{C_MAGENTA}{'='*85}{C_RESET}")
    print(f"{C_BOLD}{C_WHITE}{'DETAILED PYSHARK DISSECTIONS BY FEATURE':^85}{C_RESET}")
    print(f"{C_BOLD}{C_MAGENTA}{'='*85}{C_RESET}")

    # Feature 1 Inspection: Error Control
    print(f"\n{C_BOLD}{C_YELLOW}--- FEATURE 1: ERROR CONTROL & CRC VALIDATION ---{C_RESET}")
    inspector.print_detailed_packet(packets[0], "Clean Frame [CRC-32 FCS Valid]")
    inspector.print_detailed_packet(packets[1], "Corrupted Frame [Single-Bit Noise Injected -> FCS Mismatch]")
    inspector.print_detailed_packet(packets[2], "Burst Corrupted Frame [12-Bit Electrical Burst -> CRC Error]")

    # Feature 2 Inspection: Flow Control (Go-Back-N)
    print(f"\n{C_BOLD}{C_YELLOW}--- FEATURE 2: FLOW CONTROL (GO-BACK-N & IN-ORDER DELIVERY) ---{C_RESET}")
    inspector.print_detailed_packet(packets[3], "GBN DATA Frame Seq=0 [Sender Window Open]")
    inspector.print_detailed_packet(packets[8], "Cumulative ACK=1 [Confirms Packets 0 & 1, Slides Window]")
    inspector.print_detailed_packet(packets[10], "Out-of-Order DATA Seq=3 [Rejected by Receiver, GBN Rule]")
    inspector.print_detailed_packet(packets[12], "GBN Retransmission Seq=2 [Flag RETX set, Timer Recovery]")

    # Feature 3 Inspection: Multiple Access (CSMA/CD)
    print(f"\n{C_BOLD}{C_YELLOW}--- FEATURE 3: MULTIPLE ACCESS (CSMA & COLLISION DETECTION) ---{C_RESET}")
    inspector.print_detailed_packet(packets[17], "Collision Jam Signal [32-bit Jamming Pattern on Shared Bus]")
    inspector.print_detailed_packet(packets[18], "Post-Backoff Transmission [Binary Exponential Backoff Resolved]")


if __name__ == "__main__":
    pcap_file = "captures/dll_cpp_capture.pcap"
    generate_dll_pcap(pcap_file)
    run_pyshark_dissection(pcap_file)
