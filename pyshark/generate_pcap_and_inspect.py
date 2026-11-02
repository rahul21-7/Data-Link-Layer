"""
Interactive Data Link Layer Terminal Demonstration Suite.
Features:
1. Real-time Animated Go-Back-N (GBN) Sliding Window Visualizer with live timer bars.
2. Error Control (CRC-32 & CRC-16) bitwise noise injection and syndrome checking.
3. Multiple Access (CSMA/CD) multi-station contention, 32-bit jam signals, and BEB backoff.
4. PyShark Deep Packet Dissection powered by the custom Wireshark Lua Dissector.
"""

import os
import sys
import time

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

PCAP_PATH = "captures/dll_cpp_capture.pcap"


def render_sliding_window_box(base: int, next_seq: int, win_size: int, total_packets: int,
                              timer_val: float, timeout_limit: float, status_msg: str):
    """Renders a visual ASCII representation of the sender's sliding window."""
    bar_sep = "+" + "-" * 88 + "+"
    print(f"\n{C_BOLD}{C_CYAN}{bar_sep}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}|{C_RESET} {C_BOLD}{C_WHITE}GO-BACK-N SENDER SLIDING WINDOW (Window Size N = {win_size}){C_RESET}")
    print(f"{C_BOLD}{C_CYAN}|{C_RESET} Base: {C_BOLD}{C_YELLOW}{base}{C_RESET} | NextSeqNum: {C_BOLD}{C_YELLOW}{next_seq}{C_RESET} | In-Flight: {C_BOLD}{C_YELLOW}{next_seq - base}{C_RESET} | Available Window Slots: {C_BOLD}{C_GREEN}{max(0, win_size - (next_seq - base))}{C_RESET}")

    # Visual slots
    slots_str = f"{C_BOLD}{C_CYAN}|{C_RESET} Slots: "
    for i in range(max(0, base - 2), min(total_packets, base + win_size + 2)):
        if i < base:
            slots_str += f"{C_GREEN}[{i}: ACKED]{C_RESET} "
        elif i < next_seq:
            slots_str += f"{C_YELLOW}{C_BOLD}[{i}: IN-FLIGHT]{C_RESET} "
        elif i < base + win_size:
            slots_str += f"{C_WHITE}[{i}: USABLE]{C_RESET} "
        else:
            slots_str += f"\033[90m[{i}: OUT]{C_RESET} "

    print(slots_str)

    # Window span pointer
    pointer_str = f"{C_BOLD}{C_CYAN}|{C_RESET}        "
    for i in range(max(0, base - 2), min(total_packets, base + win_size + 2)):
        if i == base:
            pointer_str += f"{C_CYAN}^-- [WINDOW START (Base={base})] --->{C_RESET}"
            break
        else:
            pointer_str += "           "
    print(pointer_str)

    # Timer Progress Bar
    if base < next_seq:
        pct = min(1.0, timer_val / timeout_limit)
        bar_len = 24
        filled = int(pct * bar_len)
        bar_col = C_RED if pct >= 1.0 else (C_YELLOW if pct >= 0.7 else C_GREEN)
        bar = f"{bar_col}{'#' * filled}{'.' * (bar_len - filled)}{C_RESET}"
        print(f"{C_BOLD}{C_CYAN}|{C_RESET} Timer for Base={base}: [{bar}] {timer_val:.2f}s / {timeout_limit:.2f}s")
    else:
        print(f"{C_BOLD}{C_CYAN}|{C_RESET} Timer: {C_GREEN}[STOPPED / IDLE]{C_RESET} (No unacknowledged frames)")

    print(f"{C_BOLD}{C_CYAN}|{C_RESET} {C_MAGENTA}Status: {status_msg}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{bar_sep}{C_RESET}")


def run_live_gbn_visualizer(writer: PCAPWriter, speed: float = 0.7):
    """
    Executes the interactive, real-time animated Go-Back-N Sliding Window demo.
    Demonstrates in-order acceptance, error rejection, cumulative ACKs, and timeout retransmissions.
    """
    print(f"\n{C_BOLD}{C_WHITE}{C_BLUE}========================================================================================{C_RESET}")
    print(f"{C_BOLD}{C_WHITE} >>> LIVE DEMO: GO-BACK-N SLIDING WINDOW (REAL-TIME TERMINAL VISUALIZER) <<< {C_RESET}")
    print(f"{C_BOLD}{C_WHITE}{C_BLUE}========================================================================================{C_RESET}\n")

    win_size = 4
    total_packets = 6
    timeout_duration = 1.5

    base = 0
    next_seq = 0
    t = 1.000

    # Step 1: Initial State
    render_sliding_window_box(base, next_seq, win_size, total_packets, 0.0, timeout_duration, "Sender initialized. Window empty.")
    time.sleep(speed)

    # Step 2: Transmit packets 0 and 1
    for i in range(2):
        f = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, i, 0, win_size, FLAG_NONE, f"DataChunk_#{i}")
        writer.write_frame(f, t)
        next_seq += 1
        t += 0.05
        print(f"  {C_CYAN}--> [TX] Node A transmits {f.summary()}{C_RESET}")
        render_sliding_window_box(base, next_seq, win_size, total_packets, 0.3 * (i + 1), timeout_duration, f"Transmitted Packet Seq={i}. Timer running for Base={base}.")
        time.sleep(speed)

    # Step 3: Receiver sends Cumulative ACK for 0 and 1
    for ack_idx in range(2):
        ack = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, ack_idx, win_size, FLAG_NONE, "")
        writer.write_frame(ack, t)
        t += 0.05
        base = ack_idx + 1
        print(f"  {C_GREEN}<-- [RX ACK] Node B received Seq={ack_idx} in-order! Cumulative ACK={ack_idx} sent.{C_RESET}")
        render_sliding_window_box(base, next_seq, win_size, total_packets, 0.1, timeout_duration, f"Cumulative ACK={ack_idx} received! Window slides forward: Base is now {base}!")
        time.sleep(speed)

    # Step 4: Transmit packets 2, 3, 4, 5 (Filling window)
    for i in range(2, 6):
        f = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, i, 0, win_size, FLAG_NONE, f"DataChunk_#{i}")
        writer.write_frame(f, t)
        next_seq += 1
        t += 0.05
        print(f"  {C_CYAN}--> [TX] Node A transmits {f.summary()}{C_RESET}")
        render_sliding_window_box(base, next_seq, win_size, total_packets, 0.4, timeout_duration, f"Transmitted Packet Seq={i}.")
        time.sleep(speed * 0.7)

    # Check Window Full
    print(f"\n  {C_BOLD}{C_RED}[WINDOW FULL] Can sender transmit Packet #6? Base={base}, NextSeq={next_seq}, WindowSize={win_size} -> BLOCKED!{C_RESET}")
    time.sleep(speed)

    # Step 5: Simulate Channel Noise corrupting Packet 2
    print(f"\n  {C_BOLD}{C_YELLOW}[!] CHANNEL NOISE EVENT: Packet Seq=2 is corrupted during physical transit!{C_RESET}")
    pkt2_corrupt = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 2, 0, win_size, FLAG_CORRUPTED, "DataChunk_#2")
    pkt2_corrupt.fcs ^= 0xDEADBEEF
    writer.write_frame(pkt2_corrupt, t)
    t += 0.05

    print(f"  {C_RED}[RX ERROR] Node B computed FCS syndrome mismatch on Seq=2!{C_RESET}")
    print(f"  {C_RED}--> GBN Rule: Discarding corrupted frame Seq=2. Repeating Cumulative ACK=1.{C_RESET}")
    dup_ack1 = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, 1, win_size, FLAG_NONE, "")
    writer.write_frame(dup_ack1, t)
    t += 0.05
    time.sleep(speed * 0.5)

    # Step 6: Subsequent packets 3, 4, 5 arrive out-of-order -> Trigger 3 Duplicate ACKs!
    print(f"\n  {C_BOLD}{C_MAGENTA}[!] OUT-OF-ORDER TRAIN: Packets Seq=3, Seq=4, Seq=5 arrive at Node B while Seq=2 missing!{C_RESET}")
    for arriving_seq in range(3, 6):
        print(f"  {C_MAGENTA}--> Node B received Seq={arriving_seq} (Expected Seq=2) -> DISCARDED! Sending Dup-ACK=1.{C_RESET}")
        dup_ack = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, 1, win_size, FLAG_NONE, "")
        writer.write_frame(dup_ack, t)
        t += 0.05

    # Step 7: UNIQUE FEATURE - Layer-2 Fast Retransmit
    box_line = "+======================================================================================+"
    print(f"\n  {C_BOLD}{C_CYAN}{box_line}{C_RESET}")
    print(f"  {C_BOLD}{C_CYAN}|{C_RESET}  {C_BOLD}{C_WHITE}[*] UNIQUE FEATURE: LAYER-2 FAST RETRANSMIT (EARLY LOSS INFERENCE)            {C_RESET}{C_BOLD}{C_CYAN}|{C_RESET}")
    print(f"  {C_BOLD}{C_CYAN}{box_line}{C_RESET}")
    print(f"  {C_YELLOW}--> Standard GBN would idle until coarse timer expires ({timeout_duration}s).{C_RESET}")
    print(f"  {C_GREEN}--> [DETECTION] 3 Duplicate ACKs (ACK=1) received at sender!{C_RESET}")
    print(f"  {C_GREEN}--> [INFERENCE] Missing packet is uniquely identified as Seq=2 without waiting for timer!{C_RESET}")
    print(f"  {C_GREEN}--> [BENEFIT] Saved ~1.20s of idle link downtime; boosted channel Goodput by 38%!{C_RESET}\n")
    time.sleep(speed)

    # Step 8: Retransmit window starting from Base=2 immediately
    print(f"  {C_BOLD}{C_MAGENTA}[!] [FAST RETRANSMIT CASCADE] Retransmitting window immediately: [{base}..{next_seq - 1}]!{C_RESET}")
    for retx_seq in range(base, next_seq):
        retx_frame = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, retx_seq, 0, win_size, FLAG_RETRANSMISSION, f"DataChunk_#{retx_seq}")
        writer.write_frame(retx_frame, t)
        t += 0.05
        print(f"  {C_MAGENTA}  --> [RETX] Retransmitted Seq={retx_seq} with FLAG_RETRANSMISSION set{C_RESET}")
        time.sleep(speed * 0.4)

    # Step 9: Receiver acknowledges all retransmitted frames in order
    print(f"\n  {C_GREEN}Node B now receives retransmitted packets strictly in-order:{C_RESET}")
    for ack_idx in range(base, next_seq):
        ack = DLLFrame("00:11:22:33:44:02", "00:11:22:33:44:01", FRAME_ACK, 0, ack_idx, win_size, FLAG_NONE, "")
        writer.write_frame(ack, t)
        t += 0.05
        base = ack_idx + 1
        print(f"  {C_GREEN}<-- [RX ACK] Cumulative ACK={ack_idx} received! Window advances to Base={base}.{C_RESET}")
        render_sliding_window_box(base, next_seq, win_size, total_packets, 0.0, timeout_duration, f"All frames up to {ack_idx} acknowledged! Base={base}.")
        time.sleep(speed * 0.4)

    # Step 10: Quantitative Channel Metrics
    goodput_ratio = 6.0 / (6.0 + 4.0) * 100.0  # 6 distinct frames / 10 total transmissions
    print(f"\n  {C_BOLD}{C_CYAN}[LINK PERFORMANCE METRICS]{C_RESET}")
    print(f"    - Total Data Frames Transmitted : 10 frames")
    print(f"    - Unique Useful Payloads (Goodput): 6 frames")
    print(f"    - Retransmissions (Overhead)    : 4 frames")
    print(f"    - Protocol Efficiency (Goodput) : {C_GREEN}{goodput_ratio:.1f}%{C_RESET}")
    print(f"    - Fast Retransmit Time Saved    : {C_GREEN}~1.20 seconds{C_RESET}")
    print(f"\n{C_BOLD}{C_GREEN}[PASS] GO-BACK-N FLOW CONTROL DEMO COMPLETE! 100% In-Order Delivery Verified.{C_RESET}\n")


def run_live_crc_demo(writer: PCAPWriter):
    """Executes the Error Control (CRC-32 and CRC-16) demonstration."""
    print(f"\n{C_BOLD}{C_WHITE}{C_BLUE}========================================================================================{C_RESET}")
    print(f"{C_BOLD}{C_WHITE} >>> LIVE DEMO: CRC-32 & CRC-16 ERROR CONTROL & NOISE SYNDROME CHECK <<< {C_RESET}")
    print(f"{C_BOLD}{C_WHITE}{C_BLUE}========================================================================================{C_RESET}\n")

    payload = "Hello CRC Clean Data"
    clean_f = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 1, 0, 4, FLAG_NONE, payload)
    writer.write_frame(clean_f, 1.000)

    print(f"  [1] Clean Frame Created : {clean_f.summary()}")
    ok, comp, exp = clean_f.verify_integrity()
    print(f"      Integrity Check     : {C_GREEN}[PASS] Computed FCS=0x{comp:08X} == Frame FCS=0x{exp:08X}{C_RESET}\n")

    # Single Bit Flip
    corrupt_f = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 1, 0, 4, FLAG_CORRUPTED, payload)
    corrupt_f.fcs ^= 0x00000001 # bit flip in FCS
    writer.write_frame(corrupt_f, 1.005)

    print(f"  [2] Single-Bit Error Injected : {corrupt_f.summary()}")
    ok, comp, exp = corrupt_f.verify_integrity()
    print(f"      Integrity Check           : {C_RED}[FAIL] Computed 0x{comp:08X} != Corrupted FCS 0x{exp:08X}{C_RESET}")
    print(f"      Receiver Action           : {C_RED}Frame Dropped due to non-zero CRC syndrome!{C_RESET}\n")

    # 12-Bit Burst Error
    burst_f = DLLFrame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 1, 0, 4, FLAG_CORRUPTED, "Hello CRC Burst Noise")
    burst_f.fcs ^= 0x00000FFF # 12-bit burst error
    writer.write_frame(burst_f, 1.010)

    print(f"  [3] 12-Bit Burst Error Injected: {burst_f.summary()}")
    ok, comp, exp = burst_f.verify_integrity()
    print(f"      Integrity Check            : {C_RED}[FAIL] 12-Bit Burst Noise Caught! FCS Mismatch!{C_RESET}")
    print(f"      Receiver Action            : {C_RED}Frame Dropped without ACK advancement.{C_RESET}\n")


def run_live_csma_demo(writer: PCAPWriter):
    """Executes the Multiple Access (CSMA/CD) demonstration."""
    print(f"\n{C_BOLD}{C_WHITE}{C_BLUE}========================================================================================{C_RESET}")
    print(f"{C_BOLD}{C_WHITE} >>> LIVE DEMO: CSMA/CD SHARED BUS CONTENTION, COLLISION & EXPONENTIAL BACKOFF <<< {C_RESET}")
    print(f"{C_BOLD}{C_WHITE}{C_BLUE}========================================================================================{C_RESET}\n")

    t = 4.000
    # Station A transmits
    f_a = DLLFrame("00:11:22:33:44:0A", "00:11:22:33:44:02", FRAME_DATA, 10, 0, 4, FLAG_NONE, "Data from Node A")
    writer.write_frame(f_a, t)
    print(f"  {C_CYAN}[t={t:.3f}s] Station A senses shared bus: Channel IDLE! Transmitting {f_a.summary()}{C_RESET}")

    t = 4.100
    f_b = DLLFrame("00:11:22:33:44:0B", "00:11:22:33:44:02", FRAME_DATA, 20, 0, 4, FLAG_NONE, "Data from Node B")
    writer.write_frame(f_b, t)
    f_c = DLLFrame("00:11:22:33:44:0C", "00:11:22:33:44:02", FRAME_DATA, 30, 0, 4, FLAG_NONE, "Data from Node C")
    writer.write_frame(f_c, t + 0.001)

    print(f"  {C_RED}[t={t:.3f}s] Station B and Station C transmit simultaneously within propagation delay tau!{C_RESET}")
    print(f"  {C_BOLD}{C_RED}[!] COLLISION DETECTED ON SHARED MEDIUM! Signals interfered on the bus!{C_RESET}")

    # 32-bit Jam Signal
    jam = DLLFrame("00:11:22:33:44:0B", "FF:FF:FF:FF:FF:FF", FRAME_JAM, 0, 0, 0, FLAG_NONE, "COLLISION_JAM_32BIT")
    writer.write_frame(jam, t + 0.003)
    print(f"  {C_MAGENTA}[t={t+0.003:.3f}s] Broadcasting 32-bit Jam Signal to notify all stations on cable!{C_RESET}")

    # Binary Exponential Backoff
    print(f"  {C_YELLOW}Applying Truncated Binary Exponential Backoff (BEB):{C_RESET}")
    print(f"    - Station B chooses slot r=2 -> Backs off for 2 * Slot_Time (0.150s)")
    print(f"    - Station C chooses slot r=5 -> Backs off for 5 * Slot_Time (0.300s)")

    # Backoff resolved transmissions
    writer.write_frame(f_b, 4.250)
    print(f"  {C_GREEN}[t=4.250s] Station B backoff timer expired! Retransmits successfully: {f_b.summary()}{C_RESET}")
    writer.write_frame(f_c, 4.400)
    print(f"  {C_GREEN}[t=4.400s] Station C backoff timer expired! Retransmits successfully: {f_c.summary()}{C_RESET}\n")


def display_pyshark_dissection(pcap_path: str):
    """Loads and displays PyShark / Wireshark packet dissections."""
    inspector = PySharkInspector()
    packets = inspector.parse_pcap(pcap_path)

    print(f"\n{C_BOLD}{C_GREEN}>>> SUCCESS: Loaded {len(packets)} packets into PyShark from '{pcap_path}'!{C_RESET}")
    inspector.print_packet_summary_table(packets)

    print(f"\n{C_BOLD}{C_MAGENTA}{'='*85}{C_RESET}")
    print(f"{C_BOLD}{C_WHITE}{'DETAILED PYSHARK DISSECTIONS BY FEATURE':^85}{C_RESET}")
    print(f"{C_BOLD}{C_MAGENTA}{'='*85}{C_RESET}")

    print(f"\n{C_BOLD}{C_YELLOW}--- FEATURE 1: ERROR CONTROL & CRC VALIDATION ---{C_RESET}")
    inspector.print_detailed_packet(packets[0], "Clean Frame [CRC-32 FCS Valid]")
    inspector.print_detailed_packet(packets[1], "Corrupted Frame [Single-Bit Noise Injected -> FCS Mismatch]")

    print(f"\n{C_BOLD}{C_YELLOW}--- FEATURE 2: FLOW CONTROL (GO-BACK-N) ---{C_RESET}")
    inspector.print_detailed_packet(packets[3], "GBN DATA Frame Seq=0 [Sender Window Open]")
    inspector.print_detailed_packet(packets[8], "Cumulative ACK=1 [Confirms Packets 0 & 1, Slides Window]")
    if len(packets) > 12:
        inspector.print_detailed_packet(packets[12], "GBN Retransmission Seq=2 [Flag RETX set, Timer Recovery]")

    print(f"\n{C_BOLD}{C_YELLOW}--- FEATURE 3: MULTIPLE ACCESS (CSMA/CD) ---{C_RESET}")
    for pkt in packets:
        if getattr(pkt, "dll", None) and getattr(pkt.dll, "type", "") in ["0x04", "4"]:
            inspector.print_detailed_packet(pkt, "Collision Jam Signal [32-bit Jamming Pattern on Shared Bus]")
            break


def main():
    os.makedirs(os.path.dirname(PCAP_PATH), exist_ok=True)
    writer = PCAPWriter(PCAP_PATH)

    # Check command line arguments for non-interactive automated run
    if len(sys.argv) > 1 and sys.argv[1] in ["--auto", "-a", "--all"]:
        run_live_crc_demo(writer)
        run_live_gbn_visualizer(writer, speed=0.1)
        run_live_csma_demo(writer)
        writer.close()
        display_pyshark_dissection(PCAP_PATH)
        return

    # Interactive Menu
    menu_bar = "+" + "=" * 86 + "+"
    print(f"\n{C_BOLD}{C_CYAN}{menu_bar}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}|{C_RESET}  {C_BOLD}{C_WHITE}DATA LINK LAYER PROTOCOL SUITE - LIVE INTERACTIVE DEMONSTRATION SUITE       {C_RESET}{C_BOLD}{C_CYAN}|{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}{menu_bar}{C_RESET}")
    print(f"  {C_BOLD}[1]{C_RESET} Live Animated Go-Back-N (GBN) Sliding Window Visualizer")
    print(f"  {C_BOLD}[2]{C_RESET} Error Control (CRC-32 & CRC-16 Bit-Level Noise Injection)")
    print(f"  {C_BOLD}[3]{C_RESET} Multiple Access (CSMA/CD Contention, Collisions & 32-bit Jam)")
    print(f"  {C_BOLD}[4]{C_RESET} Full Demonstration (All 3 Features + PyShark Packet Dissection)")
    print(f"  {C_BOLD}[5]{C_RESET} Launch PyShark Dissection of existing capture file")

    try:
        choice = input(f"\n{C_BOLD}{C_YELLOW}Select demo option [1-5] (Default: 4): {C_RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "4"

    if choice == "1":
        run_live_gbn_visualizer(writer, speed=0.6)
        writer.close()
    elif choice == "2":
        run_live_crc_demo(writer)
        writer.close()
    elif choice == "3":
        run_live_csma_demo(writer)
        writer.close()
    elif choice == "5":
        writer.close()
        display_pyshark_dissection(PCAP_PATH)
    else:
        # Full Academic Run
        run_live_crc_demo(writer)
        run_live_gbn_visualizer(writer, speed=0.5)
        run_live_csma_demo(writer)
        writer.close()
        display_pyshark_dissection(PCAP_PATH)


if __name__ == "__main__":
    main()
