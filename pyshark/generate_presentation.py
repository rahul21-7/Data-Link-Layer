"""
5-Slide Academic Presentation Generator (PDF Format).
Generates a professional 5-slide PDF presentation for the Data Link Layer project,
conforming to all syllabus and presentation guidelines:
- Slide 1: Project Overview, Objectives & System Architecture
- Slide 2: Go-Back-N (GBN) Flow Control & In-Order Delivery Logic
- Slide 3: CRC-32 & CRC-16 Error Control: Mathematical Rigor & Error Detection
- Slide 4: CSMA & CSMA/CD Multiple Access with Binary Exponential Backoff
- Slide 5: PyShark Packet Dissection, Verification Results & Unique Contributions
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.image as mpimg

OUTPUT_DIR = "presentation"
os.makedirs(OUTPUT_DIR, exist_ok=True)
PDF_PATH = os.path.join(OUTPUT_DIR, "presentation.pdf")


def create_slide_header(ax, slide_num, title, subtitle):
    """Draws a standardized slide title banner."""
    ax.text(0.04, 0.93, f"SLIDE {slide_num} / 5", color="#38BDF8", fontsize=10, fontweight='bold', family="sans-serif")
    ax.text(0.04, 0.86, title, color="#F8FAFC", fontsize=15, fontweight='bold', family="sans-serif")
    ax.text(0.04, 0.81, subtitle, color="#94A3B8", fontsize=10.5, family="sans-serif")
    ax.plot([0.04, 0.96], [0.78, 0.78], color="#0284C7", lw=2)


def slide_1_overview(pdf):
    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)
    fig.patch.set_facecolor("#0F172A")
    ax.set_facecolor("#0F172A")
    ax.axis("off")

    create_slide_header(ax, 1, "Data Link Layer Suite: Go-Back-N, CRC-32 & CSMA/CD",
                        "Comprehensive C++ Protocol Suite with Wireshark & PyShark Deep Packet Inspection")

    # Left Column: Text Overview
    text_content = [
        ("PROJECT OBJECTIVES", [
            "• Design and implement a robust Data Link Layer from first principles.",
            "• Implement Go-Back-N ARQ for reliable sliding-window flow control.",
            "• Implement CRC-32 / CRC-16 for rigorous frame error detection.",
            "• Implement CSMA/CD with collision detection and exponential backoff.",
            "• Export standard PCAP captures for PyShark packet dissection."
        ], "#38BDF8"),
        ("CORE ARCHITECTURAL MODULES (C++)", [
            "• Crc.h / Crc.cpp: Bitwise modulo-2 arithmetic & 256-entry table CRC.",
            "• Frame.h / Frame.cpp: IEEE 802.3 Ethernet framing & bit packing.",
            "• GbnSender.h / GbnReceiver.h: Sliding window state machine & timers.",
            "• CsmaNode.h / CsmaNode.cpp: Carrier sensing & BEB collision handling.",
            "• PcapWriter.h / PcapWriter.cpp: Standard libpcap binary capture engine."
        ], "#34D399")
    ]

    y = 0.72
    for heading, bullet_list, color in text_content:
        ax.text(0.05, y, heading, color=color, fontsize=11, fontweight='bold')
        y -= 0.04
        for b in bullet_list:
            ax.text(0.06, y, b, color="#E2E8F0", fontsize=9.5)
            y -= 0.038
        y -= 0.02

    # Right Column: Diagram
    arch_img_path = "output_screenshots/05_system_architecture_flowchart.png"
    if os.path.exists(arch_img_path):
        img = mpimg.imread(arch_img_path)
        img_ax = fig.add_axes([0.55, 0.12, 0.41, 0.62])
        img_ax.imshow(img)
        img_ax.axis("off")

    pdf.savefig(fig)
    plt.close()


def slide_2_flow_control(pdf):
    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)
    fig.patch.set_facecolor("#0F172A")
    ax.set_facecolor("#0F172A")
    ax.axis("off")

    create_slide_header(ax, 2, "Flow Control: Go-Back-N (GBN) Protocol & In-Order Delivery",
                        "Sliding Window Dynamics, Cumulative ACKs, and Timeout Retransmission Cascade")

    text_content = [
        ("GBN SENDER LOGIC", [
            "• Window Size N: Allows sending up to N unacknowledged frames.",
            "• Sequence Range: [Base, NextSeqNum) where NextSeqNum < Base + N.",
            "• Buffer Management: Deque of unacked frames stored in memory.",
            "• Timer Discipline: Single countdown timer for oldest unacked packet (Base)."
        ], "#38BDF8"),
        ("RECEIVER & ERROR HANDLING", [
            "• ExpectedSeqNum: Strict in-order checking; accepts only ExpectedSeqNum.",
            "• Out-of-Order Discard: Any packet != ExpectedSeqNum is dropped immediately.",
            "• Cumulative ACK: Acknowledges all frames up to k with ACK(k).",
            "• Timeout Recovery: When timer expires, sender 'Goes Back to N' and",
            "  retransmits all buffered unacknowledged frames starting from Base."
        ], "#F59E0B")
    ]

    y = 0.72
    for heading, bullet_list, color in text_content:
        ax.text(0.05, y, heading, color=color, fontsize=11, fontweight='bold')
        y -= 0.04
        for b in bullet_list:
            ax.text(0.06, y, b, color="#E2E8F0", fontsize=9.5)
            y -= 0.038
        y -= 0.02

    # Right: GBN Ladder
    ladder_path = "output_screenshots/01_gbn_flow_control_ladder.png"
    if os.path.exists(ladder_path):
        img = mpimg.imread(ladder_path)
        img_ax = fig.add_axes([0.55, 0.12, 0.41, 0.62])
        img_ax.imshow(img)
        img_ax.axis("off")

    pdf.savefig(fig)
    plt.close()


def slide_3_crc(pdf):
    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)
    fig.patch.set_facecolor("#0F172A")
    ax.set_facecolor("#0F172A")
    ax.axis("off")

    create_slide_header(ax, 3, "Error Control: CRC-32 & CRC-16 Polynomial Division",
                        "Bitwise Modulo-2 Arithmetic, Precomputed Table Acceleration, and Noise Resilience")

    text_content = [
        ("MATHEMATICAL FORMULATION", [
            "• Generator Polynomial P(x): IEEE 802.3 standard (32-bit degree).",
            "  P(x) = x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + ...",
            "• Normal Hex: 0x04C11DB7  |  Reflected Hex: 0xEDB88320.",
            "• Shift-Register Simulation: Implemented both bit-by-bit modulo-2 division",
            "  and a 256-entry precomputed lookup table from scratch in C++."
        ], "#34D399"),
        ("SYNDROME CHECKING & ERROR INJECTION", [
            "• Error Modeling: Injected single-bit flips and 12-bit electrical burst noise.",
            "• Detection Capabilities:",
            "  - 100% of single-bit errors & double-bit errors.",
            "  - 100% of all odd-number-of-bit error patterns.",
            "  - 100% of burst errors <= 32 bits.",
            "• Receiver Action: Recomputes FCS; if mismatch, discards corrupted frame."
        ], "#38BDF8")
    ]

    y = 0.72
    for heading, bullet_list, color in text_content:
        ax.text(0.05, y, heading, color=color, fontsize=11, fontweight='bold')
        y -= 0.04
        for b in bullet_list:
            ax.text(0.06, y, b, color="#E2E8F0", fontsize=9.5)
            y -= 0.038
        y -= 0.02

    # Right: CRC Analysis Chart
    crc_path = "output_screenshots/02_crc_error_detection_analysis.png"
    if os.path.exists(crc_path):
        img = mpimg.imread(crc_path)
        img_ax = fig.add_axes([0.55, 0.12, 0.41, 0.62])
        img_ax.imshow(img)
        img_ax.axis("off")

    pdf.savefig(fig)
    plt.close()


def slide_4_csma(pdf):
    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)
    fig.patch.set_facecolor("#0F172A")
    ax.set_facecolor("#0F172A")
    ax.axis("off")

    create_slide_header(ax, 4, "Multiple Access: CSMA & CSMA/CD with Exponential Backoff",
                        "Carrier Sensing Strategies, Collision Detection, 32-Bit Jam Signals & Contention Resolution")

    text_content = [
        ("CARRIER SENSING MODES", [
            "• 1-Persistent: Transmits immediately once channel becomes idle.",
            "• Non-Persistent: If busy, backs off random duration before sensing.",
            "• p-Persistent: If idle, transmits with probability p; else defers to slot.",
            "• Shared Channel: Simulates concurrent station propagation delay."
        ], "#F59E0B"),
        ("COLLISION DETECTION & BACKOFF (CSMA/CD)", [
            "• Collision Detection: Stations listen while transmitting on shared bus.",
            "• 32-Bit Jam Signal: On collision, station broadcasts JAM frame (0x04)",
            "  to ensure all contending nodes detect the bus collision.",
            "• Truncated Binary Exponential Backoff (BEB):",
            "  - Backoff range: r in [0, 2^min(k, 10) - 1] slots.",
            "  - Backoff delay: T_wait = r * Slot_Time.",
            "  - Exponentially expands contention window on repeated collisions."
        ], "#EF4444")
    ]

    y = 0.72
    for heading, bullet_list, color in text_content:
        ax.text(0.05, y, heading, color=color, fontsize=11, fontweight='bold')
        y -= 0.04
        for b in bullet_list:
            ax.text(0.06, y, b, color="#E2E8F0", fontsize=9.5)
            y -= 0.038
        y -= 0.02

    # Right: CSMA Timeline
    csma_path = "output_screenshots/03_csma_timeline_and_contention.png"
    if os.path.exists(csma_path):
        img = mpimg.imread(csma_path)
        img_ax = fig.add_axes([0.55, 0.12, 0.41, 0.62])
        img_ax.imshow(img)
        img_ax.axis("off")

    pdf.savefig(fig)
    plt.close()


def slide_5_pyshark_results(pdf):
    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=300)
    fig.patch.set_facecolor("#0F172A")
    ax.set_facecolor("#0F172A")
    ax.axis("off")

    create_slide_header(ax, 5, "PyShark Packet Inspection, Experimental Results & Conclusion",
                        "Standard PCAP File Validation, Wireshark Protocol Dissection, and Unique Student Innovations")

    text_content = [
        ("PYSHARK PACKET DISSECTION", [
            "• Direct PCAP Parsing: PyShark integrates with TShark to inspect frames.",
            "• Dissected Layers: Ethernet II (MAC), Custom DLL Header, FCS, Payload.",
            "• Validates: Clean FCS, FCS Mismatch on noise, Retx flags, and Jam frames."
        ], "#38BDF8"),
        ("UNIQUE CONTRIBUTIONS & ORIGINAL WORK", [
            "• Dual CRC Engine: Both mathematical bitwise modulo-2 and fast table CRC.",
            "• Standalone PCAP Binary Writer: Encapsulates custom DLL frames into standard",
            "  libpcap binary format directly in C++ without external libraries.",
            "• Complete Integration: Verified all 3 features running concurrently in harmony.",
            "• 100% In-Order Delivery Verified across noisy, contending medium."
        ], "#34D399")
    ]

    y = 0.72
    for heading, bullet_list, color in text_content:
        ax.text(0.05, y, heading, color=color, fontsize=11, fontweight='bold')
        y -= 0.04
        for b in bullet_list:
            ax.text(0.06, y, b, color="#E2E8F0", fontsize=9.5)
            y -= 0.038
        y -= 0.02

    # Right: PyShark Dissection Layout
    pyshark_path = "output_screenshots/04_pyshark_packet_dissection.png"
    if os.path.exists(pyshark_path):
        img = mpimg.imread(pyshark_path)
        img_ax = fig.add_axes([0.55, 0.12, 0.41, 0.62])
        img_ax.imshow(img)
        img_ax.axis("off")

    pdf.savefig(fig)
    plt.close()


def generate_all_slides():
    """Generates the full 5-slide PDF presentation."""
    with PdfPages(PDF_PATH) as pdf:
        slide_1_overview(pdf)
        print("  [OK] Slide 1: System Overview & Architecture")
        slide_2_flow_control(pdf)
        print("  [OK] Slide 2: Go-Back-N Flow Control")
        slide_3_crc(pdf)
        print("  [OK] Slide 3: CRC Error Control")
        slide_4_csma(pdf)
        print("  [OK] Slide 4: CSMA/CD Multiple Access")
        slide_5_pyshark_results(pdf)
        print("  [OK] Slide 5: PyShark Packet Inspection & Results")

    print(f"\nPresentation successfully generated at '{PDF_PATH}'!")


if __name__ == "__main__":
    generate_all_slides()

