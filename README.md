# Data Link Layer Protocol Suite (C++ Core + PyShark Packet Dissection)

A complete, production-grade implementation of the Data Link Layer (Layer 2) developed from first principles in **C++** with automated **PyShark (Wireshark)** deep packet inspection and mathematical verification.

---

## 🌟 Key Features

1. **Flow Control — Go-Back-N (GBN) ARQ Protocol:**
   - Sliding window of size $N$ (configurable, default $N=4$) maintaining the sequence range $[Base, NextSeqNum)$.
   - Strict in-order frame verification with rejection of damaged or out-of-order packets.
   - Cumulative acknowledgment feedback ($ACK(k)$ confirms contiguous frames $0 \dots k$).
   - Base packet countdown timer and Go-Back-N retransmission cascade on timeout.

2. **Error Control — Cyclic Redundancy Check (CRC-32 & CRC-16):**
   - Implemented from scratch without external libraries.
   - **Dual-Engine Design:** Pure bit-by-bit modulo-2 polynomial division shift-register and precomputed 256-entry table acceleration.
   - Standard **IEEE 802.3 Ethernet polynomial:** $0xEDB88320$ (reflected) / $0x04C11DB7$ (normal), plus CRC-16 CCITT ($0x1021$).
   - Injected single-bit noise and 12-bit electrical burst noise with automatic receiver FCS syndrome check and corrupted frame discard.

3. **Multiple Access Control — CSMA & CSMA/CD with Exponential Backoff:**
   - Multi-station shared broadcast bus contention (Node A, Node B, Node C).
   - Carrier sensing strategies: **1-Persistent**, **Non-Persistent**, and **p-Persistent**.
   - **Collision Detection (CD):** Simultaneous transmission detection during the propagation window.
   - Immediate transmission abort and **32-bit Jam Signal** broadcast (`FRAME_JAM = 0x04`).
   - **Truncated Binary Exponential Backoff (BEB):** $r \in [0, 2^{\min(k, 10)} - 1]$, wait $r \times \text{slot\_time}$.

4. **PyShark Deep Packet Inspection & Native Wireshark Lua Dissector:**
   - Standalone C++ binary PCAP exporter writes raw frames directly into standard libpcap format (`0xA1B2C3D4`, Link Type 1 = Ethernet).
   - Includes a custom **Wireshark Lua Dissector** (`captures/dll_dissector.lua`) bound to EtherType `0x88B5` allowing Wireshark and TShark to natively parse custom header fields (`dll.type`, `dll.seq`, `dll.ack`, `dll.window`, `dll.flags`, `dll.fcs`).
   - PyShark parses `captures/dll_cpp_capture.pcap` via TShark, displaying Ethernet II headers, custom DLL headers, FCS verification status, and payload hex dumps.

---

## 📂 Repository Structure

```
Data-Link-Layer/
├── include/                                # C++ Header Specifications
│   ├── Color.h                             # ANSI terminal styling
│   ├── Crc.h                               # CRC-32 & CRC-16 bitwise specifications
│   ├── Frame.h                             # IEEE 802.3 Ethernet & DLL Frame packing
│   ├── Channel.h                           # Shared physical bus & noise simulator
│   ├── GbnSender.h                         # Go-Back-N sliding window sender
│   ├── GbnReceiver.h                       # Go-Back-N receiver with in-order acceptance
│   ├── CsmaNode.h                          # CSMA/CD station with exponential backoff
│   └── PcapWriter.h                        # Standard libpcap binary capture writer
│
├── src/                                    # C++ Source Implementations
│   ├── main.cpp                            # Interactive simulator running all 4 feature demos
│   ├── Crc.cpp                             # Modulo-2 division & 256-table CRC algorithms
│   ├── Frame.cpp                           # Bit packing, serialization & deserialization
│   ├── Channel.cpp                         # Noise channel, loss model & medium sensing
│   ├── GbnSender.cpp                       # Sliding window, timer & retransmission cascade
│   ├── GbnReceiver.cpp                     # Strict in-order logic & cumulative ACKs
│   ├── CsmaNode.cpp                        # Bus contention, jam broadcasting & BEB
│   └── PcapWriter.cpp                      # Direct binary PCAP file generation
│
├── pyshark/                                # PyShark Inspection & Submission Tools
│   ├── generate_pcap_and_inspect.py        # PCAP generator & deep PyShark packet dissector
│   ├── generate_screenshots.py             # 5 high-resolution screenshot diagrams
│   └── generate_presentation.py            # 5-slide PDF presentation builder
│
├── captures/                               # Captured Packets & Wireshark Dissector
│   ├── dll_cpp_capture.pcap                # Real binary PCAP file inspectable by Wireshark
│   └── dll_dissector.lua                   # Native Wireshark/TShark protocol dissector plugin
│
├── dll_protocol/                           # Python Protocol & Inspector Engine
│   ├── __init__.py                         # Protocol package definition
│   ├── crc.py                              # Pure Python CRC engine
│   ├── frame.py                            # Pure Python frame definition
│   ├── pcap_writer.py                      # Pure Python PCAP writer
│   └── pyshark_inspector.py                # PyShark dissection engine
│
├── output_screenshots/                     # 5 High-Resolution Submission Diagrams
│   ├── 01_gbn_flow_control_ladder.png      # GBN sequence timing ladder diagram
│   ├── 02_crc_error_detection_analysis.png # CRC modulo-2 division & error matrix
│   ├── 03_csma_timeline_and_contention.png # CSMA/CD shared bus contention & BEB timeline
│   ├── 04_pyshark_packet_dissection.png    # Wireshark-compatible packet dissection layout
│   └── 05_system_architecture_flowchart.png# Complete Layer-2 system architecture flowchart
│
├── presentation/                           # Academic Presentation Deliverables
│   ├── presentation.pdf                    # 5-Slide Presentation in PDF format
│   ├── slides.html                         # Interactive browser-based presentation
│   └── SLIDES_EXPLANATION.md               # Student speaking notes & viva Q&A
│
├── CMakeLists.txt                          # CMake build configuration
├── build.bat                               # Windows 1-click build script
├── create_submission_zip.py                # Packages complete submission archive
├── Data_Link_Layer_Final_Project.zip       # Final submission ZIP (39 files, 2.19 MB)
└── requirements.txt                        # Python dependencies
```

---

## 🚀 Step-by-Step Execution Guide

### 1. Environment Setup (Python Virtual Environment)
Activate the virtual environment to use PyShark, Matplotlib, and TShark:
```bash
# Windows:
.\venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate
```

---

### 2. Running PyShark Deep Packet Dissection
To generate the capture and inspect every packet with PyShark:
```bash
python pyshark/generate_pcap_and_inspect.py
```
This script:
1. Records 22 frames into `captures/dll_cpp_capture.pcap`.
2. Loads the native Wireshark Lua dissector (`captures/dll_dissector.lua`).
3. Dissects the frames into a summary table and detailed packet views for:
   - **Feature 1:** Error Control (CRC-32 verification and corrupted frame drops).
   - **Feature 2:** Flow Control (Go-Back-N sliding window, in-order delivery, cumulative ACKs, and timeout retransmissions).
   - **Feature 3:** Multiple Access (CSMA bus sensing, collision detection, 32-bit jam signals, and binary exponential backoff).

---

### 3. Viewing in Native Wireshark (Optional)
Because `dll_cpp_capture.pcap` is a real Libpcap binary file, you can open it in Wireshark:
```bash
wireshark captures/dll_cpp_capture.pcap
```
To load the custom protocol fields in Wireshark GUI:
```bash
wireshark -X lua_script:captures/dll_dissector.lua captures/dll_cpp_capture.pcap
```

---

### 4. Compiling the C++ Simulator
#### Option A: Windows Batch Script
```cmd
build.bat
bin\dll_simulator.exe
```

#### Option B: CMake
```bash
cmake -B build
cmake --build build
./build/dll_simulator
```

---

### 5. Regenerating Deliverables (Diagrams & Presentation)
```bash
# Rebuild the 5 screenshot figures in output_screenshots/
python pyshark/generate_screenshots.py

# Rebuild the 5-slide PDF presentation in presentation/presentation.pdf
python pyshark/generate_presentation.py

# Re-package the submission ZIP
python create_submission_zip.py
```

---

## 📊 Summary of Demonstrated Concepts

| Feature | C++ Implementation Details | PyShark & Wireshark Dissection |
| :--- | :--- | :--- |
| **Flow Control** | Go-Back-N ARQ, Sliding Window $N=4$, Cumulative ACKs, Base Timers | Cumulative ACK analysis, window sliding, and retransmitted frames tagged with `[RETX]`. |
| **Error Control** | IEEE 802.3 CRC-32 ($0xEDB88320$), CRC-16 CCITT, bit-flip & burst noise | Corrupted frames tagged with `[!] CRC ERROR (FCS Mismatch)` and discarded. |
| **Multiple Access** | CSMA/CD, Carrier Sensing, 32-bit Jam Signals, Truncated Binary Exponential Backoff | Sensed bus events, `[COLLISION JAM SIGNAL]` broadcast frames, and backoff resolution. |

---

## 🎓 Academic Presentation Notes
See [`presentation/SLIDES_EXPLANATION.md`](presentation/SLIDES_EXPLANATION.md) for detailed slide-by-slide speaking notes and viva interview questions with answers.
