# Data Link Layer Protocol Suite

A complete implementation of the Data Link Layer (OSI Layer 2) developed from first principles in C++ with automated PyShark packet inspection, mathematical verification, and a native Wireshark Lua dissector.

---

## Overview

This project implements the core responsibilities of the Data Link Layer:
* **Framing & Demarcation:** IEEE 802.3 Ethernet frame encapsulation with custom EtherType `0x88B5`.
* **Error Control:** CRC-32 (IEEE 802.3 polynomial) and CRC-16 (CCITT polynomial) via bitwise shift-register LFSR and precomputed 256-entry lookup tables.
* **Flow Control:** Go-Back-N (GBN) sliding window ARQ with cumulative acknowledgments and Layer-2 Fast Retransmit.
* **Medium Access Control (MAC):** CSMA/CD with carrier sensing, collision detection, 32-bit collision jamming, and Truncated Binary Exponential Backoff (BEB).
* **Packet Inspection:** Native Wireshark Lua dissector plugin and PyShark dissection engine parsing standard Libpcap binary captures.

---

## Key Features

### 1. Flow Control - Go-Back-N ARQ with Fast Retransmit
* Configurable sliding window bounds unacknowledged in-flight frames: `[Base, NextSeqNum)`.
* Strict in-order frame validation at receiver; damaged or out-of-order packets are discarded without buffer pollution.
* Cumulative acknowledgments: `ACK(k)` confirms contiguous delivery of all frames from `0` through `k`.
* Countdown timer for the oldest unacknowledged frame (`Base`) with Go-Back-N retransmission cascade upon expiration.
* **Layer-2 Fast Retransmit:** When 3 duplicate ACKs are detected, the sender infers packet loss early and retransmits the window immediately without waiting for the coarse timer.

### 2. Error Control - CRC-32 & CRC-16
* **Dual-Engine Architecture:**
  * **Bitwise Shift-Register:** Simulates a hardware Linear Feedback Shift Register (LFSR) performing modulo-2 polynomial division.
  * **Table Acceleration:** Precomputed 256-entry lookup table for high-throughput frame generation.
* Standard IEEE 802.3 polynomial: `0xEDB88320` (reflected) / `0x04C11DB7` (normal).
* Standard CRC-16 CCITT polynomial: `0x1021`.
* Noise injection module supports single-bit flips and electrical burst errors with automatic syndrome mismatch detection.

### 3. Multiple Access Control - CSMA/CD with Exponential Backoff
* Multi-station shared broadcast bus simulation (Node A, Node B, Node C).
* Carrier sensing strategies: 1-Persistent, Non-Persistent, and p-Persistent.
* Collision Detection during the propagation delay window ($\tau$).
* Immediate transmission abort and 32-bit Jam Signal broadcast (`FRAME_JAM = 0x04`) to `FF:FF:FF:FF:FF:FF`.
* Truncated Binary Exponential Backoff (BEB): contention window $r \in [0, 2^{\min(k, 10)} - 1]$, backoff delay $T = r \times \text{slot\_time}$.

### 4. Deep Packet Inspection & Wireshark Dissector
* Generates standard Libpcap binary files (`.pcap`) with microsecond timestamps and Ethernet Link Type (`0x01`).
* Custom Wireshark Lua Dissector (`captures/dll_dissector.lua`) bound to EtherType `0x88B5` provides native field decoding (`dll.type`, `dll.seq`, `dll.ack`, `dll.window`, `dll.flags`, `dll.fcs`) and live display filtering in Wireshark.
* PyShark automated inspection scripts dissect and validate clean frames, corrupted frames, and collision jam signals.

---

## Frame Specification

EtherType: `0x88B5` (IEEE 802 Local Experimental 1)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (1B)   |          Sequence Number (2B)         |  ...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ... Ack (2B)  |  Window (1B)  |   Flags (1B)  |  Length (2B)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Data ...                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Frame Check Sequence (FCS, 4B)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
| :--- | :--- | :--- |
| **Type** | 1 byte | Frame Type: `0x01` DATA, `0x02` ACK, `0x03` NAK, `0x04` JAM |
| **Seq** | 2 bytes | Frame sequence number (uint16, big-endian) |
| **Ack** | 2 bytes | Cumulative acknowledgment number (uint16, big-endian) |
| **Window** | 1 byte | Advertised receiver window size |
| **Flags** | 1 byte | Control flags: `0x01` Retransmission, `0x02` Corrupted Noise |
| **Length** | 2 bytes | Byte length of payload |
| **Payload** | Variable | Encapsulated payload data |
| **FCS** | 4 bytes | IEEE 802.3 CRC-32 Frame Check Sequence |

---

## Repository Structure

```
Data-Link-Layer/
|-- include/                   # C++ Header Files
|   |-- Channel.h              # Shared physical medium & noise model
|   |-- Color.h                # ANSI terminal styling
|   |-- Crc.h                  # CRC-32 and CRC-16 bitwise specifications
|   |-- CsmaNode.h             # CSMA/CD station logic & backoff
|   |-- Frame.h                # Frame serialization & deserialization
|   |-- GbnReceiver.h          # Go-Back-N receiver with in-order verification
|   |-- GbnSender.h            # Go-Back-N sender with sliding window
|   `-- PcapWriter.h           # Libpcap binary capture writer
|
|-- src/                       # C++ Implementations
|   |-- Channel.cpp            # Noise channel, loss model & carrier sensing
|   |-- Crc.cpp                # Bitwise LFSR & table-accelerated CRC
|   |-- CsmaNode.cpp           # Bus contention, jam broadcasting & BEB
|   |-- Frame.cpp              # Bit packing & CRC verification
|   |-- GbnReceiver.cpp        # In-order acceptance & cumulative ACKs
|   |-- GbnSender.cpp          # Window management & Fast Retransmit
|   |-- PcapWriter.cpp         # Direct binary PCAP generation
|   `-- main.cpp               # C++ interactive demonstration suite
|
|-- dll_protocol/              # Python Protocol Engine & Inspector
|   |-- __init__.py            # Package initialization
|   |-- crc.py                 # Pure Python CRC engine
|   |-- frame.py               # Frame packing and unpacking
|   |-- pcap_writer.py         # Libpcap binary file writer
|   `-- pyshark_inspector.py   # PyShark dissection engine
|
|-- captures/                  # Captures & Wireshark Dissector
|   |-- dll_cpp_capture.pcap   # Binary capture file
|   `-- dll_dissector.lua      # Native Wireshark/TShark Lua dissector
|
|-- pyshark/                   # Python Inspection Tools
|   `-- generate_pcap_and_inspect.py  # PCAP generator & visualizer
|
|-- CMakeLists.txt             # CMake build configuration
|-- Makefile                   # GNU Make build configuration
|-- build.bat                  # Windows build script
`-- requirements.txt           # Python dependencies
```

---

## Getting Started

### Prerequisites

* **C++ Compiler:** GCC (g++ 9+), Clang (10+), or MSVC with C++17 support.
* **Python:** Python 3.9+ (for PyShark packet inspection).
* **Wireshark / TShark:** (Optional) for live packet dissection and GUI analysis.

### Python Environment Setup

```bash
# Create and activate virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Building and Running

### 1. C++ Simulator

#### Windows (Batch Script)
```cmd
build.bat
bin\dll_simulator.exe
```

#### Linux / macOS / Windows (CMake)
```bash
cmake -B build
cmake --build build
./build/dll_simulator
```

#### GNU Make
```bash
make
./bin/dll_simulator
```

---

### 2. PyShark Dissection & Terminal Visualizer

Run the animated terminal visualizer and PyShark dissection suite:

```bash
python pyshark/generate_pcap_and_inspect.py
```

This script:
1. Generates authentic Data Link Layer traffic across all three subsystems.
2. Writes the packet trace to `captures/dll_cpp_capture.pcap`.
3. Loads `captures/dll_dissector.lua` into TShark to dissect custom fields.
4. Prints formatted packet summaries, protocol layer fields, and CRC validation statuses.

---

### 3. Native Wireshark Integration

To inspect the generated PCAP in the Wireshark GUI with custom protocol decoding:

```bash
wireshark -X lua_script:captures/dll_dissector.lua captures/dll_cpp_capture.pcap
```

Alternatively, copy `captures/dll_dissector.lua` to your personal Wireshark plugins directory:
* **Windows:** `%APPDATA%\Wireshark\plugins\`
* **Linux:** `~/.local/lib/wireshark/plugins/`
* **macOS:** `~/.config/wireshark/plugins/`

Once installed, Wireshark will automatically recognize EtherType `0x88B5` as `DLL` protocol frames, displaying sequence numbers, cumulative ACKs, window sizes, and FCS checks in the packet details pane.
