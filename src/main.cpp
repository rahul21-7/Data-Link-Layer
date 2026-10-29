#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <chrono>

#include "Color.h"
#include "Crc.h"
#include "Frame.h"
#include "Channel.h"
#include "GbnSender.h"
#include "GbnReceiver.h"
#include "CsmaNode.h"
#include "PcapWriter.h"

void print_banner() {
    std::cout << Color::BOLD << Color::CYAN
              << "========================================================================================\n"
              << "       DATA LINK LAYER PROTOCOL SUITE (C++ IMPLEMENTATION)                             \n"
              << "  Features: Go-Back-N ARQ (Flow Control) | CRC-32/16 (Error Control) | CSMA/CD (MAC)    \n"
              << "  Output Export: Standard PCAP Binary for Wireshark & PyShark Deep Packet Inspection    \n"
              << "========================================================================================\n"
              << Color::RESET << std::endl;
}

void demo_error_control(PcapWriter& pcap) {
    std::cout << "\n" << Color::BOLD << Color::BG_BLUE << Color::WHITE
              << " >>> FEATURE 1: ERROR CONTROL (CRC-32 / CRC-16 BITWISE CALCULATION & VERIFICATION) <<< "
              << Color::RESET << "\n\n";

    // 1. Modulo-2 Bitwise Division Trace
    std::cout << Color::BOLD << "[1] Bit-by-Bit Modulo-2 Division Trace (Textbook Example):" << Color::RESET << "\n";
    std::string sample_data = "11010011101100000";
    std::string generator_poly = "10011"; // x^4 + x + 1
    std::cout << CRC::demonstrate_modulo2_division(sample_data, generator_poly) << "\n";

    // 2. Pure Bitwise vs Table-Accelerated CRC-32 (IEEE 802.3 Standard)
    std::string payload = "Hello Computer Networks Lab! Data Link Layer CRC Test";
    const uint8_t* byte_ptr = reinterpret_cast<const uint8_t*>(payload.data());
    size_t len = payload.size();

    uint32_t crc_bitwise = CRC::compute_crc32_bitwise(byte_ptr, len);
    uint32_t crc_table   = CRC::compute_crc32(byte_ptr, len);
    uint16_t crc16       = CRC::compute_crc16(byte_ptr, len);

    std::cout << Color::BOLD << "[2] IEEE 802.3 Standard Polynomial CRC Verification:" << Color::RESET << "\n";
    std::cout << "  Payload: \"" << payload << "\"\n";
    std::cout << "  - CRC-32 (Bitwise Shift-Register) : 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << crc_bitwise << "\n";
    std::cout << "  - CRC-32 (256-Table Accelerated)  : 0x" << std::setw(8) << std::setfill('0') << crc_table << "\n";
    std::cout << "  - CRC-16 (CCITT Polynomial)       : 0x" << std::setw(4) << std::setfill('0') << crc16 << std::dec << "\n";
    std::cout << "  - Bitwise vs Table Match Check     : " << (crc_bitwise == crc_table ? Color::GREEN "[PERFECT MATCH]" : Color::RED "[MISMATCH]") << Color::RESET << "\n\n";

    // 3. Bit Error and Burst Error Injection
    std::cout << Color::BOLD << "[3] Transmission Error Injection & Syndrome Detection:" << Color::RESET << "\n";
    DLLFrame clean_frame("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 1, 0, 4, FLAG_NONE, payload);
    pcap.write_frame(clean_frame, 1.000);

    std::cout << "  Clean Frame Created : " << clean_frame.summary() << "\n";
    uint32_t comp_fcs = 0;
    bool clean_ok = clean_frame.verify_integrity(&comp_fcs);
    std::cout << "  Clean Frame CRC Check: " << (clean_ok ? Color::GREEN "[VALID FCS]" : Color::RED "[INVALID]")
              << Color::RESET << " (FCS=0x" << std::hex << std::uppercase << clean_frame.fcs << ")\n\n" << std::dec;

    // Single Bit Flip
    std::vector<uint8_t> raw_clean = clean_frame.serialize();
    std::vector<uint8_t> raw_bit_flipped = CRC::inject_bit_flip(raw_clean, 25 * 8 + 4); // flip bit 4 of byte 25
    DLLFrame corrupted_frame = DLLFrame::deserialize(raw_bit_flipped);
    corrupted_frame.flags |= FLAG_CORRUPTED;
    pcap.write_frame(corrupted_frame, 1.005);

    std::cout << Color::YELLOW << "  [!] Single-Bit Flip Injected at Byte 25, Bit 4!" << Color::RESET << "\n";
    std::cout << "  Corrupted Frame Data : " << corrupted_frame.summary() << "\n";
    bool corrupt_ok = corrupted_frame.verify_integrity(&comp_fcs);
    std::cout << "  Corrupted Frame Check: " << (corrupt_ok ? Color::GREEN "[VALID]" : Color::RED "[FCS ERROR DETECTED]")
              << Color::RESET << " (Expected 0x" << std::hex << std::uppercase << corrupted_frame.fcs
              << " vs Computed 0x" << comp_fcs << ")" << std::dec << "\n\n";

    // Multi-Bit Burst Error
    std::vector<uint8_t> raw_burst = CRC::inject_burst_error(raw_clean, 20 * 8, 12); // 12-bit burst error
    DLLFrame burst_frame = DLLFrame::deserialize(raw_burst);
    burst_frame.flags |= FLAG_CORRUPTED;
    pcap.write_frame(burst_frame, 1.010);

    std::cout << Color::YELLOW << "  [!] 12-Bit Electrical Burst Error Injected!" << Color::RESET << "\n";
    std::cout << "  Burst Corrupted Frame: " << burst_frame.summary() << "\n";
    bool burst_ok = burst_frame.verify_integrity(&comp_fcs);
    std::cout << "  Burst Error Check    : " << (burst_ok ? Color::GREEN "[VALID]" : Color::RED "[BURST ERROR DETECTED]")
              << Color::RESET << "\n";
}

void demo_flow_control(PcapWriter& pcap) {
    std::cout << "\n" << Color::BOLD << Color::BG_BLUE << Color::WHITE
              << " >>> FEATURE 2: FLOW CONTROL (GO-BACK-N SLIDING WINDOW & IN-ORDER DELIVERY) <<< "
              << Color::RESET << "\n\n";

    GbnSender sender("00:11:22:33:44:01", "00:11:22:33:44:02", 4, 1.5); // Window Size = 4, Timeout = 1.5s
    GbnReceiver receiver("00:11:22:33:44:02", "00:11:22:33:44:01");
    SharedChannel channel(0.0, 0.0, &pcap);

    double current_time = 2.0;

    std::cout << Color::BOLD << "[1] Transmitting Initial Window (N=4 frames: Seq 0, 1, 2, 3):" << Color::RESET << "\n";
    for (int i = 0; i < 4; ++i) {
        std::string msg = "PacketPayload_#" + std::to_string(i);
        DLLFrame frame = sender.send_packet(msg, current_time);
        pcap.write_frame(frame, current_time);
        std::cout << "  --> Sender TX: " << frame.summary() << "\n";
        current_time += 0.01;
    }
    sender.print_window_state();

    // Verify window full
    std::cout << "\n" << Color::BOLD << "[2] Window Full Protection Check:" << Color::RESET << "\n";
    std::cout << "  Can sender transmit another packet? "
              << (sender.can_send() ? Color::GREEN "YES" : Color::RED "NO (Window is Full!)")
              << Color::RESET << "\n\n";

    // Simulate Receiver processing Packet 0 and Packet 1 successfully
    std::cout << Color::BOLD << "[3] Receiver In-Order Processing & Cumulative ACKs:" << Color::RESET << "\n";
    for (int i = 0; i < 2; ++i) {
        DLLFrame pkt("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, i, 0, 4, FLAG_NONE, "PacketPayload_#" + std::to_string(i));
        DLLFrame ack;
        receiver.receive_frame(pkt, ack);
        pcap.write_frame(ack, current_time);
        sender.process_ack(ack.ack_num, current_time);
        current_time += 0.02;
    }
    std::cout << "\n  Sender window slides forward after receiving Cumulative ACK=1:\n";
    sender.print_window_state();

    // Simulate Frame 2 being corrupted by noise, while Frame 3 arrives intact
    std::cout << "\n" << Color::BOLD << "[4] Error Handling & Out-of-Order Frame Rejection:" << Color::RESET << "\n";
    std::cout << Color::YELLOW << "  * Simulating Noise: Packet Seq=2 is corrupted during link transit!" << Color::RESET << "\n";
    DLLFrame pkt2("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 2, 0, 4, FLAG_CORRUPTED, "PacketPayload_#2");
    pkt2.fcs ^= 0xFFFFFFFF; // corrupt FCS
    pcap.write_frame(pkt2, current_time);
    DLLFrame ack2;
    receiver.receive_frame(pkt2, ack2);
    pcap.write_frame(ack2, current_time + 0.005);
    current_time += 0.05;

    std::cout << "\n  * Packet Seq=3 arrives at receiver while Seq=2 was dropped:\n";
    DLLFrame pkt3("00:11:22:33:44:01", "00:11:22:33:44:02", FRAME_DATA, 3, 0, 4, FLAG_NONE, "PacketPayload_#3");
    pcap.write_frame(pkt3, current_time);
    DLLFrame ack3;
    receiver.receive_frame(pkt3, ack3);
    pcap.write_frame(ack3, current_time + 0.005);
    current_time += 0.05;

    // Simulate GBN Sender Timeout
    std::cout << "\n" << Color::BOLD << "[5] Go-Back-N Timeout & Window Retransmission Cascade:" << Color::RESET << "\n";
    current_time += 2.0; // Advance time past timeout duration
    if (sender.is_timed_out(current_time)) {
        auto retx_frames = sender.handle_timeout(current_time);
        for (const auto& f : retx_frames) {
            pcap.write_frame(f, current_time);
            std::cout << "  --> Retransmitting: " << f.summary() << "\n";
            current_time += 0.01;
        }

        std::cout << "\n  * Receiver now receives retransmitted packets in order:\n";
        for (const auto& f : retx_frames) {
            DLLFrame ack;
            receiver.receive_frame(f, ack);
            pcap.write_frame(ack, current_time);
            sender.process_ack(ack.ack_num, current_time);
            current_time += 0.02;
        }
    }

    std::cout << "\n";
    sender.print_window_state();
    receiver.print_status();
}

void demo_multiple_access(PcapWriter& pcap) {
    std::cout << "\n" << Color::BOLD << Color::BG_BLUE << Color::WHITE
              << " >>> FEATURE 3: MULTIPLE ACCESS (CSMA & CSMA/CD WITH EXPONENTIAL BACKOFF) <<< "
              << Color::RESET << "\n\n";

    SharedChannel bus(0.0, 0.0, &pcap);
    double current_time = 5.0;

    CsmaNode node_a("Station_A", "00:11:22:33:44:0A", CsmaMode::CSMA_CD, 0.5, 0.05);
    CsmaNode node_b("Station_B", "00:11:22:33:44:0B", CsmaMode::CSMA_CD, 0.5, 0.05);
    CsmaNode node_c("Station_C", "00:11:22:33:44:0C", CsmaMode::CSMA_CD, 0.5, 0.05);

    // Enqueue frames
    node_a.enqueue_frame(DLLFrame("00:11:22:33:44:0A", "00:11:22:33:44:02", FRAME_DATA, 10, 0, 4, FLAG_NONE, "Data from Node A"));
    node_b.enqueue_frame(DLLFrame("00:11:22:33:44:0B", "00:11:22:33:44:02", FRAME_DATA, 20, 0, 4, FLAG_NONE, "Data from Node B"));
    node_c.enqueue_frame(DLLFrame("00:11:22:33:44:0C", "00:11:22:33:44:02", FRAME_DATA, 30, 0, 4, FLAG_NONE, "Data from Node C"));

    std::cout << Color::BOLD << "[1] Station A senses idle medium and transmits:" << Color::RESET << "\n";
    node_a.attempt_transmission(bus, current_time, &pcap);

    std::cout << "\n" << Color::BOLD << "[2] Stations B and C contend simultaneously -> Collision & Jamming:" << Color::RESET << "\n";
    bus.request_transmission("Station_B", current_time, 0.08); // Simulate overlapping transmission
    node_c.attempt_transmission(bus, current_time, &pcap);

    std::cout << "\n" << Color::BOLD << "[3] Binary Exponential Backoff Resolution:" << Color::RESET << "\n";
    node_b.attempt_transmission(bus, current_time, &pcap);
    node_c.attempt_transmission(bus, current_time, &pcap);

    std::cout << "\n";
    node_a.print_stats();
    node_b.print_stats();
    node_c.print_stats();
}

void demo_integrated_simulation(PcapWriter& pcap) {
    std::cout << "\n" << Color::BOLD << Color::BG_BLUE << Color::WHITE
              << " >>> FEATURE 4: FULL INTEGRATED DLL RUN (CSMA + GBN + CRC IN HARMONY) <<< "
              << Color::RESET << "\n\n";

    SharedChannel shared_medium(0.15, 0.05, &pcap); // 15% bit error, 5% loss
    GbnSender sender("00:11:22:33:44:AA", "00:11:22:33:44:BB", 4, 1.2);
    GbnReceiver receiver("00:11:22:33:44:BB", "00:11:22:33:44:AA");
    CsmaNode csma_station("Node_Alpha", "00:11:22:33:44:AA", CsmaMode::CSMA_CD);

    double sim_time = 10.0;
    const int TOTAL_PACKETS = 8;

    std::cout << Color::CYAN << "Starting end-to-end transmission of " << TOTAL_PACKETS
              << " packets across noisy CSMA medium...\n\n" << Color::RESET;

    int attempts = 0;
    while (!sender.is_done(TOTAL_PACKETS) && attempts < 40) {
        attempts++;

        // 1. Send packets while sender window allows
        while (sender.can_send() && sender.get_next_seq() < TOTAL_PACKETS) {
            std::string payload = "MsgChunk_" + std::to_string(sender.get_next_seq());
            DLLFrame tx_frame = sender.send_packet(payload, sim_time);

            // Channel transmission with possible noise
            DLLFrame rx_frame;
            TransmissionResult res = shared_medium.transmit_frame(tx_frame, rx_frame, sim_time);

            if (res == TransmissionResult::LOST) {
                // Lost on channel
            } else {
                // Receiver processes frame (CRC check + In-Order check)
                DLLFrame ack_frame;
                ReceiverAction act = receiver.receive_frame(rx_frame, ack_frame);

                if (act == ReceiverAction::ACCEPTED) {
                    shared_medium.transmit_frame(ack_frame, ack_frame, sim_time + 0.005);
                    sender.process_ack(ack_frame.ack_num, sim_time + 0.005);
                } else {
                    // Repeat ACK on error or out-of-order
                    shared_medium.transmit_frame(ack_frame, ack_frame, sim_time + 0.005);
                }
            }
            sim_time += 0.05;
        }

        // 2. Check for GBN timeout
        if (sender.is_timed_out(sim_time)) {
            auto retx_list = sender.handle_timeout(sim_time);
            for (const auto& rf : retx_list) {
                DLLFrame rx_frame;
                TransmissionResult res = shared_medium.transmit_frame(rf, rx_frame, sim_time);
                if (res != TransmissionResult::LOST) {
                    DLLFrame ack_frame;
                    ReceiverAction act = receiver.receive_frame(rx_frame, ack_frame);
                    if (act == ReceiverAction::ACCEPTED) {
                        shared_medium.transmit_frame(ack_frame, ack_frame, sim_time + 0.005);
                        sender.process_ack(ack_frame.ack_num, sim_time + 0.005);
                    }
                }
                sim_time += 0.05;
            }
        }

        sim_time += 0.2;
    }

    std::cout << "\n" << Color::BOLD << Color::GREEN
              << "========================================================================================\n"
              << "  INTEGRATED SIMULATION COMPLETE!\n"
              << "  Total In-Order Packets Delivered: " << receiver.get_delivered_payloads().size() << " / " << TOTAL_PACKETS << "\n"
              << "  Total Retransmissions Triggered : " << sender.get_total_retransmissions() << "\n"
              << "  Total CRC Errors Caught         : " << receiver.get_crc_errors_count() << "\n"
              << "========================================================================================\n"
              << Color::RESET << "\n";
}

int main(int argc, char* argv[]) {
    print_banner();

    std::string pcap_output = "captures/dll_cpp_capture.pcap";
    PcapWriter pcap(pcap_output);
    std::cout << Color::CYAN << "[PCAP RECORDER] Capturing all frames to: " << pcap_output << Color::RESET << "\n";

    demo_error_control(pcap);
    demo_flow_control(pcap);
    demo_multiple_access(pcap);
    demo_integrated_simulation(pcap);

    pcap.close();
    std::cout << "\n" << Color::BOLD << Color::GREEN
              << "[DONE] Successfully generated " << pcap.get_packet_count()
              << " frames in " << pcap_output << "!\n"
              << "Ready for PyShark deep packet inspection.\n"
              << Color::RESET << std::endl;

    return 0;
}

