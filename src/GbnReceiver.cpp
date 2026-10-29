#include "GbnReceiver.h"
#include "Color.h"
#include <iostream>
#include <iomanip>

GbnReceiver::GbnReceiver(const std::string& rx_mac, const std::string& tx_mac)
    : receiver_mac(rx_mac),
      sender_mac(tx_mac),
      expected_seq_num(0),
      last_ack_sent(-1),
      crc_errors_detected(0),
      out_of_order_drops(0) {}

ReceiverAction GbnReceiver::receive_frame(const DLLFrame& frame, DLLFrame& ack_frame) {
    uint32_t computed_fcs = 0;
    bool fcs_valid = frame.verify_integrity(&computed_fcs);

    // [1] CRC Error Check
    if (!fcs_valid || (frame.flags & FLAG_CORRUPTED)) {
        crc_errors_detected++;
        std::cout << "  " << Color::RED << Color::BOLD
                  << "[RX ERROR] CRC Check FAILED for Seq=" << frame.seq_num
                  << "! Computed FCS=0x" << std::hex << std::uppercase << computed_fcs
                  << " != Frame FCS=0x" << frame.fcs << Color::RESET << "\n";
        std::cout << "  " << Color::RED << "--> Action: DISCARDING damaged frame Seq="
                  << std::dec << frame.seq_num << ". Do NOT advance ACK." << Color::RESET << "\n";

        // If we have acknowledged previous frames, repeat the last ACK
        if (last_ack_sent >= 0) {
            ack_frame = DLLFrame(receiver_mac, sender_mac, FRAME_ACK, 0,
                                 static_cast<uint16_t>(last_ack_sent), 4, FLAG_NONE, "");
        } else {
            ack_frame = DLLFrame(receiver_mac, sender_mac, FRAME_NAK, 0, 0, 4, FLAG_NONE, "");
        }
        return ReceiverAction::DISCARDED_CRC_ERROR;
    }

    // [2] Sequence Number Check (Strict In-Order Acceptance)
    if (frame.seq_num == expected_seq_num) {
        // Correct In-Order Packet Received!
        delivered_payloads.push_back(frame.payload_as_string());
        last_ack_sent = expected_seq_num;
        expected_seq_num++;

        std::cout << "  " << Color::GREEN << Color::BOLD
                  << "[RX ACCEPT] In-order packet Seq=" << frame.seq_num
                  << " accepted! Payload: '" << frame.payload_as_string() << "'"
                  << Color::RESET << "\n";

        // Generate cumulative ACK
        ack_frame = DLLFrame(receiver_mac, sender_mac, FRAME_ACK, 0,
                             static_cast<uint16_t>(last_ack_sent), 4, FLAG_NONE, "");
        std::cout << "  " << Color::GREEN << "--> Action: Sending Cumulative ACK="
                  << last_ack_sent << " to sender." << Color::RESET << "\n";
        return ReceiverAction::ACCEPTED;
    } else {
        // Out-of-Order Packet Received
        out_of_order_drops++;
        std::cout << "  " << Color::MAGENTA << Color::BOLD
                  << "[RX OUT-OF-ORDER] Received Seq=" << frame.seq_num
                  << " but expected Seq=" << expected_seq_num << "!" << Color::RESET << "\n";
        std::cout << "  " << Color::MAGENTA << "--> Action: GBN rule DISCARDS frame Seq="
                  << frame.seq_num << ". Repeating ACK=" << last_ack_sent << "." << Color::RESET << "\n";

        if (last_ack_sent >= 0) {
            ack_frame = DLLFrame(receiver_mac, sender_mac, FRAME_ACK, 0,
                                 static_cast<uint16_t>(last_ack_sent), 4, FLAG_NONE, "");
        } else {
            ack_frame = DLLFrame(receiver_mac, sender_mac, FRAME_NAK, 0, 0, 4, FLAG_NONE, "");
        }
        return ReceiverAction::DISCARDED_OUT_OF_ORDER;
    }
}

void GbnReceiver::print_status() const {
    std::cout << "  " << Color::CYAN << "[GBN RECEIVER STATUS] " << Color::RESET
              << "ExpectedSeq: " << Color::BOLD << expected_seq_num << Color::RESET
              << " | LastAckSent: " << last_ack_sent
              << " | Total Delivered: " << delivered_payloads.size()
              << " | CRC Errors Detected: " << crc_errors_detected
              << " | Out-of-Order Discards: " << out_of_order_drops << "\n";
}

