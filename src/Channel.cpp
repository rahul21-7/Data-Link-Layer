#include "Channel.h"
#include "Crc.h"
#include "Color.h"
#include <iostream>

SharedChannel::SharedChannel(double ber, double plr, PcapWriter* writer)
    : bit_error_rate(ber),
      packet_loss_rate(plr),
      channel_busy(false),
      current_occupant(""),
      busy_until_time(0.0),
      concurrent_transmissions(0),
      rng(1337),
      dist(0.0, 1.0),
      pcap_writer(writer) {}

void SharedChannel::set_error_rates(double ber, double plr) {
    bit_error_rate = ber;
    packet_loss_rate = plr;
}

void SharedChannel::set_pcap_writer(PcapWriter* writer) {
    pcap_writer = writer;
}

bool SharedChannel::is_idle(double current_time) const {
    if (channel_busy && current_time < busy_until_time) {
        return false;
    }
    return true;
}

bool SharedChannel::request_transmission(const std::string& node_id, double current_time, double duration) {
    if (is_idle(current_time)) {
        channel_busy = true;
        current_occupant = node_id;
        busy_until_time = current_time + duration;
        concurrent_transmissions = 1;
        return true;
    } else {
        concurrent_transmissions++;
        return false;
    }
}

void SharedChannel::complete_transmission(const std::string& node_id) {
    if (current_occupant == node_id) {
        channel_busy = false;
        current_occupant = "";
        concurrent_transmissions = 0;
    }
}

TransmissionResult SharedChannel::transmit_frame(const DLLFrame& frame, DLLFrame& received_frame,
                                                 double current_time, bool force_corrupt) {
    // Record original frame in PCAP
    if (pcap_writer) {
        pcap_writer->write_frame(frame, current_time);
    }

    // Check packet loss
    if (dist(rng) < packet_loss_rate && !force_corrupt) {
        std::cout << "  " << Color::RED << "[CHANNEL LOSS] Frame " << frame.type_name()
                  << " dropped due to channel loss simulation." << Color::RESET << "\n";
        return TransmissionResult::LOST;
    }

    received_frame = frame;

    // Check error / corruption injection
    if (force_corrupt || dist(rng) < bit_error_rate) {
        // Corrupt frame payload or FCS
        std::vector<uint8_t> raw = frame.serialize();
        raw = CRC::inject_bit_flip(raw, 18 * 8 + 3); // flip a bit inside header/payload
        try {
            received_frame = DLLFrame::deserialize(raw);
            received_frame.flags |= FLAG_CORRUPTED;
        } catch (...) {
            // In case deserialization failed, invert FCS
            received_frame.fcs ^= 0xDEADBEEF;
            received_frame.flags |= FLAG_CORRUPTED;
        }

        std::cout << "  " << Color::YELLOW << "[CHANNEL NOISE] Noise injected into "
                  << frame.type_name() << " Seq=" << frame.seq_num
                  << " -> Bit flipped! FCS will fail at receiver." << Color::RESET << "\n";

        // Log corrupted frame into PCAP as well to inspect with PyShark
        if (pcap_writer) {
            pcap_writer->write_frame(received_frame, current_time + 0.001);
        }
        return TransmissionResult::CORRUPTED;
    }

    return TransmissionResult::SUCCESS;
}

void SharedChannel::reset() {
    channel_busy = false;
    current_occupant = "";
    busy_until_time = 0.0;
    concurrent_transmissions = 0;
}

