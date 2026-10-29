#include "GbnSender.h"
#include "Color.h"
#include <iostream>
#include <iomanip>

GbnSender::GbnSender(const std::string& src_mac, const std::string& dst_mac,
                     uint8_t win_size, double timeout)
    : sender_mac(src_mac),
      receiver_mac(dst_mac),
      window_size(win_size),
      base(0),
      next_seq_num(0),
      timeout_duration(timeout),
      timer_start_time(0.0),
      timer_running(false),
      total_retransmissions(0),
      total_packets_sent(0) {}

bool GbnSender::can_send() const {
    return next_seq_num < (base + window_size);
}

DLLFrame GbnSender::send_packet(const std::string& payload, double current_time) {
    if (!can_send()) {
        throw std::runtime_error("Cannot send: Sender window is full!");
    }

    DLLFrame frame(sender_mac, receiver_mac, FRAME_DATA, next_seq_num, 0, window_size, FLAG_NONE, payload);
    buffer.push_back(frame);

    if (!timer_running) {
        timer_running = true;
        timer_start_time = current_time;
    }

    next_seq_num++;
    total_packets_sent++;
    return frame;
}

bool GbnSender::process_ack(uint16_t cumulative_ack, double current_time) {
    // Cumulative ACK: ACK=k acknowledges all packets up to and including k
    if (cumulative_ack >= base && cumulative_ack < next_seq_num) {
        uint16_t old_base = base;
        base = cumulative_ack + 1;

        // Pop acknowledged frames from buffer
        size_t acked_count = base - old_base;
        for (size_t i = 0; i < acked_count && !buffer.empty(); ++i) {
            buffer.pop_front();
        }

        if (base == next_seq_num) {
            timer_running = false;
        } else {
            // Restart timer for remaining unacknowledged packets
            timer_running = true;
            timer_start_time = current_time;
        }
        return true;
    }
    // Duplicate or out-of-range ACK (ignored in standard GBN)
    return false;
}

bool GbnSender::is_timed_out(double current_time) const {
    return timer_running && ((current_time - timer_start_time) >= timeout_duration);
}

std::vector<DLLFrame> GbnSender::handle_timeout(double current_time) {
    std::vector<DLLFrame> retransmit_list;
    if (!timer_running) return retransmit_list;

    std::cout << "\n" << Color::RED << Color::BOLD
              << "  [!] GBN TIMER EXPIRED at t=" << std::fixed << std::setprecision(2)
              << current_time << "s for Base Packet Seq=" << base << "!" << Color::RESET << "\n";
    std::cout << Color::YELLOW << "  [↺] GOING BACK TO " << base
              << " -> Retransmitting ALL " << buffer.size() << " frames in current window: [";

    for (size_t i = 0; i < buffer.size(); ++i) {
        DLLFrame retx_frame = buffer[i];
        retx_frame.flags |= FLAG_RETRANSMISSION;
        retx_frame.fcs = retx_frame.compute_fcs(); // recompute FCS
        retransmit_list.push_back(retx_frame);
        std::cout << retx_frame.seq_num << (i + 1 < buffer.size() ? ", " : "");
        total_retransmissions++;
    }
    std::cout << "]\n" << Color::RESET;

    // Restart timer
    timer_start_time = current_time;
    return retransmit_list;
}

void GbnSender::print_window_state() const {
    std::cout << "  " << Color::CYAN << "[GBN SENDER WINDOW] " << Color::RESET
              << "Base: " << Color::BOLD << base << Color::RESET
              << " | NextSeq: " << Color::BOLD << next_seq_num << Color::RESET
              << " | Size: " << static_cast<int>(window_size)
              << " | In-Flight: " << buffer.size()
              << " | Available Slots: " << (window_size - (next_seq_num - base))
              << "\n  Window View: [";

    for (int i = std::max(0, static_cast<int>(base) - 2); i < base + window_size + 2; ++i) {
        if (i < base) {
            std::cout << Color::GREEN << i << "(ACKED)" << Color::RESET << " ";
        } else if (i < next_seq_num) {
            std::cout << Color::YELLOW << Color::BOLD << i << "(SENT)" << Color::RESET << " ";
        } else if (i < base + window_size) {
            std::cout << Color::WHITE << i << "(USABLE)" << Color::RESET << " ";
        } else {
            std::cout << "\033[90m" << i << "(OUT)" << Color::RESET << " ";
        }
    }
    std::cout << "]\n";
}

