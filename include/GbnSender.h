#ifndef GBN_SENDER_H
#define GBN_SENDER_H

#include <vector>
#include <string>
#include <deque>
#include "Frame.h"

class GbnSender {
private:
    std::string sender_mac;
    std::string receiver_mac;
    uint8_t window_size;
    uint16_t base;
    uint16_t next_seq_num;

    double timeout_duration;
    double timer_start_time;
    bool timer_running;

    // Innovative Feature: Layer-2 Fast Retransmit via 3 Duplicate ACKs
    int32_t last_ack_received;
    int dup_ack_count;
    bool fast_retransmit_enabled;

    std::deque<DLLFrame> buffer; // frames currently in-flight or waiting for ACK
    size_t total_retransmissions;
    size_t total_packets_sent;
    size_t fast_retransmissions_triggered;

public:
    GbnSender(const std::string& src_mac, const std::string& dst_mac,
              uint8_t win_size = 4, double timeout = 2.0, bool enable_fast_retx = true);

    bool can_send() const;
    DLLFrame send_packet(const std::string& payload, double current_time);

    // Returns true if ACK advanced window. If fast retransmission is triggered, fills out_fast_retx
    bool process_ack(uint16_t cumulative_ack, double current_time, std::vector<DLLFrame>* out_fast_retx = nullptr);
    bool is_timed_out(double current_time) const;
    std::vector<DLLFrame> handle_timeout(double current_time);

    void print_window_state() const;

    uint16_t get_base() const { return base; }
    uint16_t get_next_seq() const { return next_seq_num; }
    uint8_t get_window_size() const { return window_size; }
    size_t get_total_retransmissions() const { return total_retransmissions; }
    size_t get_total_packets_sent() const { return total_packets_sent; }
    size_t get_fast_retransmissions() const { return fast_retransmissions_triggered; }
    bool is_done(size_t total_expected) const { return base >= total_expected; }
    void set_fast_retransmit(bool enable) { fast_retransmit_enabled = enable; }
};

#endif // GBN_SENDER_H

