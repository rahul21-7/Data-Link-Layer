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

    std::deque<DLLFrame> buffer; // frames currently in-flight or waiting for ACK
    size_t total_retransmissions;
    size_t total_packets_sent;

public:
    GbnSender(const std::string& src_mac, const std::string& dst_mac,
              uint8_t win_size = 4, double timeout = 2.0);

    bool can_send() const;
    DLLFrame send_packet(const std::string& payload, double current_time);

    bool process_ack(uint16_t cumulative_ack, double current_time);
    bool is_timed_out(double current_time) const;
    std::vector<DLLFrame> handle_timeout(double current_time);

    void print_window_state() const;

    uint16_t get_base() const { return base; }
    uint16_t get_next_seq() const { return next_seq_num; }
    uint8_t get_window_size() const { return window_size; }
    size_t get_total_retransmissions() const { return total_retransmissions; }
    size_t get_total_packets_sent() const { return total_packets_sent; }
    bool is_done(size_t total_expected) const { return base >= total_expected; }
};

#endif // GBN_SENDER_H

