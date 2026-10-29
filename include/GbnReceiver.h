#ifndef GBN_RECEIVER_H
#define GBN_RECEIVER_H

#include <vector>
#include <string>
#include "Frame.h"

enum class ReceiverAction {
    ACCEPTED,
    DISCARDED_CRC_ERROR,
    DISCARDED_OUT_OF_ORDER
};

class GbnReceiver {
private:
    std::string receiver_mac;
    std::string sender_mac;
    uint16_t expected_seq_num;
    int32_t last_ack_sent; // -1 if no packet received yet

    std::vector<std::string> delivered_payloads;
    size_t crc_errors_detected;
    size_t out_of_order_drops;

public:
    GbnReceiver(const std::string& rx_mac, const std::string& tx_mac);

    ReceiverAction receive_frame(const DLLFrame& frame, DLLFrame& ack_frame);

    uint16_t get_expected_seq() const { return expected_seq_num; }
    int32_t get_last_ack() const { return last_ack_sent; }
    size_t get_crc_errors_count() const { return crc_errors_detected; }
    size_t get_out_of_order_count() const { return out_of_order_drops; }
    const std::vector<std::string>& get_delivered_payloads() const { return delivered_payloads; }

    void print_status() const;
};

#endif // GBN_RECEIVER_H

