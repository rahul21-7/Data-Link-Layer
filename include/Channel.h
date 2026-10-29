#ifndef CHANNEL_H
#define CHANNEL_H

#include <string>
#include <vector>
#include <random>
#include "Frame.h"
#include "PcapWriter.h"

enum class TransmissionResult {
    SUCCESS,
    CORRUPTED,
    LOST,
    COLLISION
};

class SharedChannel {
private:
    double bit_error_rate;
    double packet_loss_rate;
    bool channel_busy;
    std::string current_occupant;
    double busy_until_time;
    int concurrent_transmissions;

    std::mt19937 rng;
    std::uniform_real_distribution<double> dist;
    PcapWriter* pcap_writer;

public:
    SharedChannel(double ber = 0.0, double plr = 0.0, PcapWriter* writer = nullptr);

    void set_error_rates(double ber, double plr);
    void set_pcap_writer(PcapWriter* writer);

    // Carrier Sensing
    bool is_idle(double current_time) const;
    bool request_transmission(const std::string& node_id, double current_time, double duration);
    void complete_transmission(const std::string& node_id);

    // Frame Transmission over Channel
    TransmissionResult transmit_frame(const DLLFrame& frame, DLLFrame& received_frame,
                                      double current_time, bool force_corrupt = false);

    bool has_collision() const { return concurrent_transmissions > 1; }
    void reset();
};

#endif // CHANNEL_H

