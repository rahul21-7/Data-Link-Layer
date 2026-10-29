#ifndef CSMA_NODE_H
#define CSMA_NODE_H

#include <string>
#include <random>
#include <queue>
#include "Frame.h"
#include "Channel.h"
#include "PcapWriter.h"

enum class CsmaMode {
    ONE_PERSISTENT,
    NON_PERSISTENT,
    P_PERSISTENT,
    CSMA_CD
};

struct CsmaStats {
    size_t frames_attempted;
    size_t frames_succeeded;
    size_t collisions_detected;
    size_t jam_signals_sent;
    size_t backoffs_performed;
    size_t busy_channel_senses;
};

class CsmaNode {
private:
    std::string node_id;
    std::string mac_address;
    CsmaMode mode;
    double p_probability;
    double slot_time;

    int collision_counter;
    const int MAX_COLLISIONS = 16;

    std::mt19937 rng;
    std::uniform_real_distribution<double> uniform_dist;

    CsmaStats stats;
    std::queue<DLLFrame> tx_queue;

public:
    CsmaNode(const std::string& id, const std::string& mac,
             CsmaMode m = CsmaMode::CSMA_CD, double p_prob = 0.5, double slot = 0.05);

    void enqueue_frame(const DLLFrame& frame);
    bool has_frames_to_send() const { return !tx_queue.empty(); }

    // Execute one CSMA contention cycle
    bool attempt_transmission(SharedChannel& channel, double& current_time, PcapWriter* pcap_writer = nullptr);

    // Exponential backoff calculation
    double calculate_exponential_backoff();

    const std::string& get_id() const { return node_id; }
    const std::string& get_mac() const { return mac_address; }
    const CsmaStats& get_stats() const { return stats; }

    void print_stats() const;
};

#endif // CSMA_NODE_H

