#include "CsmaNode.h"
#include "Color.h"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <algorithm>

CsmaNode::CsmaNode(const std::string& id, const std::string& mac,
                   CsmaMode m, double p_prob, double slot)
    : node_id(id),
      mac_address(mac),
      mode(m),
      p_probability(p_prob),
      slot_time(slot),
      collision_counter(0),
      rng(std::hash<std::string>{}(id)),
      uniform_dist(0.0, 1.0),
      stats{0, 0, 0, 0, 0, 0} {}

void CsmaNode::enqueue_frame(const DLLFrame& frame) {
    tx_queue.push(frame);
}

double CsmaNode::calculate_exponential_backoff() {
    int max_exponent = std::min(collision_counter, 10);
    int max_slots = (1 << max_exponent) - 1;
    std::uniform_int_distribution<int> slot_dist(0, max_slots);
    int chosen_slot = slot_dist(rng);
    double backoff_seconds = chosen_slot * slot_time;

    stats.backoffs_performed++;
    std::cout << "    " << Color::YELLOW << "[BEB BACKOFF] Node " << node_id
              << " Collision #" << collision_counter << " (k=" << max_exponent
              << ", range [0.." << max_slots << "]) -> Selected Slot "
              << chosen_slot << " (" << std::fixed << std::setprecision(3)
              << (backoff_seconds * 1000.0) << " ms)" << Color::RESET << "\n";
    return backoff_seconds;
}

bool CsmaNode::attempt_transmission(SharedChannel& channel, double& current_time, PcapWriter* pcap_writer) {
    if (tx_queue.empty()) return false;

    DLLFrame& frame = tx_queue.front();
    stats.frames_attempted++;

    std::cout << "\n" << Color::BOLD << Color::CYAN
              << "[CSMA SENSE] Station " << node_id << " (" << mac_address
              << ") sensing medium at t=" << std::fixed << std::setprecision(3)
              << current_time << "s..." << Color::RESET << "\n";

    // 1. Carrier Sensing Phase
    bool channel_is_idle = channel.is_idle(current_time);

    if (!channel_is_idle) {
        stats.busy_channel_senses++;
        std::cout << "  " << Color::YELLOW << "[CARRIER SENSE] Channel is BUSY! Station "
                  << node_id << " defers transmission." << Color::RESET << "\n";

        if (mode == CsmaMode::ONE_PERSISTENT) {
            std::cout << "  [1-Persistent] Waiting until channel becomes IDLE to transmit.\n";
            current_time += slot_time;
            return false;
        } else if (mode == CsmaMode::NON_PERSISTENT || mode == CsmaMode::CSMA_CD) {
            double backoff = (uniform_dist(rng) * 4.0 + 1.0) * slot_time;
            std::cout << "  [Non-Persistent/CD] Channel busy, backing off for "
                      << std::fixed << std::setprecision(3) << (backoff * 1000.0) << " ms.\n";
            current_time += backoff;
            return false;
        } else if (mode == CsmaMode::P_PERSISTENT) {
            std::cout << "  [p-Persistent] Waiting for next time slot.\n";
            current_time += slot_time;
            return false;
        }
    }

    // Channel is IDLE
    std::cout << "  " << Color::GREEN << "[CARRIER SENSE] Channel is IDLE!" << Color::RESET << "\n";

    if (mode == CsmaMode::P_PERSISTENT) {
        double r = uniform_dist(rng);
        if (r > p_probability) {
            std::cout << "  [p-Persistent] Probability check failed (r=" << r
                      << " > p=" << p_probability << "). Deferring to next slot.\n";
            current_time += slot_time;
            return false;
        }
        std::cout << "  [p-Persistent] Probability check passed (r=" << r
                  << " <= p=" << p_probability << "). Proceeding to transmit.\n";
    }

    // 2. Medium Acquisition & Collision Detection
    double tx_duration = 0.08; // 80 ms transmission time
    bool acquired = channel.request_transmission(node_id, current_time, tx_duration);

    if (!acquired || channel.has_collision()) {
        // Collision Occurred!
        stats.collisions_detected++;
        collision_counter++;

        std::cout << "  " << Color::RED << Color::BOLD
                  << "[!] COLLISION DETECTED on shared bus during transmission by "
                  << node_id << "!" << Color::RESET << "\n";

        // Broadcast 32-bit Jam Signal
        stats.jam_signals_sent++;
        DLLFrame jam_frame(mac_address, "FF:FF:FF:FF:FF:FF", FRAME_JAM, 0, 0, 0, FLAG_NONE, "COLLISION_JAM_32BIT");
        std::cout << "  " << Color::MAGENTA << Color::BOLD
                  << "[JAM SIGNAL] Broadcasting 32-bit Jam Signal to notify all stations on bus!"
                  << Color::RESET << "\n";

        if (pcap_writer) {
            pcap_writer->write_frame(jam_frame, current_time + 0.002);
        }

        channel.reset();

        if (collision_counter > MAX_COLLISIONS) {
            std::cout << Color::RED << "  [ERROR] Exceeded maximum collisions ("
                      << MAX_COLLISIONS << ") for Node " << node_id << ". Dropping frame."
                      << Color::RESET << "\n";
            tx_queue.pop();
            collision_counter = 0;
            return false;
        }

        // Apply Truncated Binary Exponential Backoff
        double backoff_time = calculate_exponential_backoff();
        current_time += backoff_time;
        return false;
    }

    // 3. Successful Transmission
    std::cout << "  " << Color::GREEN << Color::BOLD
              << "[TX SUCCESS] " << node_id << " transmitted " << frame.summary()
              << Color::RESET << "\n";

    if (pcap_writer) {
        pcap_writer->write_frame(frame, current_time);
    }

    current_time += tx_duration;
    channel.complete_transmission(node_id);
    tx_queue.pop();
    collision_counter = 0;
    stats.frames_succeeded++;
    return true;
}

void CsmaNode::print_stats() const {
    std::cout << "  " << Color::CYAN << "[CSMA NODE " << node_id << " STATS]" << Color::RESET
              << " Attempted: " << stats.frames_attempted
              << " | Succeeded: " << stats.frames_succeeded
              << " | Collisions: " << stats.collisions_detected
              << " | Jam Signals: " << stats.jam_signals_sent
              << " | Backoffs: " << stats.backoffs_performed
              << " | Sensed Busy: " << stats.busy_channel_senses << "\n";
}

