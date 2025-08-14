#ifndef RP_H
#define RP_H

#include "../node.h"

#include <vector>
#include <unordered_map>

// Structure to hold routing table entries
struct RoutingTableEntry {
    MACAddress next_hop;    // Next hop MAC address for reaching the destination IP
    size_t cost;            // Total distance istance for reaching destination IP in optimal path
    int remaining_time;     // Time until entry expires (validity time)
};

class RPNode : public Node {
    /*
     * XXX
     * Add any fields, helper functions etc here
     */

    // Routing table: maps destination IP to next-hop MAC, cost and validity time
    std::unordered_map<IPAddress, RoutingTableEntry> routing_table;

public:
    /*
     * NOTE You may not modify the constructor of this class
     */
    RPNode(Simulation* simul, MACAddress mac, IPAddress ip) : Node(simul, mac, ip) { }

    void send_segment(IPAddress dest_ip, std::vector<uint8_t> const& segment) const override;
    void receive_packet(MACAddress src_mac, std::vector<uint8_t> packet, size_t distance) override;
    void do_periodic() override;

private:
    void update_routing_table(IPAddress src_ip, std::unordered_map<IPAddress, RoutingTableEntry> const& neighbor_table, size_t link_weight);
    void broadcast_routing_table() const;
};

#endif
