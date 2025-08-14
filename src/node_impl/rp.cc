#include "rp.h"

#include <cassert>
#include <cstring>
#include<iostream>
using namespace std;

#define MAX_TTL 15
#define TIMEOUT 20

struct PacketHeader{

private:
    PacketHeader() = default;    // default constructor

public:
    IPAddress src_ip;        // source ip address in header
    IPAddress dest_ip;       // destination ip address in header
    size_t ttl;              // current ttl of the packet
    bool is_routing_update;       // flag for checking if packet is a routing table update

    // constructor of packet header
    PacketHeader(IPAddress src_ip, IPAddress dest_ip, bool is_routing_update = false, size_t ttl = MAX_TTL)    
        : src_ip(src_ip), dest_ip(dest_ip), ttl(ttl), is_routing_update(is_routing_update) {}

    // Function to extract the packet header from bytes
    static PacketHeader from_bytes(uint8_t const* bytes){
        PacketHeader ph;
        memcpy(&ph, bytes, sizeof(ph));
        return ph;
    }

    // Function to transform the packet header to bytes for transmission
    vector<uint8_t> to_bytes() const{
        vector<uint8_t> bytes(sizeof(*this));
        memcpy(&bytes[0], this, sizeof(*this));
        return bytes;
    }
};


void RPNode::send_segment(IPAddress dest_ip, vector<uint8_t> const& segment) const
{
    /*
    The function forms a packet from the segment by adding packet header and sends the packet towards destination node.

    dest_ip : IP address of the destination node
    segment : a vector of bytes denoting a segment

    */


    auto it = routing_table.find(dest_ip);           // iterating over the routing table to find destination ip

    // Constructing the packet (header + segment)
    PacketHeader header(ip, dest_ip);                             
    vector<uint8_t> packet(sizeof(header) + segment.size());      
    memcpy(&packet[0], &header, sizeof(header));
    memcpy(&packet[sizeof(header)], &segment[0], segment.size());

    if (it == routing_table.end())              // Broadcasting the packet to all neighbours if there is no routing table entry
        broadcast_packet_to_all_neighbors(packet, /*contains_segment*/ true);

    else{
        MACAddress next_hop = it->second.next_hop;   // Finding next-hop from routing table

        // Sending the packet to the next hop
        if(it->second.cost < INT32_MAX && it->second.cost > 0 && it->second.remaining_time > 0)  // Sending if destination node is not expired
            send_packet(next_hop, packet, /*contains_segment*/ true);
    }
}

void RPNode::receive_packet(MACAddress src_mac, vector<uint8_t> packet, size_t distance)
{
    /*
    This function receives a packet from a node.

    src_mac : MAC address of the immediate node sending the packet
    packet : a vector of bytes denoting a packet
    distance : Link weight of the routing link between the current node and the neighbouring node
    */

    PacketHeader header = PacketHeader::from_bytes(&packet[0]);   // Extracting packet header from received packet

    if (header.is_routing_update) {
        /*  
        As the packet is a routing table update, the routing table details of neighbour node
        is retreived and is used to update the routing table of the current node.
        */

        // Storing the routing table of neighbouring node
        unordered_map<IPAddress, RoutingTableEntry> neighbour_table;
        size_t offset = sizeof(header);
        
        while (offset < packet.size()){
            // Declaring all the necessary elements of the routing table
            IPAddress dest_ip;
            size_t cost;
            int remaining_time;
            MACAddress next_hop;

            // Extracting destination ip, cost, next hop and remaining time from the packet
            memcpy(&dest_ip, &packet[offset], sizeof(dest_ip));
            offset += sizeof(dest_ip);
            memcpy(&cost, &packet[offset], sizeof(cost));
            offset += sizeof(cost);
            memcpy(&remaining_time, &packet[offset], sizeof(remaining_time));
            offset += sizeof(remaining_time);
            memcpy(&next_hop, &packet[offset], sizeof(next_hop));
            offset += sizeof(next_hop);

            /* To mitigate the count-to-infinity problem, the routing table 
            entry is discarded if the current router is neighbour's next hop.
            */
            if(next_hop == mac) continue;

            // Updating routing table of neighbour with the extracted data
            neighbour_table[dest_ip] = {next_hop, cost, remaining_time};
        }

        // Updating the routing table of current node with the extracted neighbour's table
        update_routing_table(src_mac, neighbour_table, distance);
    } 
    else{
        /*
        As the packet is not a routing table update, it is normal packet
        which is meant to be sent or forwarded.
        */

        if (header.dest_ip == ip) {
            // The packet is for this node
            vector<uint8_t> segment(packet.begin() + sizeof(header), packet.end());
            receive_segment(header.src_ip, segment);   // The packet is received at the destination node
        } 
        else if (header.ttl == 0) {
            log("Packet dropped due to TTL expiration.");
        } 
        else {
            // The packet is not for this node, so forwarding it

            header.ttl--; // The TTL is decreased for ensuring no routing loops
            memcpy(&packet[0], &header, sizeof(header));  // Updating the packet with new TTL

            auto it = routing_table.find(header.dest_ip); // Iterating over the routing table to find destination ip
            if (it == routing_table.end())    // Broadcasting the packet if destination ip is not in routing table
                broadcast_packet_to_all_neighbors(packet, /*contains_segment*/ true);
            else{
                // Forwarding the packet to the next hop node
                MACAddress next_hop = it->second.next_hop;
                send_packet(next_hop, packet, /*contains_segment*/ true);
            }
        }
        
    }
}

void RPNode::do_periodic()
{
    /*
    This function broadcasts the routing table in case of link failure, link revival and initial set up.
    Besides, it also updates the validity time of a routing table entry.
    */
    
    // Decrement remaining_time for each routing table entry
    for (auto &it : routing_table){
        it.second.remaining_time--;
        if (it.second.remaining_time <= 0) {  // Node for which validity expires
            it.second.cost = INT32_MAX;       // Setting the distance as infinity
            it.second.remaining_time = -1;   // Setting validity time as a negative value for coding logic
        }
    }
    
    // Sending the routing table to all neighbours
    broadcast_routing_table();
}



// Bellman-Ford update using neighbour's routing table and link weights
void RPNode::update_routing_table(MACAddress src_mac, unordered_map<IPAddress, RoutingTableEntry> const& neighbour_table, size_t link_weight)
{
    /*
    This function updates its routing table by using Bellman-Ford algorithm.

    src_mac : MAC address of the immediate node sending the packet
    neighbour_table : a dictionary denoting the routing table of neighbour
    link_weight : Link weight of the routing link between the current node and the neighbouring node
    */

    // Iterating over the neighbour's routing table
    for (const auto& [dest_ip, neighbour_entry] : neighbour_table) {
        if (dest_ip == ip) continue;  // Skipping the destination node
        if (neighbour_entry.next_hop == mac) continue;  // Skipping the node if this is the next hop for avoiding count-to-infinity problem

        if (neighbour_entry.cost == INT32_MAX){     // case when neighbour entry is expired
            auto it = routing_table.find(dest_ip);   // iterating over the routing table of current node

            if(it == routing_table.end()) continue;   // No update if the entry is not present in routing table
            else if (routing_table[dest_ip].next_hop == src_mac) // Marking as expired if the neighbouring node is the next hop
                routing_table[dest_ip] = {src_mac, INT32_MAX, -1};
            else if (routing_table[dest_ip].next_hop == neighbour_entry.next_hop)  // Updating validity time when same next hops for better convergence
                routing_table[dest_ip].remaining_time = neighbour_entry.remaining_time;
            continue;
        }
        
        // Calculating new cost: cost to reach the neighbour + neighbour's cost to reach destination
        size_t new_cost;
        new_cost = link_weight + neighbour_entry.cost;
        
        // Updating the routing table only if this new path is shorter or if the destination isn't in the routing table
        if (routing_table.find(dest_ip) == routing_table.end() || new_cost < routing_table[dest_ip].cost)
            routing_table[dest_ip] = {src_mac, new_cost, neighbour_entry.remaining_time};  // Passing on the validity time for better convergence

        else if (neighbour_entry.next_hop == routing_table[dest_ip].next_hop)
            routing_table[dest_ip].remaining_time = neighbour_entry.remaining_time;  // Updating validity time when same next hops for better convergence
    }

}


void RPNode::broadcast_routing_table() const
{
    /*
    This function broadcasts the routing table in case of link failure, link revival and initial set up.
    */


    // Constructing the routing table broadcast packet with the routing table update flag set

    PacketHeader header(ip, 0, /*is_routing_update*/ true);    // Constructing the packet header
    vector<uint8_t> data = header.to_bytes();    // Transforming the header into a vector of bytes for suitable transmission
    
    // Initialising the default values of the routing table where the destination ip is the current ip
    size_t own_cost = 0;                              // Cost to itself is 0
    int own_remaining_time = TIMEOUT;                 // Setting validity time to maximum value
    MACAddress own_next_hop = mac;                    // Setting next hop as current mac address



    /*
    Adding these data to the routing data by type casting the variables to byte pointers
    */

    // Inserting own IP address
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&ip), reinterpret_cast<const uint8_t*>(&ip) + sizeof(ip));

    //Inserting own cost
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&own_cost), reinterpret_cast<const uint8_t*>(&own_cost) + sizeof(own_cost));

    // Inserting own validity time
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&own_remaining_time), reinterpret_cast<const uint8_t*>(&own_remaining_time) + sizeof(own_remaining_time));

    // Inserting own next hop
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&own_next_hop), reinterpret_cast<const uint8_t*>(&own_next_hop) + sizeof(own_next_hop));


    /*
    Iteratively adding every entry of the routing table to the routing data.
    The data is broadcasted here and filtered while receiving the packet.
    */

    for (const auto& [dest_ip, entry] : routing_table){

        // Inserting destination IP address
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&dest_ip), reinterpret_cast<const uint8_t*>(&dest_ip) + sizeof(dest_ip));

        // Inserting the total cost of reaching the destination IP address
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&entry.cost), reinterpret_cast<const uint8_t*>(&entry.cost) + sizeof(entry.cost));

        // Inserting the validity time for better convergence of routing table
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&entry.remaining_time), reinterpret_cast<const uint8_t*>(&entry.remaining_time) + sizeof(entry.remaining_time));

        // Inserting the next hop MAC address for the destination IP
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&entry.next_hop), reinterpret_cast<const uint8_t*>(&entry.next_hop) + sizeof(entry.next_hop));
    }


    // Broadcasting the routing table to all neighbours
    broadcast_packet_to_all_neighbors(data, /*contains_segment*/ false);
}