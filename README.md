# Routing Protocol Implementation

## Overview

This lab implements standard routing protocols using Bellman Ford algorithm for efficient routing dealing with cases of node failure.

## Features

- **Dynamic Routing**: The protocol dynamically updates routing tables based on received packets.
- **Bellman-Ford Algorithm**: Utilizes the Bellman-Ford algorithm to compute the shortest path from each node to all other nodes.
- **Handling Node Failures**: Detects and responds to node failures by updating the routing tables accordingly.
- **Broadcasting Updates**: Periodically broadcasts the routing table to neighboring nodes to ensure all nodes have the latest routing information.
- **TTL Management**: Implements Time-To-Live (TTL) to prevent endless packet loops in the network.

## Mechanism

- Initially, all the nodes have their own routing data initialised in their routing tables. Later, due to periodic broadcast for initial set up, the routing tables are modified according to Bellman Ford Algorithm.
- A header is added to the segment to form a packet. The header contains crucial information about the packet for analysis. 
- The segment is sent only if the destination node entry in the routing table is not expired.
- When the packet is received by a node, it checks for a boolean flag of routing table update. If that flag is false then it is a normal packet. If the node is the destination node, the segment is received, otherwise is forwarded to the next hop node in the router table.
- In both sender and receiver functions, if there is no routing table entry, the packet is broadcasted to the neighbours.
- During the periodic function call when a node fails or establishes, the routing table is broadcasted as bytes in the form of packet. The receiver function deals with cases of infinite distance and discards the entry when the receivin node is the next hop. This along with TTL expiry system mitigates count-to-infinity problem.
