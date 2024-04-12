### TINTU Gabriel-Claudiu 323CAb - 2023-2024

### PCOM - first assignment
# Dataplane-router

#### Solved the IPv4 and ICMP tasks

Start by parsing the routing and ARP table and sort the routing one in a
descending order.

In a loop, process every packet and check if it is an IPv4 and if the router
got an "Echo request".

## IPv4

Check the integrity of the IP header & the ttl and drop the packet if those
fields are not ok.
Use the function *get_best_route* to binary search (through the sorted routing
table) the IP address of the destination in order to determine the next hop
address. If there is no route drop the packet.
Recompute the checksum using the old ttl, new_ttl and old checksum.
Rewrite the ethernet header addresses so that the sent frame is correct.

## ICMP

3 types of ICMP messages can be sent:
1. Echo reply - sent when the router gets an echo request;
2. Destination unreachable - sent when there is sno route to the destination;
3. Time exceeded - sent if the packet is dropped due to the expiring of ttl;

For the first type check if the router got an "Echo request". If so call
*send_echo_reply*. The function properly changes the fields in the ip and
icmp headers such as: swapping the destination address, recomputing the
checksums and set the type for an "Echo reply".

For the destination unreachable and time exceeded call *send_icmp*. In the
function, create a new buffer that is going to be sent. The new buffer will
contain a new __ether header__, __ip header__, __icmp header__, the 
__ip header__ from the dropped packet, and 8 bytes from it.
Set the addresses from the ETH header, build the new IP header accordingly
and set the fields for the ICMP header corresponding to the message that
needs to be sent (TIME_EXCEEDED or DST_UNREACHABLE). Put the headers in the
new buffer and send it.