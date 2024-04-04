#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	for (int i = 0; i < rtable_len; i++)
    	if (rtable[i].prefix == (ip_dest & rtable[i].mask))
    		return &rtable[i];

	return NULL;
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	/* We can iterate thrpigh the mac_table for (int i = 0; i <
	 * mac_table_len; i++) */

	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];
	
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 1000000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	//  mac_table_len = parse_arp_table(mac_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* Check if we got an IPv4 packet */
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}
		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */
		
		int checksum_ret = ip_hdr->check;
		ip_hdr->check = 0;
		
		// checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != ntohs(checksum_ret))
			continue;
		
		ip_hdr->check = checksum_ret;
		
		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
		// if (best_route == NULL)
		// 	continue;
		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
		int ttl = ip_hdr->ttl;
		if (ttl >= 1)
			ip_hdr->ttl--;
		else 
			continue;

		int new_checksum = ~(~ip_hdr->check +  ~((uint16_t)ttl) + (uint16_t)ip_hdr->ttl) - 1;
		ip_hdr->check = new_checksum;

		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		
		// uint8_t mac[6];
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		struct arp_table_entry *ret = get_mac_entry(best_route->next_hop);	
		// for (int i = 0; i < 6; ++i) {
		// 	eth_hdr->ether_shost[i] = mac[i];
		// 	eth_hdr->ether_dhost[i] = ret->mac[i];
		// }
		memcpy(eth_hdr->ether_dhost, ret->mac, 6);
		send_to_link(best_route->interface, buf, len);
	}
}

