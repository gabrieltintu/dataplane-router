#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define HOST_UNREACHABLE 0
#define TIME_EXCEEDED 1
#define ECHO_REPLY 2

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

int compare_masks_desc(const void *a, const void *b) {
    const struct route_table_entry *entry_a = (const struct route_table_entry *)a;
    const struct route_table_entry *entry_b = (const struct route_table_entry *)b;

    // Comparați măștile în ordine descrescătoare
    if (entry_a->mask > entry_b->mask) {
        return -1;
    } else if (entry_a->mask < entry_b->mask) {
        return 1;
    } else {
        return 0;
    }
}

void sort_rtable(void) {
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_masks_desc);
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

void send_icmp(struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *payload, int type, int interface) {
	char *new_buf = malloc(sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);

	// uint8_t temp[6];

	// memcpy(temp, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	// memcpy(eth_hdr->ether_dhost, temp, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	memcpy(new_buf, eth_hdr, sizeof(struct ether_header));

	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));

	struct iphdr *ip_header = malloc(sizeof(struct iphdr));
	
		if (type == ECHO_REPLY) {
		icmp_hdr->type = 0;
		icmp_hdr->code = 0;
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));
		memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
		memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, 8);
		send_to_link(interface, new_buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 8 );
	}	

	ip_header->tos = 0;
	ip_header->frag_off = htons(0);
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->id = htons(1);
	ip_header->ttl = 20;
	ip_header->protocol = 1;
	ip_header->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	ip_header->daddr = ip_hdr->saddr;
	ip_header->saddr = inet_addr(get_interface_ip(interface));
	ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));

	memcpy(new_buf + sizeof(struct ether_header), ip_header, sizeof(struct iphdr));

	if (type == HOST_UNREACHABLE) {
		icmp_hdr->type = 3;
		icmp_hdr->code = 0;
	} else if (type == TIME_EXCEEDED) {
		icmp_hdr->type = 11;
		icmp_hdr->code = 0;
	}

	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

	memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));

	memcpy(new_buf + sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr), payload, 8);

	send_to_link(interface, new_buf, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);


}

void send_echo_reply(char *buf, struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, int len, int interface) {


	// uint8_t temp[6];
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	// memcpy(eth_hdr->ether_dhost, temp, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	// memcpy(eth_hdr->ether_shost, temp, 6);

	// memcpy(new_buf, eth_hdr, sizeof(struct ether_header));


	// struct iphdr *ip_header = malloc(sizeof(struct iphdr));
	// memcpy(ip_header, ip_hdr, sizeof(struct iphdr));

	uint32_t tmp;
	tmp = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = tmp;
	// ip_header->daddr = ip_hdr->saddr;
	// ip_header->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// memcpy(new_buf + sizeof(struct ether_header), ip_header, sizeof(struct iphdr));

	icmp_hdr->type = 0;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - (sizeof(struct ether_header) + sizeof(struct iphdr))));

	// memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	// memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), buf + (len - sizeof(struct iphdr) - sizeof(struct ether_header) - sizeof(struct icmphdr)),
	//   len - sizeof(struct iphdr) - sizeof(struct ether_header) - sizeof(struct icmphdr));

	send_to_link(interface, buf, len);

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
	sort_rtable();
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

		/* Check if we got an IPv4 packet */
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}
		
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */
		
		if (ip_hdr->protocol == 1 && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (icmp_hdr->type == 8) {
				send_echo_reply(buf, eth_hdr, ip_hdr, icmp_hdr, len, interface);
				continue;
			}
		}


		int checksum_ret = ip_hdr->check;
		ip_hdr->check = 0;
		
		// checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != ntohs(checksum_ret))
			continue;
		
		ip_hdr->check = checksum_ret;
		

		// uint16_t checksum1 = ntohs(ip_hdr->check);
		// ip_hdr->check = 0;
		// uint16_t checksum2 = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

		// if (checksum1 != checksum2) {
		// 	printf("Wrong checksum\n");
		// 	continue;
		// }

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
		if (best_route == NULL) {
			send_icmp(eth_hdr, ip_hdr, buf + sizeof(struct ether_header) + sizeof(struct iphdr), HOST_UNREACHABLE, interface);

			continue;
		}
		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
		int ttl = ip_hdr->ttl;
		if (ttl > 1) {
			ip_hdr->ttl--;
		} else {
			send_icmp(eth_hdr, ip_hdr, buf + sizeof(struct ether_header) + sizeof(struct iphdr), TIME_EXCEEDED, interface);
			continue;
		}
		// aicii

		// ip_hdr->check = 0;
		// uint16_t checksum3 = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		// ip_hdr->check = checksum3;
		int new_checksum = ~(~ip_hdr->check +  ~((uint16_t)ttl) + (uint16_t)ip_hdr->ttl) - 1;
		ip_hdr->check = new_checksum;
		// ip_hdr->check = 0;
		// ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		
		// uint8_t mac[6];
		
		// get_interface_mac(best_route->interface, mac);
		struct arp_table_entry *ret = get_mac_entry(best_route->next_hop);
		if (ret == NULL) {
			printf("No matching MAC entry found for destination IP. Packet dropped.\n");
			continue;
		}	
		struct ether_header new_eth_hdr;
		get_interface_mac(best_route->interface, new_eth_hdr.ether_shost);
		memcpy(new_eth_hdr.ether_dhost, ret->mac, sizeof(ret->mac));
		new_eth_hdr.ether_type = htons(ETHERTYPE_IP);
		memcpy(buf, &new_eth_hdr, sizeof(new_eth_hdr));
		// for (int i = 0; i < 6; ++i) {
		// 	eth_hdr->ether_shost[i] = mac[i];
		// 	eth_hdr->ether_dhost[i] = ret->mac[i];
		// }
		// memcpy(eth_hdr->ether_dhost, ret->mac, 6);
		// memcpy(eth_hdr->ether_shost, mac, 6);		
		send_to_link(best_route->interface, buf, len);
	}
}

