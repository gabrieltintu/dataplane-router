#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define HOST_UNREACHABLE 0
#define TIME_EXCEEDED 1

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

	int low = 0;
    int high = rtable_len - 1;
    struct route_table_entry *best_match = NULL;

    while (low <= high) {
        int mid = low + (high - low) / 2;

        // Check if the current entry matches the destination IP address
        if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix) {
            // Update the best match if the current entry has a longer prefix
            best_match = &rtable[mid];
            // Continue searching for a longer match
            high = mid - 1;
        } else if ((ip_dest & rtable[mid].mask) > rtable[mid].prefix) {
            // If the prefix of the current entry is less than the masked destination IP
            // Move to the lower half of the table
            high = mid - 1;
        } else {
            // If the prefix of the current entry is greater than the masked destination IP
            // Move to the upper half of the table
            low = mid + 1;
        }
    }

    return best_match;
}

int compare_masks_desc(const void *a, const void *b) {
    struct route_table_entry *r_table_entry_1 = (struct route_table_entry *)a;
    struct route_table_entry *r_table_entry_2 = (struct route_table_entry *)b;

    // Comparați măștile în ordine descrescătoare
	if (r_table_entry_1->prefix > r_table_entry_2->prefix) {
		return -1;
	} else if (r_table_entry_1->prefix < r_table_entry_2->prefix) {
		return 1;
	} else {
		if (r_table_entry_1->mask > r_table_entry_2->mask) {
			return -1;
		} else if (r_table_entry_1->mask < r_table_entry_2->mask) {
			return 1;
		} else {
			return 0;
    	}
	}
}

void sort_rtable(void) {
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_masks_desc);
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
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
	size_t new_buf_size = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;
	char *new_buf = malloc(new_buf_size);

	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	size_t curr = 0;
	memcpy(new_buf, eth_hdr, sizeof(struct ether_header));

	curr += sizeof(struct ether_header);

	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));

	struct iphdr *ip_header = malloc(sizeof(struct iphdr));

	ip_header->tos = 0;
	ip_header->frag_off = htons(0);
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->id = htons(1);
	ip_header->ttl = 20;
	ip_header->protocol = 1;
	ip_header->tot_len = htons(new_buf_size - curr);
	uint32_t tmp = ip_header->daddr;
	ip_header->daddr = ip_hdr->saddr;
	ip_header->saddr = tmp;
	ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));

	memcpy(new_buf + curr, ip_header, sizeof(struct iphdr));
	curr += sizeof(struct iphdr);

	if (type == HOST_UNREACHABLE) {
		icmp_hdr->type = 3;
		icmp_hdr->code = 0;
	} else if (type == TIME_EXCEEDED) {
		icmp_hdr->type = 11;
		icmp_hdr->code = 0;
	}

	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

	memcpy(new_buf + curr, icmp_hdr, sizeof(struct icmphdr));
	curr += sizeof(struct icmphdr);

	memcpy(new_buf + curr, ip_hdr, sizeof(struct iphdr));
	curr += sizeof(struct iphdr);

	memcpy(new_buf + curr, payload, 8);

	send_to_link(interface, new_buf, new_buf_size);


}

void send_echo_reply(char *buf, struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, int len, int interface) {
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	uint32_t tmp;
	tmp = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = tmp;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));


	icmp_hdr->type = 0;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - (sizeof(struct ether_header) + sizeof(struct iphdr))));

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

		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != ntohs(checksum_ret))
			continue;
		
		ip_hdr->check = checksum_ret;


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

		int new_checksum = ~(~ip_hdr->check +  ~((uint16_t)ttl) + (uint16_t)ip_hdr->ttl) - 1;
		ip_hdr->check = new_checksum;
		
		/* TODO 2.4: Update the ethernet addresses. Use get_arp_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		
		
		uint8_t mac[6];
		
		get_interface_mac(best_route->interface, mac);
		struct arp_table_entry *ret = get_arp_entry(best_route->next_hop);
		if (ret == NULL) {
			printf("No matching MAC entry found for destination IP. Packet dropped.\n");
			continue;
		}
		

		memcpy(eth_hdr->ether_dhost, ret->mac, 6);
		memcpy(eth_hdr->ether_shost, mac, 6);
		
		send_to_link(best_route->interface, buf, len);
	}
}

