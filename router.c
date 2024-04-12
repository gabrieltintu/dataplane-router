#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define DST_UNREACHABLE 0
#define TIME_EXCEEDED 1

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

/*
 Binary search through the sorted routing table.
 Returns a pointer to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	int low = 0;
	int high = rtable_len - 1;
	struct route_table_entry *best_match = NULL;

	while (low <= high) {
		int mid = low + (high - low) / 2;

		if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix) {
			best_match = &rtable[mid];
			// Move to the left side to search for a better match
			high = mid - 1;
		} else if ((ip_dest & rtable[mid].mask) > rtable[mid].prefix) {
			// Move to the left side
			high = mid - 1;
		} else {
			// Move to the right side
			low = mid + 1;
		}
	}

	return best_match;
}

int compare_func(const void *a, const void *b)
{
	struct route_table_entry *r_table_entry_1 = (struct route_table_entry *)a;
	struct route_table_entry *r_table_entry_2 = (struct route_table_entry *)b;

	// Sort by prefix and mask in a descending order
	if (r_table_entry_1->prefix > r_table_entry_2->prefix)
		return -1;
	else if (r_table_entry_1->prefix < r_table_entry_2->prefix)
		return 1;

	if (r_table_entry_1->mask > r_table_entry_2->mask)
		return -1;
	else if (r_table_entry_1->mask < r_table_entry_2->mask)
		return 1;
	else
		return 0;
}

void sort_rtable(void)
{
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_func);
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip)
{
	// Search for an entry that matches given_ip
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];

	return NULL;
}

/*
 Sends an ICMP message when destination is unreachable or time is exceeded.
*/
void send_icmp(struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *payload, int type, int interface)
{
	// Allocate the new buffer that will be sent
	size_t new_buf_size = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;
	char *new_buf = malloc(new_buf_size);
	DIE(!new_buf, "memory");

	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	size_t curr = 0;
	memcpy(new_buf, eth_hdr, sizeof(struct ether_header));

	curr += sizeof(struct ether_header);

	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
	DIE(!icmp_hdr, "memory");

	struct iphdr *ip_header = malloc(sizeof(struct iphdr));
	DIE(!ip_header, "memory");

	// Set the fields for the new IP header
	ip_header->tos = 0;
	ip_header->frag_off = 0;
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->id = 1;
	ip_header->ttl = 20;
	ip_header->protocol = 1;
	ip_header->tot_len = htons(new_buf_size - curr);
	uint32_t tmp = ip_header->daddr;
	ip_header->daddr = ip_hdr->saddr;
	ip_header->saddr = tmp;
	ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));

	memcpy(new_buf + curr, ip_header, sizeof(struct iphdr));
	curr += sizeof(struct iphdr);

	// Set the ICMP header fields accordingly
	if (type == DST_UNREACHABLE) {
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

	// Send the new buffer
	send_to_link(interface, new_buf, new_buf_size);

	free(new_buf);
	free(icmp_hdr);
	free(ip_header);
}

/*
 Sends an echo reply when the router receives an ICMP message of type
 echo request.
*/
void send_echo_reply(char *buf, struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct icmphdr *icmp_hdr, int len, int interface)
{
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	// Swap the source and destination addresses
	uint32_t tmp;
	tmp = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = tmp;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	icmp_hdr->type = 0;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - (sizeof(struct ether_header) + sizeof(struct iphdr))));

	// Send the buffer with the changed fields
	send_to_link(interface, buf, len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 1000000);
	DIE(!rtable, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(!arp_table, "memory");

	/* Read the static routing table and the ARP table */
	rtable_len = read_rtable(argv[1], rtable);

	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	sort_rtable();

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;

		/* Check if we got an IPv4 packet */
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		// Send echo reply
		if (ip_hdr->protocol == 1 && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			DIE(!icmp_hdr, "memory");

			if (icmp_hdr->type == 8) {
				send_echo_reply(buf, eth_hdr, ip_hdr, icmp_hdr, len, interface);
				continue;
			}
		}

		// Check the ip_hdr integrity with checksum and drop if not ok
		int checksum_ret = ip_hdr->check;
		ip_hdr->check = 0;

		if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != ntohs(checksum_ret))
			continue;

		ip_hdr->check = checksum_ret;

		// Find the best route
		// Send an ICMP message and drop if destination is unreachable

		size_t size = sizeof(struct ether_header) + sizeof(struct iphdr);

		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
		if (!best_route) {
			send_icmp(eth_hdr, ip_hdr, buf + size, DST_UNREACHABLE, interface);
			continue;
		}

		// Check time_to_live to avoid looping
		// Send ICMP and drop if time is exceeded
		int ttl = ip_hdr->ttl;

		if (ttl > 1) {
			ip_hdr->ttl--;
		} else {
			send_icmp(eth_hdr, ip_hdr, buf + size, TIME_EXCEEDED, interface);
			continue;
		}

		// Update the checksum after decreasing ttl
		int new_checksum = ~(~ip_hdr->check + ~((uint16_t)ttl) + (uint16_t)ip_hdr->ttl) - 1;
		ip_hdr->check = new_checksum;

		// Update the ethernet addresses
		uint8_t mac[6];

		get_interface_mac(best_route->interface, mac);
		struct arp_table_entry *ret = get_arp_entry(best_route->next_hop);
		if (!ret) {
			printf("No matching ARP entry found for destination IP\n");
			continue;
		}

		memcpy(eth_hdr->ether_dhost, ret->mac, 6);
		memcpy(eth_hdr->ether_shost, mac, 6);

		send_to_link(best_route->interface, buf, len);
	}

	free(rtable);
	free(arp_table);
}

