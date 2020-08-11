#include <cstdio>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include "net-address.h"

/* print MAC address */
void MacAddr::print_mac_addr() {
	for (int i = 0; i < 6; i++) {
		printf("%02x", mac[i]);
		if (i != 5) printf(":");
	}
}

/* set MAC address */
int MacAddr::set_mac_addr(const char *addr) {
	uint8_t _mac[6];
	int res = sscanf(addr, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		&_mac[0], &_mac[1], &_mac[2], &_mac[3], &_mac[4], &_mac[5]);
	
	if (res != 6) {
		fprintf(stderr, "Error: cannot convert %s to MAC address.\n", addr);
		return -1;
	}
	
	for (int i = 0; i < 6; i++) {
		mac[i] = _mac[i];
	}
	
	return 0;
}

int MacAddr::set_mac_addr(MacAddr &addr) {
	for (int i = 0; i < 6; i++) {
		mac[i] = addr.mac[i];
	}

	return 0;
}

/* Constructor of MacAddr */
MacAddr::MacAddr() {
	mac[0] = mac[1] = mac[2]
	= mac[3] = mac[4] = mac[5] = 0;
}

MacAddr::MacAddr(const char *addr) {
	set_mac_addr(addr);
}

/* Operator of MacAddr */
bool MacAddr::operator==(MacAddr &addr) {	
	bool ret = true;
	for (int i = 0; i < 6; i++) {
		ret = ret && mac[i] == addr.mac[i];
	}
	
	return ret;
}

bool MacAddr::operator==(const char *addr) {
	MacAddr mac_addr(addr);
	
	bool ret = true;
	for (int i = 0; i < 6; i++) {
		ret = ret && mac[i] == mac_addr.mac[i];
	}
	
	return ret;
}

/* print IP address */
void IPv4Addr::print_ipv4_addr() {
	uint32_t addr = ntohl(ip);
	printf("%d.%d.%d.%d",
		(addr & 0xFF000000) >> 24,
		(addr & 0x00FF0000) >> 16,
		(addr & 0x0000FF00) >> 8,
		(addr & 0x000000FF)
	);
}

/* set IP address */
int IPv4Addr::set_ipv4_addr(const char *addr) {
	uint8_t ip0, ip1, ip2, ip3;
	int res = sscanf(addr, "%hhu.%hhu.%hhu.%hhu",
		&ip0, &ip1, &ip2, &ip3);
	
	if (res != 4) {
		fprintf(stderr, "Error: cannot convert %s to IP address.\n", addr);
		return -1;
	}
	
	ip = (ip0 << 24) | (ip1 << 16) | (ip2 << 8) | ip3;
	ip = htonl(ip);  // convert to network byte order
	
	return 0;
}

int IPv4Addr::set_ipv4_addr(IPv4Addr &addr) {
	ip = addr.ip;

	return 0;
}

/* Constructor of IPv4Addr */
IPv4Addr::IPv4Addr() {
	ip = 0u;
}

IPv4Addr::IPv4Addr(const char *addr) {
	set_ipv4_addr(addr);
}

/* Operator of IPv4Addr */
bool IPv4Addr::operator==(IPv4Addr &addr) {	
	return ip == addr.ip;
}

bool IPv4Addr::operator==(const char *addr) {
	IPv4Addr ip_addr(addr);
	
	return ip == ip_addr.ip;
}
