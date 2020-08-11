// net-address.h: Network addresses for capturing network packet
// Created by Creation Yun

/* Constants */
enum {
	MAC_ADDR_SIZE = 6,
	IPv4_ADDR_SIZE = 4
};

/* MAC Address */
#pragma pack(push, 1)
class MacAddr {
public:
	uint8_t mac[6];
 
	void print_mac_addr();
	int set_mac_addr(const char *addr);
	int set_mac_addr(MacAddr &addr);

	MacAddr();
	MacAddr(const char *addr);
	bool operator==(MacAddr &addr);
	bool operator==(const char *addr);
};
#pragma pack(pop)

/* IP Address */
#pragma pack(push, 1)
class IPv4Addr {
public:
	uint32_t ip;

	void print_ipv4_addr();
	int set_ipv4_addr(const char *addr);
	int set_ipv4_addr(IPv4Addr &addr);

	IPv4Addr();
	IPv4Addr(const char *addr);
	bool operator==(IPv4Addr &addr);
	bool operator==(const char *addr);
};
#pragma pack(pop)

