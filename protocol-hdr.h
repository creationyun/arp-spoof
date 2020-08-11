// protocol-hdr.h: Network protocol header structures for capturing network packet
// Created by Creation Yun

#include "net-address.h"

/* Constants */
enum {
	ETH_HEADER_LEN = 14,
	ETH_TYPE_IPv4 = 0x0800,
	ETH_TYPE_ARP = 0x0806,
	IP_PROTO_TCP = 0x06,
	ARP_HTYPE_ETH = 1,
	ARP_PTYPE_IPv4 = 0x0800,
	ARP_OP_REQUEST = 1,
	ARP_OP_REPLY = 2
};

/* Ethernet header */
#pragma pack(push, 1)
class Ethernet {
public:
	MacAddr dst_mac_addr;
	MacAddr src_mac_addr;
	uint16_t eth_type;
};
#pragma pack(pop)

/* IPv4 header */
#pragma pack(push, 1)
class IPv4 {
public:
	uint8_t ver_hdrlen;
	uint8_t diff_services_field;
	uint16_t tot_len;
	uint16_t id;
	uint16_t flag_fragoffset;
	uint8_t ttl;
	uint8_t proto;
	uint16_t chksum;
	IPv4Addr src_ip_addr;
	IPv4Addr dst_ip_addr;
	
	uint8_t get_ip_version();
	uint8_t get_ip_hdrlen();
};
#pragma pack(pop)

/* TCP header */
#pragma pack(push, 1)
class TCP {
public:
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t hdrlen_flags;
	uint16_t win_size;
	uint16_t chksum;
	uint16_t urgent_ptr;
	
	uint8_t get_tcp_hdrlen();
};
#pragma pack(pop)

/* ARP header */
#pragma pack(push, 1)
class ARP {
public:
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t op;
	MacAddr sender_hw_addr;
	IPv4Addr sender_pr_addr;
	MacAddr target_hw_addr;
	IPv4Addr target_pr_addr;
};
#pragma pack(pop)

