#include <cstdio>
#include <cstdint>
#include <pcap.h>
#include <netinet/in.h>
#include "protocol-hdr.h"

/* get IP version */
uint8_t IPv4::get_ip_version() {
	return ver_hdrlen >> 4;
}

/* get IP header length as byte */
uint8_t IPv4::get_ip_hdrlen() {
	return (ver_hdrlen & 0x0f) * 4;
}

/* get TCP header length */
uint8_t TCP::get_tcp_hdrlen() {
	return (uint8_t)(ntohs(hdrlen_flags) >> 12) * 4;
}

