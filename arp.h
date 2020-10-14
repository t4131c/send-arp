#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define MAC_ALEN 6
#define MAC_BROADCAST "ff:ff:ff:ff:ff:ff"
#define MAC_NULL "00:00:00:00:00:00"


Ip my_ip(const char* interface);
Mac my_mac(const char* interface);
void send_arp(pcap_t* handle, Mac eth_dmac, Mac eht_smac, ArpHdr::Operation todo, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);
EthArpPacket recv_arp(pcap_t* handle, Ip send_ip);
