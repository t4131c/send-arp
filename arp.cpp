#include "arp.h"


void send_arp(pcap_t* handle, Mac eth_dmac, Mac eth_smac, ArpHdr::Operation todo, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip){
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(todo);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		printf("pcap_sendpacket error=%s\n", pcap_geterr(handle));
	}
}

EthArpPacket recv_arp(pcap_t* handle, Ip send_ip){
	EthArpPacket *packet;
	struct pcap_pkthdr* header;
	const u_char * pkt_data ;
	int res;
	while((res=pcap_next_ex(handle, &header,&pkt_data))>=0){
		if(res == 0)
			continue;
		packet = (EthArpPacket*)pkt_data;
		if(packet -> eth_.type_ == htons(EthHdr::Arp) && packet -> arp_.op_ == htons(ArpHdr::Reply) && packet -> arp_.sip_ == Ip(htonl(send_ip))){
			break;
		}
	}
	return *packet;
}


Ip my_ip(const char* interface) {
    struct ifreq ifr;
    char ipstr[40];
    int s;
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
 
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("[*] Error");
        close(s);
        exit(0);
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
        printf("[*] my ip : %s\n", ipstr);
        close(s);
        return Ip(ipstr);
    }
 
    return 0;
}

Mac my_mac(const char* interface){
    struct ifreq ifr;
    char mac_addr[32]; 
    int s;
 
    s = socket(AF_INET, SOCK_STREAM, 0);
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
 
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        printf("[*] Error");
        close(s);
        exit(0);
    } else {
    	for (int i=0; i<MAC_ALEN; i++) 
            sprintf(&mac_addr[i*3],"%02x:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
        mac_addr[MAC_ALEN*3 - 1]='\0';
    	
    	printf("[*] my mac : %s\n", mac_addr);
    	close(s);
        return Mac(mac_addr);
    }
 
    return 0;
}
// int main(){
// 	my_ip("ens33");
// 	my_mac("ens33");
// 	//printf("%s\n",ip);
// }
