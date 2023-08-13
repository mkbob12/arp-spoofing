#include "packet.h"

int request(pcap_t* handle, char* interface, char *dst_mac, char *src_mac, char *src_ip, char *t_mac, char *t_ip, string type)
{
    EthArpPacket packet;
    
    if(type == "request"){

        packet.eth_.dmac_ = Mac(dst_mac);
        packet.eth_.smac_ = Mac(src_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.op_ = htons(ArpHdr::Request);

        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        
        packet.arp_.smac_ = Mac(src_mac);
        packet.arp_.sip_ = htonl(Ip(src_ip)); 

        packet.arp_.tmac_ = Mac(t_mac);
        packet.arp_.tip_ = htonl(Ip(t_ip));
        
        cout << packet.arp_.tip_  << endl;

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if(res !=0 ){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

    

    }

    if(type == "reply"){

        packet.eth_.dmac_ = Mac(dst_mac);
        packet.eth_.smac_ = Mac(src_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.op_ = htons(ArpHdr::Request);

        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        
        packet.arp_.smac_ = Mac(src_mac);
        packet.arp_.sip_ = htonl(Ip(src_ip));  // 속일 ip 

        packet.arp_.tmac_ = Mac(t_mac);
        packet.arp_.tip_ = htonl(Ip(t_ip));
        
        cout << packet.arp_.tip_  << endl;

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if(res !=0 ){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

    }


   return -1;


};


int reply(pcap_t* handle,  char* interface, char *dst_mac , char *dst_ip){

    struct pcap_pkthdr *header;
    const u_char* packet;

    while (true) {
        
        int res = pcap_next_ex(handle, &header, &packet);
        if (res != 1)
        {
            printf("error!\n");
            return -1;
        }
        EthArpPacket *arppkt;
        arppkt = (EthArpPacket *)packet;

        if (arppkt->eth_.type_ == htons(EthHdr::Arp) && arppkt->arp_.pro_ == htons(EthHdr::Ip4) && (!memcmp(std::string(arppkt->arp_.sip_).c_str(), dst_ip, 4)))
        {
            strcpy(dst_mac, std::string(arppkt->arp_.smac_).c_str());
            break;
        }

            cout << "hello" << endl;
        }

    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);

    return -1;
};