#include "packet.h"

int request(pcap_t* pcap, char* interface, u_int8_t *broad_mac,u_int8_t *attacker_mac, char *attacker_ip, u_int8_t *empty_mac,u_int8_t *target_ip, string type)
{
    EthArpPacket packet;
    
    if(type == "request"){
        packet.eth_.dmac_ = Mac(broad_mac);
        packet.eth_.smac_ = Mac(attacker_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.op_ = htons(ArpHdr::Request);

        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;

        packet.arp_.smac_ = Mac(attackder_mac);
        packet.arp_.sip_ = htonl(Ip(attacker_ip)); 

        packet.arp_.tmac_ = Mac(empty_mac);
        packet.arp_.tip_ = htonl(Ip(target_ip)); // 

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if(res !=0 ){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

    }

    if(type == "reply"){

    }


   return -1;


};


int reply(pcap_t* pcap,  char* interface, u_int8_t *dst_mac , u_int8_t *dst_ip){

    struct pcap_pkthdr *header;
    const u_char* reply_packet;
    
  

    while (true) {
        
            int result = pcap_next_ex(handle, &header, &reply_packet);

            if (result == 0) {
                continue;
            }
            if (result == -1 || result == -2) {
                break;
            }
            

            EthArpPacket* pArpPacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(reply_packet));

            // ARP reply 패킷인지 확인 및 target IP 확인
            // 
            if (ntohs(pArpPacket->eth_.type_) == EthHdr::Arp &&
                ntohs(pArpPacket->arp_.op_) == ArpHdr::Reply &&
                pArpPacket->arp_.tip_ == dst_mac &&
                pArpPacket->arp_.sip_ == packet.arp_.tip_) {

                // 받은 패킷에서 target MAC 주소 추출
                strcpy(dst_mac, std::string(pArpPacket->arp_.smac_).c_str());
                break;
            }
        }

    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);

    return -1;
};