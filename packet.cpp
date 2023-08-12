#include "packet.h"



int request(pcap_t* handle, char* interface,  char* d_mac,  char* s_mac,  char* s_ip,  char* t_mac,  char* t_ip, string type)
{
    EthArpPacket packet;
    
    if(type == "request"){
        packet.eth_.dmac_ = Mac(d_mac);
        packet.eth_.smac_ = Mac(s_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.op_ = htons(ArpHdr::Request);

        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        
        packet.arp_.smac_ = Mac(s_mac);
        packet.arp_.sip_ = htonl(Ip(s_ip)); 
       
        packet.arp_.tmac_ = Mac(t_mac);
        packet.arp_.tip_ = htonl(Ip(t_ip)); 

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if(res !=0 ){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

    }

    if(type == "reply"){

        cout << "reply에 들어옴" << endl;

        packet.eth_.dmac_ = Mac(d_mac);
        packet.eth_.smac_ = Mac(s_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.op_ = htons(ArpHdr::Reply);

        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;

        
        packet.arp_.smac_ = Mac(s_mac);
        packet.arp_.sip_ = htonl(Ip(s_ip)); 
       
        packet.arp_.tmac_ = Mac(t_mac);
        packet.arp_.tip_ = htonl(Ip(t_ip)); 

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if(res !=0 ){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }


    }


   return -1;


};


// int reply(pcap_t* handle,  char *interface,  char* ip,  char *mac){
//         char *mac_temp;
        

//         while (true) {
//         struct pcap_pkthdr* header;
//         const u_char* reply_packet;
//         int result = pcap_next_ex(handle, &header, &reply_packet);
//         if (result == 0) {
//             continue;
//         }
//         if (result == -1 || result == -2) {
//             break;
//         }

//         EthArpPacket* pArpPacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(reply_packet));

//         // ARP reply 패킷인지 확인 및 target IP 확인
//         if (ntohs(pArpPacket->eth_.type_) == EthHdr::Arp &&
//             ntohs(pArpPacket->arp_.op_) == ArpHdr::Reply &&
//             pArpPacket->arp_.sip_ == ip) {

//             // 받은 패킷에서 target MAC 주소 추출
//             strcpy(mac_temp, std::string(pArpPacket->arp_.smac_).c_str());
//             break;
//         }
            
//     }
//        printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
// 	    mac_temp[0], mac_temp[1], mac_temp[2], mac_temp[3], mac_temp[4], mac_temp[5]);

//     return -1;
// };
