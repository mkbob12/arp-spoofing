#include "packet.h"
#include "get_address.h"
#include "ip.h"

#define MAC_ADDR_LEN 6 
using namespace std; 
EthArpPacket packet;

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
    u_int8_t attacker_mac[6];
    u_int8_t sender_mac[6];
    u_int8_t target_mac[6];
    u_int8_t broad_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    u_int8_t empty_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

    char attacker_ip[INET_ADDRSTRLEN]; 
    u_int8_t sender_ip[4];
    u_int8_t target_ip[4];

    char *interface = argv[1];
    -

    // =================== Get attacker mac, ip address ==========================
    get_mac_address(interface, attacker_mac);

    get_ip_address(interface, attacker_ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface,BUFSIZ,1,1,errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}    

   
    string type;
    

    request(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,target_ip, type);// gateway_mac request (attacekr -> gateway)
    reply(handle, interface, target_mac, target_ip); // reply : target_mac , target_ip 
    //reqeust(handle,interface,broad_mac,attacker_mac,attacker_ip,empty_mac,target_ip,request)
    // reply()

    // relay()
    // reinfect()




}

    

