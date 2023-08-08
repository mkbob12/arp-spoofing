#include "main.h"
#include "get_mac.h"
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



    u_int8_t attacker_mac[6];
    u_int8_t sender_mac[6];
    u_int8_t target_mac[6];
    u_int8_t broad_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    u_int8_t attacker_ip[4];
    u_int8_t sender_ip[4];
    u_int8_t target_ip[4];

    char *interface = argv[1];
    get_mac_address(interface, attacker_mac);







}