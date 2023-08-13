#pragma once 


#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string.h>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <unistd.h>


// get_mac_address 
#include <regex>
#include <string>
#include <fstream>
#include <streambuf>


using namespace std;

int get_mac_address(const std::string& if_name, uint8_t *mac_addr_buf);
int get_ip_address(char *interface, char *attacker_ip);
void to_hex_string(const unsigned char* bytes, size_t len, char* output);

void PrintArpInfo(EthArpPacket capture){

    printf("%s", " packet capture ");
    printf("pkt_dmac: %s\n", std::string(pkt.eth_.dmac_).c_str());
	printf("pkt_smac: %s\n", std::string(pkt.eth_.smac_).c_str());
	printf("ptk_arp_smac: %s\n", std::string(pkt.arp_.smac_).c_str());
	printf("pkt_sip: %s\n", std::string(pkt.arp_.sip_).c_str());
	printf("pkt_tmac: %s\n", std::string(pkt.arp_.tmac_).c_str());
	printf("pkt_tip: %s\n\n", std::string(pkt.arp_.tip_).c_str());


}

