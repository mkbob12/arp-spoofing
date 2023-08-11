#pragma once // 컴파일러에게 해당 파일이 한번 빌드 


#include <cstdio>
#include <pcap.h>
#include<fstream>
#include <iostream>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <typeinfo>
#include <netinet/if_ether.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <regex>
#include "string.h"

using namespace std;



#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


int request(pcap_t* pcap, char* interface, u_int8_t *broad_mac,u_int8_t *attacker_mac, char *attacker_ip, u_int8_t *empty_mac, u_int8_t *target_ip, string type);
int reply(pcap_t* pcap,  char* interface, u_int8_t *target_mac, u_int8_t *target_ip);

// int relay();