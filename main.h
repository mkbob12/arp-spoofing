
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

#define MAC_ADDR_LEN 6 
using namespace std; 



#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}


bool getIPAddress(const char* interface, char* ipAddress) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in* sin;

    // 소켓 생성
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return false;
    }

    // IP 주소 얻기
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        return false;
    }

    sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    inet_ntop(AF_INET, &(sin->sin_addr), ipAddress, INET_ADDRSTRLEN);

    close(sockfd);
    return true;
}




bool get_mac_address(const std::string& if_name, uint8_t *mac_addr_buf){
	string mac_addr;
	ifstream iface("/sys/class/net/" + if_name + "/address");
	string str((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());

	if(str.length() > 0){
		string hex = regex_replace(str, regex(":"),"");
		uint64_t result = stoull(hex,0,16);
		for(int i =0; i < MAC_ADDR_LEN; i++){
			mac_addr_buf[i] = (uint8_t) ((result & ((uint64_t) 0xFF << (i * 8))) >> (i * 8));
		}

		return true;
	}


	return false;

}

void get_ip_address(string(argv[1])){
	 int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    struct ifreq ifr{};
    strcpy(ifr.ifr_name, "wlo1");
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    char ip[INET_ADDRSTRLEN];
    strcpy(ip, inet_ntoa(((sockaddr_in *) &ifr.ifr_addr)->sin_addr));


	cout << ip << endl;

}