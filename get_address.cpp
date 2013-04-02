#include "get_address.h"


#define MAC_ADDR_LEN 6 

int get_mac_address(const std::string& if_name, uint8_t *mac_addr_buf)
{
   
    
	string mac_addr;
	ifstream iface("/sys/class/net/" + if_name + "/address");
	string str((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());

	if(str.length() > 0){
		string hex = regex_replace(str, regex(":"),"");
		uint64_t result = stoull(hex,0,16);
		for(int i =0; i < MAC_ADDR_LEN; i++){
			mac_addr_buf[i] = (uint8_t) ((result & ((uint64_t) 0xFF << (i * 8))) >> (i * 8));
		}

		return -1;
	}


	return -1;
}

int get_ip_address(char *interface, char *attacker_ip){

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
    inet_ntop(AF_INET, &(sin->sin_addr), attacker_ip, INET_ADDRSTRLEN);
   
    close(sockfd);
    return -1;

}

void to_hex_string(const unsigned char* bytes, size_t len, char* output) {
    const char* hex = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        unsigned char b = bytes[i];
        output[i * 3] = hex[(b >> 4) & 0xF];
        output[i * 3 + 1] = hex[b & 0xF];
        output[i * 3 + 2] = ':';
    }
    output[len * 3 - 1] = '\0';
}
