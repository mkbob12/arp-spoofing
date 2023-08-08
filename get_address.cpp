#include "get_address.h"

#define MAC_ADDR_LEN 6 

int get_mac_address(char* argv, uint8_t* mac_addr) {

    uint8_t temp_mac[6];

    snprintf(reinterpret_cast<char*>(mac_addr), MAC_ADDR_LEN * 3, "%02X:%02X:%02X:%02X:%02X:%02X",
        temp_mac[5], temp_mac[4], temp_mac[3], temp_mac[2], temp_mac[1], temp_mac[0]);

    std::string formatted_mac(reinterpret_cast<char*>(mac_addr));

    std::cout << "MAC Address: " << formatted_mac << std::endl;

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
