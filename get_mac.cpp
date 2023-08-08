#include "get_mac.h"

#define MAC_ADDR_LEN 6 

int get_mac_address(char* argv, uint8_t* mac_addr) {

    uint8_t temp_mac[6];

    snprintf(reinterpret_cast<char*>(mac_addr), MAC_ADDR_LEN * 3, "%02X:%02X:%02X:%02X:%02X:%02X",
        temp_mac[5], temp_mac[4], temp_mac[3], temp_mac[2], temp_mac[1], temp_mac[0]);

    std::string formatted_mac(reinterpret_cast<char*>(mac_addr));

    std::cout << "MAC Address: " << formatted_mac << std::endl;

    return -1;
}