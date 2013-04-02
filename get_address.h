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

