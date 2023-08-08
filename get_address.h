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

using namespace std;



int get_mac_address(char *argv, uint8_t *mac_addr);
int get_ip_address(char *interface, char *attacker_ip);

