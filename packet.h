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




#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

