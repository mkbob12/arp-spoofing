#include "packet.h"

EthArpPacket packet;

packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
packet.eth_.smac_ = Mac(attacker_mac);
packet.eth_.type_ = htons(EthHdr::Arp);

packet.arp_.hrd_ = htons(ArpHdr::ETHER);
packet.arp_.pro_ = htons(EthHdr::Ip4);
packet.arp_.op_ = htons(ArpHdr::Request);

packet.arp_.hln_ = Mac::SIZE;
packet.arp_.pln_ = Ip::SIZE;

packet.arp_.smac_ = Mac(attacker_mac);
packet.arp_.sip_ = htonl(Ip(attacker_ip));

packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
packet.arp_.tip_ = htonl(Ip(argv[2]));