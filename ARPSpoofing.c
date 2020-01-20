#include<WinSock2.h> // htons(), htonl() 함수를 사용
#include<pcap.h> // 네트워크 프로그래밍 함수를 제공
#include<stdio.h>
#include<stdint.h> // 여러 자료형을 정리하여 제공
#include<string.h>

#pragma warning(disable:4996)
#pragma warning(disable:6011)

#define ETH_LEN 6
#define IP_LEN 4

#define ETHERTYPE_ARP 0x0806

#pragma pack(push, 1)
struct ether_header
{
	uint8_t dst_host[ETH_LEN]; // uint8_t는 0~255까지의 범위를 갖는다. 
	uint8_t src_host[ETH_LEN];
	uint16_t ether_type; // uint16_t는 0~65,535 범위를 가짐.
};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_header
{
	uint16_t hw_type;
	uint16_t protocol_type;
	uint8_t hw_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t sebder_host[ETH_LEN];
	uint8_t sender_ip[IP_LEN];
	uint8_t target_host[ETH_LEN];
	uint8_t target_ip[IP_LEN];
};
#pragma pack(pop)

void make_arp_reply(uint8_t _packet[], int* _length) {
	struct ether_header eth;

	eth.dst_host[0] = 0x00;
	eth.dst_host[1] = 0x00;
	eth.dst_host[2] = 0x00;
	eth.dst_host[3] = 0x00;
	eth.dst_host[4] = 0x00;
	eth.dst_host[5] = 0x00;

	eth.src_host[0] = 0x00;
	eth.src_host[1] = 0x00;
	eth.src_host[2] = 0x00;
	eth.src_host[3] = 0x00;
	eth.src_host[4] = 0x00;
	eth.src_host[5] = 0x00;

	eth.ether_type = htons(ETHERTYPE_ARP);

	struct arp_header arp;

	arp.hw_type = htons(0x0001);
	arp.protocol_type = htons(0x0800);
	arp.hw_size = 0x06;
	arp.protocol_size = 0x04;
	arp.opcode = htons(0x0002);

	arp.sebder_host[0] = 0x00;
	arp.sebder_host[1] = 0x00;
	arp.sebder_host[2] = 0x00;
	arp.sebder_host[3] = 0x00;
	arp.sebder_host[4] = 0x00;
	arp.sebder_host[5] = 0x00;

	arp.sender_ip[0] = 0x00;
	arp.sender_ip[1] = 0x00;
	arp.sender_ip[2] = 0x00;
	arp.sender_ip[3] = 0x00;

	arp.target_host[0] = 0x00;
	arp.target_host[1] = 0x00;
	arp.target_host[2] = 0x00;
	arp.target_host[3] = 0x00;
	arp.target_host[4] = 0x00;
	arp.target_host[5] = 0x00;

	arp.target_ip[0] = 0x00;
	arp.target_ip[1] = 0x00;
	arp.target_ip[2] = 0x00;
	arp.target_ip[3] = 0x00;

	memcpy(_packet, &eth, sizeof(eth));
	*_length += sizeof(eth);

	memcpy(_packet + *_length, &arp, sizeof(arp));
	*_length += sizeof(arp);
}

int get_pcap_handle() {
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t* allDev;
	if (pcap_findalldevs(&allDev, errbuf) == PCAP_ERROR)
	{
		printf("[ERROR] pcap_findalldevs() : %s\n", errbuf);
		return NULL;
	}

	pcap_if_t* tempDev;
	int i = 0;
	for (tempDev = allDev; tempDev != NULL; tempDev = tempDev->next)
	{
		printf("%d. %s", ++i, tempDev->name);
		if (tempDev->description)
			printf("  (%s)\n", tempDev->description);
		else printf("\n");
	}

	int select;
	printf("select interface number (1-%d) : ", i);
	scanf_s("%d", &select);
	for (tempDev = allDev, i = 0; i < select - 1; tempDev = tempDev->next, i++);

	pcap_t* _handle = pcap_open(tempDev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (_handle == NULL)
	{
		printf("[ERROR] pcap_open() : %s\n", errbuf);
		return NULL;
	}
	pcap_freealldevs(allDev);
	return _handle;
}

void main() {



	pcap_t* dev_handle = get_pcap_handle();
	if (dev_handle == NULL)
	{
		printf("[ERROR] get_pcap_handle()\n");
		return -1;
	}

	uint8_t arp_packet[100] = { 0 };
	int arp_packet_len = 0;
	make_arp_reply(arp_packet, &arp_packet_len);
	for (int i = 0; i < 100; i++) {
		pcap_sendpacket(dev_handle, arp_packet, arp_packet_len);
		Sleep(1000);
	}

	return 0;
}
