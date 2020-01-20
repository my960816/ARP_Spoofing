#define _CRT_SECURE_NO_WARNINGS
#include<WinSock2.h>
#include<pcap.h>
#include<stdio.h>
#include<stdint.h>
#include<string.h>

#define ETH_LEN 6
#define IP_LEN 4

#pragma pack(push, 1)
struct ether_header {
	uint8_t dst_host[ETH_LEN];
	uint8_t src_host[ETH_LEN];
	uint16_t ether_type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ipv4_header
{
	uint8_t version : 4;
	uint8_t header_len : 4;
	uint8_t DSF;
	uint16_t t_length;
	uint16_t id;
	uint16_t flag;
	uint8_t time;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src_ip[IP_LEN];
	uint8_t dst_ip[IP_LEN];
};
#pragma pack(pop)

#pragma pack(push,1)
struct icmp_header
{
	uint8_t type;
	uint8_t code;
	uint16_t Ichecksum;
	uint16_t iden;
	uint16_t seq_num;
};
#pragma pack(pop)

u_short ip_checksum(struct ipv4_header* buf, int len);
u_short icmp_checksum(struct uint8_t* buf, int len);

int main(void)
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];


	struct pcap_pkthdr* header;
	const u_char* pkt_data;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);


	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,
		65536,

		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	while (1)
	{
		res = pcap_next_ex(adhandle, &header, &pkt_data);
		if (res == 0)
			continue;

		struct ether_header* eh;
		struct ipv4_header* ih;
		struct icmp_header* ich;

		const u_char* data=0;
		u_int ethlen = 0;
		uint8_t packet[2500] = { 0 };


		eh = (struct ether_header*)pkt_data;
		ethlen += sizeof(*eh);

		if (eh->src_host[0] == 0xd4 &&
			eh->src_host[1] == 0xbe &&
			eh->src_host[2] == 0xd9 &&
			eh->src_host[3] == 0x92 &&
			eh->src_host[4] == 0x38 &&
			eh->src_host[5] == 0x1f)
		{
			if (eh->ether_type == ntohs(0x0800))
			{
				ih = (struct ipv4_header*)(pkt_data + ethlen);
				ethlen += sizeof(*ih);

				if (ih->dst_ip[0] != 192 ||
					ih->dst_ip[1] != 168 ||
					ih->dst_ip[2] != 42 ||
					ih->dst_ip[3] != 20)
				{
					ich = (struct icmp_header*)(pkt_data + ethlen);
					ethlen += sizeof(*ich);
					

					if (ih->protocol == 0x01 && ich->type == 0x08)
					{
						
						data = (pkt_data + ethlen);
						
						
						printf("1.    %s\n", data+32);
						//printf("2.    %s\n", pkt_data+(sizeof(*eh)+sizeof(*ih));

						eh->src_host[0] = 0x00;
						eh->src_host[1] = 0xd8;
						eh->src_host[2] = 0x61;
						eh->src_host[3] = 0x36;
						eh->src_host[4] = 0x39;
						eh->src_host[5] = 0x28;

						eh->dst_host[0] = 0xd4;
						eh->dst_host[1] = 0xbe;
						eh->dst_host[2] = 0xd9;
						eh->dst_host[3] = 0x92;
						eh->dst_host[4] = 0x38;
						eh->dst_host[5] = 0x1f;


						ih->src_ip[0] = ih->dst_ip[0];
						ih->src_ip[1] = ih->dst_ip[1];
						ih->src_ip[2] = ih->dst_ip[2];
						ih->src_ip[3] = ih->dst_ip[3];

						ih->dst_ip[0] = 192;
						ih->dst_ip[1] = 168;
						ih->dst_ip[2] = 42;
						ih->dst_ip[3] = 5;


						ich->type = htons(0x00);
						
						uint8_t icmpa[500] = { 0 };
						uint8_t* icmpall=icmpa;
						int icmp_data_size = 0;
						u_int datalen = 0;
						//uint8_t add = NULL;

						

						//ih->t_length = htons(sizeof(*ih) + sizeof(*ich) + strlen((char*)data));
						ih->checksum = htons(0);
						ih->checksum = ip_checksum(ih, sizeof(*ih));//ip checksum ÇÔ¼ö

						ich->Ichecksum = htons(0x0000);
		

						icmp_data_size = (ntohs(ih->t_length)) - sizeof(*ih);

						memcpy(icmpall, ich, sizeof(*ich));
						//icmp_data_size += sizeof(*ich);
						memcpy(icmpall + sizeof(*ich), data,strlen((char*)data));
						//icmp_data_size += strlen((char*)data);
						//strcat((char*)(icmpall + sizeof(*ich)), (char*)data);
						ich->Ichecksum = icmp_checksum(icmpall, icmp_data_size);

						memcpy(packet, eh, sizeof(*eh));
						datalen += sizeof(*eh);
						memcpy(packet + datalen, ih, sizeof(*ih));
						datalen += sizeof(*ih);
						memcpy(packet + datalen, ich, sizeof(*ich));
						datalen += sizeof(*ich);
						memcpy(packet + datalen, data, strlen((char*)data));
						//datalen += strlen((char*)data);
						//memcpy(packet + datalen, &add, 1);
						//datalen += 1;
						//strcat((char*)(packet + datalen), (char*)data);

						//printf("2.    %s\n", data);

						pcap_sendpacket(adhandle, packet, header->len);

					}
					else
					{
						eh->dst_host[0] = 0x88;
						eh->dst_host[1] = 0x36;
						eh->dst_host[2] = 0x6c;
						eh->dst_host[3] = 0x7a;
						eh->dst_host[4] = 0x56;
						eh->dst_host[5] = 0x40;

						eh->src_host[0] = 0x00;
						eh->src_host[1] = 0xd8;
						eh->src_host[2] = 0x61;
						eh->src_host[3] = 0x36;
						eh->src_host[4] = 0x39;
						eh->src_host[5] = 0x28;


						uint8_t packet[2500] = { 0 };

						memcpy(packet, eh, sizeof(*eh));
						memcpy(packet + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

						pcap_sendpacket(adhandle, packet, header->len);
					}
				}
			}
			else {
				eh->dst_host[0] = 0x88;
				eh->dst_host[1] = 0x36;
				eh->dst_host[2] = 0x6c;
				eh->dst_host[3] = 0x7a;
				eh->dst_host[4] = 0x56;
				eh->dst_host[5] = 0x40;

				eh->src_host[0] = 0x00;
				eh->src_host[1] = 0xd8;
				eh->src_host[2] = 0x61;
				eh->src_host[3] = 0x36;
				eh->src_host[4] = 0x39;
				eh->src_host[5] = 0x28;


				uint8_t packet[2500] = { 0 };

				memcpy(packet, eh, sizeof(*eh));
				memcpy(packet + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

				pcap_sendpacket(adhandle, packet, header->len);
			}

		}
		
		}
		if (res == -1) {
			printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
			return -1;
	}
	return 0;
}

	u_short ip_checksum(struct ipv4_header* buf, int len)
	{
		uint16_t* alldata = (uint16_t*)buf;
		uint32_t sum;
		for (sum = 0; len > 0; len -= 2)
			sum += *alldata++;
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);

		return ~sum;
	}


	u_short icmp_checksum(uint8_t* buf, int len)
	{
		uint16_t* alldata = (uint16_t*)buf;
		uint32_t sum;
		for (sum = 0; len > 0; len -= 2)
			sum += *alldata++;
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);

		return ~sum;
	}