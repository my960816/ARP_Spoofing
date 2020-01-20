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
struct tcp_header {

	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t nc : 1;
	uint16_t reserved : 3;
	uint16_t dataoffset : 4;
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t ecn : 1;
	uint16_t cwr : 1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgentp;

};
#pragma pack(pop)

//#pragma pack(push, 1)
//struct tcp2_header {
//
//	uint16_t src_port;
//	uint16_t dst_port;
//	uint32_t seq_num;
//	uint32_t ack_num;
//	uint16_t flag;
//	uint16_t window;
//	uint16_t checksum;
//	uint16_t urgentp;
//
//};
//#pragma pack(pop)

#pragma pack(push, 1)
struct pseudohdr {
	uint8_t Psrc_ip[IP_LEN];
	uint8_t Pdst_ip[IP_LEN];
	uint8_t Preser;
	uint8_t Pprotocol;
	uint16_t Plength; //tcp:(ip total lenth)-(ip header length)
};
#pragma pack(pop)

u_short ip_checksum(struct ipv4_header* buf, int len);
void tcp_checksum(struct ipv4_header* ip, struct tcp_header* tcp);

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

	while (1)
	{
		res = pcap_next_ex(adhandle, &header, &pkt_data);
		if (res == 0)
			continue;

		struct ether_header* eh;
		struct ipv4_header* ih;
		struct tcp_header* th;
		struct tcp2_header* th2;

		u_int ethlen = 0;

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
					th = (struct tcp_header*)(pkt_data + ethlen);

					if (ih->protocol == 0x06 && th->syn)
					{
						th2 = (struct tcp2_header*)(pkt_data + ethlen);

						uint16_t temp_port;

						struct pseudohdr pse;

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

						ih->checksum = htons(0);
						ih->t_length = htons(sizeof(*ih) + sizeof(*th));

						/*th2->flag = htons(0x5014);

						th2->checksum = 0;

						temp_port = th2->src_port;
						th2->src_port = th2->dst_port;
						th2->dst_port = temp_port;

						th2->ack_num = htonl(ntohl(th2->seq_num) + 1);
						th2->seq_num = htonl(0);*/

						th->dataoffset = 5;
						th->rst = 1;
						th->ack = 1;
						th->syn = 0;

						/*th->rst = 1;
						th->ack = 1;
						th->syn = 1;
						th->psh = 1;
						th->cwr = 1;
						th->ecn = 1;*/


						th->checksum = 0;

						temp_port = th->src_port;
						th->src_port = th->dst_port;
						th->dst_port = temp_port;

						th->ack_num = htonl(ntohl(th->seq_num) + 1);
						th->seq_num = htonl(0);




						int datalen = 0;


						ih->checksum = ip_checksum(ih, sizeof(*ih));


						uint8_t packet[2500] = { 0 };

						tcp_checksum(ih, th);


						//데이터 합치고 보내기.

						/*memcpy(packet, eh, sizeof(*eh));
						datalen += sizeof(*eh);
						memcpy(packet + datalen, ih, sizeof(*ih));
						datalen += sizeof(*ih);
						memcpy(packet + datalen, th2, sizeof(*th2));
						datalen += sizeof(*th2);*/

						memcpy(packet, eh, sizeof(*eh));
						datalen += sizeof(*eh);
						memcpy(packet + datalen, ih, sizeof(*ih));
						datalen += sizeof(*ih);
						memcpy(packet + datalen, th, sizeof(*th));
						datalen += sizeof(*th);

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

void tcp_checksum(struct ipv4_header* ip, struct tcp_header* tcp)
{
	unsigned short* pTcpH = (unsigned short*)tcp;
	unsigned short* tempIP;
	unsigned short dataLen = (ntohs(ip->t_length)) - sizeof(struct ipv4_header);
	unsigned short nLen = dataLen;

	unsigned chksum = 0;

	unsigned short finalchk;

	nLen >>= 1;
	tcp->checksum = 0;

	for (int i = 0; i < nLen; i++)
	{
		chksum += *pTcpH++;
	}

	if (dataLen % 2 == 1)
	{
		chksum += *pTcpH++ & 0x00ff;
	}

	tempIP = (USHORT*)(&ip->src_ip);
	for (int i = 0; i < 2; i++)
	{
		chksum += *tempIP++;
	}
	tempIP = (USHORT*)(&ip->dst_ip);
	for (int i = 0; i < 2; i++)
	{
		chksum += *tempIP++;
	}

	chksum += htons(6);

	chksum += htons(dataLen);

	chksum = (chksum >> 16) + (chksum & 0xffff);
	chksum += (chksum >> 16);

	finalchk = (~chksum & 0xffff);

	tcp->checksum = finalchk;
}