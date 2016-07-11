#include "pcap.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )
struct ipaddress
{
	u_char ip1;
	u_char ip2;
	u_char ip3;
	u_char ip4;
};
struct ether_header
{
	u_char src[6];
	u_char des[6];
	unsigned short ether_type;
};
struct ip_header
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	struct ipaddress ip_srcaddr;
	struct ipaddress ip_destaddr;
};
struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
};
void packet_handle(u_char *param, const struct pcap_pkthdr *h, const u_char *data)
{
	ether_header *EH = (ether_header *)data;
	ip_header *IH = (struct ip_header*)(data + 14); 
	tcp_header *TH = (struct tcp_header*)(data + (IH->ip_header_len)+14);
	if (ntohs(EH->ether_type) == 0x0800)
	{
		if (IH->ip_protocol==6)
		{
			printf("┌─────────────────────────\n");
			printf("├Src MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->src[0], EH->src[1], EH->src[2], EH->src[3], EH->src[4], EH->src[5]);//송신자 MAC
			printf("├Dst MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", EH->des[0], EH->des[1], EH->des[2], EH->des[3], EH->des[4], EH->des[5]);//수신자 MAC
			printf("├Src IP  : %d.%d.%d.%d\n", IH->ip_srcaddr.ip1, IH->ip_srcaddr.ip2, IH->ip_srcaddr.ip3, IH->ip_srcaddr.ip4);
			printf("├Dst IP  : %d.%d.%d.%d\n", IH->ip_destaddr.ip1, IH->ip_destaddr.ip2, IH->ip_destaddr.ip3, IH->ip_destaddr.ip4);
			printf("├Src Port: %d\n", TH->source_port);
			printf("├Dst Port: %d\n", TH->dest_port);
			printf("└─────────────────────────\n");
		}
	}
}
int main()
{
	pcap_if_t *allDevice, *device; 
	char errorMSG[256];
	int count = 0, choice;
	pcap_t *pickedDev;
	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)
		printf("장치 검색 오류");
	for (device = allDevice; device != NULL; device = device->next)
	{
		printf("┌%d 번 네트워크 카드───────────────────────────\n", count);
		printf("│어댑터 정보 : %s\n", device->name);
		printf("│어댑터 설명 : %s\n", device->description);
		printf("└────────────────────────────────────\n");
		count = count + 1;
	}
	printf("패킷을 수집할 네트워크 카드를 선택 하세요 : ");
	device = allDevice;
	scanf_s("%d", &choice);
	for (count = 0; count < choice; count++)
		device = device->next;
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, errorMSG);
	pcap_freealldevs(allDevice);
	pcap_loop(pickedDev, 0, packet_handle, NULL);
	return 0;
}