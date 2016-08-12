#include "pcap.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )
FILE *a = fopen("mal_site.txt", "r"), *b = fopen("output.txt", "w");
char site[100][100];
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
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};
struct http_header
{
	u_char data[1000];
};
void packet_handle(u_char *param, const struct pcap_pkthdr *h, const u_char *data)
{
	int i, j, str;
	ether_header *EH = (ether_header *)data;
	if (EH->ether_type == 0x0800)
	{
		ip_header *IH = (struct ip_header*)(data + 14);
		if (IH->ip_protocol == 6)
		{
			tcp_header *TH = (struct tcp_header*)(data + (IH->ip_header_len) + 14);
			if (TH->dest_port == 0x0050)
			{
				http_header *HH = (http_header*)(data + (IH->ip_header_len) + (TH->data_offset) + 14);
				for (i = 3; ; i++)
				{
					if (HH->data[i - 3] == 'H' && HH->data[i - 2] == 'o' && HH->data[i - 1] == 's' && HH->data[i] == 't')
					{
						i += 3;
						break;
					}
				}
				str = i;
				for (i = 0; ; i++)
				{
					for (j = 0; ; j++)
					{
						if (HH->data[str + j] != site[i][j])
							break;
						if (HH->data[str + j] == 0x0d || site[i][j] == '\0')
							break;
					}
					if (HH->data[str + j] == 0x0d || site[i][j] == '\0')
						break;
				}
				fprintf(b, "%s", site[i]);
				printf("유해사이트 접속탐지\n");
			}
		}
	}
}
int main()
{
	pcap_if_t *allDevice, *device;
	char errorMSG[256], c;
	pcap_t *pickedDev;
	int i, j, che, cou;
	for (i = 0; ; i++)
	{
		cou = 0;
		j = 0;
		while (1)
		{
			che = fscanf(a, "%c", &c);
			if (c == '\n' || che == -1)
				break;
			if (c == '/')
			{
				cou++;
				continue;
			}
			if (cou < 2)
				continue;
			site[i][j++] = c;
		}
		site[i][j] = '\0';
		if (che == -1)
			break;
	}
	if ((pcap_findalldevs(&allDevice, errorMSG)) == -1)
		printf("장치 검색 오류");
	device = allDevice;
	pickedDev = pcap_open_live(device->name, 65536, 0, 1000, errorMSG);
	pcap_freealldevs(allDevice);
	pcap_loop(pickedDev, 0, packet_handle, NULL);
	return 0;
}