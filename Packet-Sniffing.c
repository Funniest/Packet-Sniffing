#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include "pcap.h" 

#define ETHER_ADDR_LEN 6

// save MAC Address sturct 
typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;

// Ethernet header (d_mac_addr,s_mac_addr,packet type ethernet header) struct
struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; // d_mac_addr
	u_char ether_shost[ETHER_ADDR_LEN]; // s_mac_addr
	u_short ether_type; // packet type
}eth;

// save IP address struct
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

//ip header
typedef struct ip_header {
	u_char ver_ihl;
	u_char tos; // Type of Service
	u_short tlen; // size
	u_short identification; // Identification
	u_short flags_fo; // flag(3bits) + flag offset(13bits)
	u_char ttl; // Time to Live TTL
	u_char proto; // protocol
	u_short crc; // IP header CRC check sum
	ip_address saddr; // src IP    
	ip_address daddr; // des IP
	u_int op_pad; // option and padding
}ip_header;

typedef struct tcp_header {
	u_short sport; // Source port
	u_short dport; // Destination port
	u_int seqnum; // Sequence Number
	u_int acknum; // Acknowledgement number
	u_char th_off; // Header length
	u_char flags; // packetflags(SYN, ACK, PSH, FIN...)
	u_short win; // Window size, recv size
	u_short crc; // Header Checksum
	u_short urgptr; // Urgent pointer
}tcp_header;

typedef struct udp_header {
	u_short sport; // Source port
	u_short dport; // Destination port
	u_short len; // Datagram length
	u_short crc; // Checksum
}udp_header;

pcap_t* getDeviceList();
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void ErrorMessage(char* str);

int main() {
	pcap_t *adhandle;

	//select device
	adhandle = getDeviceList();

	pcap_loop(adhandle, // 선택한 디바이스 open한 핸들
		0,  // 무한루프로 계속 캡쳐할 것을 의미
		packet_handler, // 패킷이 캡쳐 되면 패킷 처리를 위한 콜백방식의 패킷 핸들러 정의
		NULL); // 패킷 데이터 포인터인데 보통 NULL

	pcap_close(adhandle); // 디바이스 핸들 close
	return 0;
}

pcap_t* getDeviceList() {
	pcap_if_t *device_list;
	int select_num = 0;
	pcap_t *pcap_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask = 0;

	char packet_filter[] = ""; // packet filetering(ex; tcp, udp, src foo(발신지 foo), ip or udp)
	struct bpf_program fcode; // protocol information save

	if (pcap_findalldevs(&device_list, errbuf) == -1)
		ErrorMessage("pcap_findalldevs error");

	//device list print
	int num = 0;
	for (pcap_if_t *i = device_list; i != NULL; i = i->next, num++) {
		printf("[%d] %s ", num, device_list->description); //device name
		if (i->description) //if deivce description != NULL
			printf("(%s)\n", i->description);
		else
			printf("(UnKonow)\n");
	}

	//No device list
	if (num == 0)
		ErrorMessage("Device Not found");

	printf("select device number >> ");
	scanf("%d", &select_num);

	//exception
	if (select_num < 0 || select_num > num) {
		//device list free
		pcap_freealldevs(device_list);
		ErrorMessage("select fail");
	}

	//find device
	int i = 0;
	pcap_if_t *device;
	for (device = device_list; i < select_num; device = device->next, i++);

	//device open and Defining Packet Collection Methods
	//pcap_open_live(device name, read packet size, mode, time out, error buffer)
	if ((pcap_handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf)) == NULL) {
		pcap_freealldevs(device_list);
		ErrorMessage("pcap_open_live error");
	}

	//pcap_compile(handle, bpf_program* rule, filtering rule,optimization, netmask)
	if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) <0){
		pcap_freealldevs(device_list);
		ErrorMessage("pcap_compile error");
	}

	printf("\nlistening on %s...\n", device->description);

	//device free
	pcap_freealldevs(device_list);

	//return device handle
	return pcap_handle;
}

// handler
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	int i;
	// (ethernet=14byte next IP header, ether_type=0x0800=IP_HEADER)
	ip_header * ih;
	u_int ip_len;
	ih = (ip_header*)(pkt_data + 14); // IP header start posi
	ip_len = (ih->ver_ihl & 0xf) * 4; // IP header length (IHL=1 4byte) // using &0xf Header bit field length extraction
	tcp_header *th;
	th = (tcp_header*)((u_char*)ih + ip_len); // TCP header start posi = ih + Variable length IP header next if ih->proto=6 TCP

	udp_header *uh;
	uh = (udp_header*)((u_char*)ih + ip_len);

	// packet data
	time_t local_tv_sec;
	struct tm * ltime;
	char timestr[16];

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	// ehternet packet
	printf("=====================Ethernet Packet ==================================\n\n");
	printf("%s.%.6d \n\n", timestr, header->ts.tv_usec); // 시스템 시간 출력
														 /*
														 struct pcap_pkthdr{
														 struct timeval ts; // 패킷이 캡쳐된 시간정보
														 bpf_u_int32 caplen; // 수집된 패킷 길이(os커널에서 사용자 모드로 넘어온 실제 패킷 길이=이더넷헤더14byte+IP헤더 20byte+ TCP(UDP)헤더 20byte=54byte)
														 bpf_u_int32 len; // 실제 패킷 길이
														 }header;
														 */

														 // 이더넷 헤더
	mac *srcmac;
	mac *destmac;
	destmac = (mac *)pkt_data;
	srcmac = (mac *)(pkt_data + 6);

	// smac, dmac 출력
	printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n\n",
		srcmac->byte1,
		srcmac->byte2,
		srcmac->byte3,
		srcmac->byte4,
		srcmac->byte5,
		srcmac->byte6,

		destmac->byte1,
		destmac->byte2,
		destmac->byte3,
		destmac->byte4,
		destmac->byte5,
		destmac->byte6);

	// IP hedaer
	ih = (ip_header *)(pkt_data + 14);
	ip_len = (ih->ver_ihl & 0xf) * 4; //length of ethernet header

									  // TCP header
	th = (tcp_header *)((u_char*)ih + ip_len);

	// UDP header
	uh = (udp_header*)((u_char*)ih + ip_len);

	// number 6 means TCP
	if (ih->proto == 6)
	{

		// src ip, dst ip print
		printf("%d.%d.%d.%d (%d)-> %d.%d.%d.%d (%d), flag: %04x\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			ntohs(th->sport), // src port litle->big

			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			ntohs(th->dport), // dst port
			th->flags);

		printf(" TCP Protocol\n\n");

		for (i = 55; (i < header->caplen + 1); i++) // caplen=OS커널에서 캡쳐된 패킷이 사용자모드로 넘어온 패킷의 실제 길이 // 55byte부터가 data필드
			printf(" %02x", pkt_data[i - 1]);

		printf("\n\n");

		for (i = 55; (i<header->caplen + 1); i++) {
			if ((pkt_data[i - 1] >= 33) && (pkt_data[i - 1] <= 126)) //ASCII code print
				printf(" %c", pkt_data[i - 1]);
			else
				printf(" "); // printf(".");
		}

		printf("\n\n");
		printf("====================The End =======================================\n");
		printf("\n\n");
	}

	// number 17 means UDP
	if (ih->proto == 17) {
		// src ip, dst ip print
		printf("%d.%d.%d.%d (%d)-> %d.%d.%d.%d (%d)\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			ntohs(uh->sport), // big -> litle

			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			ntohs(uh->dport));
		printf("\n");

		printf("UDP Protocol\n");
		printf("\n");
		for (i = 55; (i < header->caplen + 1); i++)
			printf(" %02x", pkt_data[i - 1]);

		for (i = 55; (i<header->caplen + 1); i++) {
			if ((pkt_data[i - 1] >= 33) && (pkt_data[i - 1] <= 126))
				printf(" %c", pkt_data[i - 1]);
			else
				printf(" ");
		}

		printf("\n\n");
		printf("===========================The End ==============================\n");
		printf("\n\n");
	}

	// number 1 means ICMP
	if (ih->proto == 1) {
		// print ip
		printf("%d.%d.%d.%d -> %d.%d.%d.%d \n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,

			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4);
		printf("\n");

		printf("ICMP Protocol\n\n");
		for (i = 55; (i < header->caplen + 1); i++)
			printf(" %02x", pkt_data[i - 1]);

		printf("\n\n");

		for (i = 55; (i<header->caplen + 1); i++) {
			if ((pkt_data[i - 1] >= 33) && (pkt_data[i - 1] <= 126))
				printf(" %c", pkt_data[i - 1]);
			else
				printf(" ");
		}

		printf("\n\n");
		printf("===========================The End ==============================\n");
		printf("\n\n");
	}
}

void ErrorMessage(char* str) {
	printf("%s\n", str);
	exit(1);
}
