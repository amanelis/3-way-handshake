#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/time.h>

#include <dnet.h>
#include <pcap.h>
#include "proxy.h"

struct timev {
	unsigned int tv_sec;
	unsigned int tv_usec;
};

struct my_pkthdr {
	struct timev ts;
	int caplen;
	int len;
};

void layer4 (char *layer4p, uint8_t type) {
	struct tcp_hdr *tcph;
	struct udp_hdr *udph;
	struct icmp_hdr *icmph;

	switch (type) {
		case IP_PROTO_TCP:
			tcph = (struct tcp_hdr *)layer4p;
			printf("	Src Port = %u\n", ntohs(tcph->th_sport));
			printf("	Dst Port = %u\n", ntohs(tcph->th_dport));
			printf("	Seq = %u\n", ntohl(tcph->th_seq));
			printf("	Ack = %u\n", ntohl(tcph->th_ack));
			break;
		case IP_PROTO_UDP:
			udph = (struct udp_hdr *)layer4p;
			printf("	UPD\n");
			printf("	Src Port = %u\n", ntohs(udph->uh_sport));
			printf("	Dst Port = %u\n", ntohs(udph->uh_dport));
			break;
		case IP_PROTO_ICMP:
			icmph = (struct icmp_hdr *)layer4p;
			printf("	ICMP\n");
			switch (icmph->icmp_type) {
				case ICMP_ECHOREPLY:
					printf("		Echo Reply\n");
					break;
				case ICMP_UNREACH:
					printf("		Destination unreachable\n");
					break;
				case ICMP_SRCQUENCH:
					printf("		Source Quench\n");
					break;
				case ICMP_REDIRECT:
					printf("		Route Redirection\n");
					break;
				case ICMP_ALTHOSTADDR:
					printf("		Alternative Address\n");
					break;
				case ICMP_ECHO:
					printf("		Echo\n");
					break;
				case ICMP_RTRADVERT:
					printf("		Route Advertisement\n");
					break;
				case ICMP_RTRSOLICIT:
					printf("		Route Solicitation\n");
					break;
				case ICMP_TIMEXCEED:
					printf("		Time Exceeded\n");
					break;
				case ICMP_PARAMPROB:
					printf("		Bad IP Header\n");
					break;
				case ICMP_TSTAMP:
					printf("		Time stamp Request\n");
					break;
				case ICMP_TSTAMPREPLY:
					printf("		Time stamp Reply\n");
					break;
				case ICMP_INFO:
					printf("		Information Request\n");
					break;
				case ICMP_INFOREPLY:
					printf("		Information Reply\n");
					break;
				case ICMP_MASK:
					printf("		Address Mask Request\n");
					break;
				case ICMP_MASKREPLY:
					printf("		Address Mast Reply\n");
					break;
				case ICMP_TRACEROUTE:
					printf("		Trace Route\n");
					break;
				case ICMP_DATACONVERR:
					printf("		Data Conversion Error\n");
					break;
				case ICMP_MOBILE_REDIRECT:
					printf("		Mobile Host Redirection\n");
					break;
				case ICMP_IPV6_WHEREAREYOU:
					printf("		IPV6 not available\n");
					break;
				case ICMP_IPV6_IAMHERE:
					printf("		IPV6 is available\n");
					break;
				case ICMP_MOBILE_REG:
					printf("		Mobile Registration Request\n");
					break;
				case ICMP_MOBILE_REGREPLY:
					printf("		Mobile Registration Reply\n");
					break;
				case ICMP_DNS:
					printf("		Domain Name Request\n");
					break;
				case ICMP_DNSREPLY:
					printf("		Domain Name Reply\n");
					break;
				case ICMP_SKIP:
					printf("		Skip\n");
					break;
				case ICMP_PHOTURIS:
					printf("		Photuris\n");
					break;
				default:
					printf("		Unknown\n");
					break;
			}
			break;
		case IP_PROTO_IGMP:
			printf("	IGMP\n");
			break;
		default:
			printf("	OTHER\n");
			break;
	}

}

void layer3 (char *layer3p, uint16_t type) {
	struct arp_hdr *arpheader;
	struct ip_hdr *ipheader;

	switch(type){
		case ETH_TYPE_IP:
			ipheader = (struct ip_hdr *) layer3p;
			printf("	IP\n");
			printf("	IP len = %d\n", ipheader->ip_hl*4);
			printf("	IP src = %s\n", ip_ntoa(&ipheader->ip_src));
			printf("	IP dst = %s\n", ip_ntoa(&ipheader->ip_dst));
			layer4(layer3p+(ipheader->ip_hl*4),ipheader->ip_p);
			break;
		case ETH_TYPE_ARP:
			arpheader = (struct arp_hdr *) layer3p;
			printf("	ARP\n");
			if(arpheader->ar_op == 1)
				printf("	ARP Operation = ARP_OP_REQUEST\n");
			else if (arpheader->ar_op == 2)
				printf("	ARP Operation = ARP_OP_REPLY\n");
			else if (arpheader->ar_op == 3)
				printf("	ARP Operation = ARP_OP_REVREQUEST\n");
			else if (arpheader->ar_op == 4)
				printf("	ARP Operation = ARP_OP_REVREPLY\n");
			break;
		default:
			printf("	OTHER\n");
			break;
	}
}

void layer2 (struct eth_hdr *ethhead, int size) {
	printf("Ethernet Header\n");
	printf("	eth_dst = %02x:%02x:%02x:%02x:%02x:%02x\n", (*ethhead).eth_dst.data[0],
			(*ethhead).eth_dst.data[1],
			(*ethhead).eth_dst.data[2],
			(*ethhead).eth_dst.data[3],
			(*ethhead).eth_dst.data[4],
			(*ethhead).eth_dst.data[5]);
	printf("	eth_src = %02x:%02x:%02x:%02x:%02x:%02x\n", (*ethhead).eth_src.data[0],
			(*ethhead).eth_src.data[1],
			(*ethhead).eth_src.data[2],
			(*ethhead).eth_src.data[3],
			(*ethhead).eth_src.data[4],
			(*ethhead).eth_src.data[5]);

	layer3(((char *)ethhead)+14,ntohs((*ethhead).eth_type));
}

int main (int argc, char *argv[]) {
	char pktbuff[20000];
	//struct pcap_file_header fheader;
	struct my_pkthdr pheader;
	int fd, bytes, i;
	long long sstart = 0, ustart = 0, timesec = 0, timeusec = 0;


	open_devices();

	if(argc !=2){
		fprintf(stderr, "USAGE: ./executable [log file]\n");
		return(-1);
	}

	if((fd = open(argv[1], O_RDONLY)) == -1){
		fprintf(stderr, "ERROR: on fd = open(argv[1], O_RDONLY)\n");
		return(-1);
	}

	if((bytes = read(fd, &pheader, 24)) !=24){
		fprintf(stderr, "ERROR: on bytes = read()\n");
		return(-1);
	}

	i = 0;
	while((bytes = read(fd, &pheader, 16)) == 16){
		if(i == 0){
			ustart = pheader.ts.tv_usec;
			sstart = pheader.ts.tv_sec;
		} else {
			timeusec = pheader.ts.tv_usec-ustart;
			timesec = pheader.ts.tv_sec-sstart;
				if (timeusec < 0){
					timeusec += 1000000;
					timesec--;
				}
		}

		readcfg(argv[1]);
		open_devices();	

		printf("\nPacket %d\n%05lld.%06lld\nCaptured Packet Length = %d\n",i,timesec,timeusec,pheader.caplen);
		printf("Actual Packet Length = %d\n", pheader.len);

		if((bytes = read(fd, &pktbuff, pheader.caplen)) !=pheader.caplen){
			fprintf(stdout, "End of file or error on packet read\n");
			fprintf(stdout, "%d\n", pheader.caplen);
			return(-1);
		}
		layer2((struct eth_hdr *) &pktbuff, bytes);
		i++;
	}

	return(0);
}
