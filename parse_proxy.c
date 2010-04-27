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

void retrans(u_char *user, struct pcap_pkthdr *h, u_char *pack ); 
void setfilter();
void rmnl(char *s);
void rmslash(char *s);
void readcfg(char *filename);
void open_devices(void);
void usage(void);
int load_address(FILE *fp, char *ip, char *hw,struct addr *ad, struct addr *ha);
void load_error(int e, char *mach);

struct timev {
	unsigned int tv_sec;
	unsigned int tv_usec;
};

struct my_pkthdr {
	struct timev ts;
	int caplen;
	int len;
};

#define CMD "tcp and dst host %s and ( src host %s or src host %s )"
#define PCAP_MAGIC                      0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC              0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC             0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC     0x34cdb2a1

char *cfile;

struct addr ad;
struct addr cad, cha;        // client ip and mac address structures
struct addr sad, sha;        // server ip and mac address structures
struct addr mad, mha;        // my ip and mac address structures

char cip[32], chw[32];       // client ascii ip and mac addresses
char sip[32], shw[32];       // server ascii ip and mac addresses
char mip[32], mhw[32];       // my ascii ip and mac addresses

char iface[32];

char buf[2048];
char ebuf[2048];

FILE *fp;
int err;

intf_t *i;
eth_t *e;
pcap_t *p;
struct intf_entry ie;
struct bpf_program fcode;
uint32_t localnet, netmask;

//  Get source address from the current packet, determine whether
//  it is from the client or the server (client1 or client2) and
//  rewrite the mac addresses and the ip addresses appropriately
//  Src address should be this machine (mha,mad) while destination
//  addresses should be other client.  Then set both ip and tcp
//  checksums (both done by ip_checksum()).

void retrans(u_char *user, struct pcap_pkthdr *h, u_char *pack ) {
  struct eth_hdr *ethhdr;
  struct ip_hdr *iphdr;
  struct addr srcad, srcha;
  int n;

  ethhdr = (struct eth_hdr *)pack;
  iphdr = (struct ip_hdr *)(pack + ETH_HDR_LEN);

  // Get source addresses from packet (mac and ip)
  addr_pack(&srcha,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(ethhdr->eth_src),ETH_ADDR_LEN);
  addr_pack(&srcad,ADDR_TYPE_IP,IP_ADDR_BITS,&(iphdr->ip_src),IP_ADDR_LEN);
 
  // Replace source address with my address and destination address
  memcpy( &ethhdr->eth_src, &mha.addr_eth, ETH_ADDR_LEN);
  memcpy( &iphdr->ip_src, &mad.addr_ip, IP_ADDR_LEN);
  
  // Replace destination address with other client
  if ( addr_cmp( &srcad, &cad ) == 0 ) {
    memcpy( &ethhdr->eth_dst, &sha.addr_eth, ETH_ADDR_LEN);
    memcpy( &iphdr->ip_dst, &sad.addr_ip, IP_ADDR_LEN);
  }else{
    memcpy( &ethhdr->eth_dst, &cha.addr_eth, ETH_ADDR_LEN);
    memcpy( &iphdr->ip_dst, &cad.addr_ip, IP_ADDR_LEN);
  }

  // Compute both ip and tcp checksums
  ip_checksum((void *)iphdr, ntohs(iphdr->ip_len));
  // Send packet
  n = eth_send(e,pack,h->len);
  if ( n != h->len ) 
    fprintf(stderr,"Partial packet transmission %d/%d\n",n,h->len);
}

// Set the bpf filter to only accept tcp packets from the clients
// to this machine.
void setfilter() {
  char cmd[128];
  if ( pcap_lookupnet(iface, &localnet, &netmask, ebuf) < 0 ) {
    fprintf(stderr,"pcap_lookupnet: %s\n", ebuf);
    exit(-1);
  }
  snprintf(cmd, sizeof(cmd), CMD, mip, cip, sip);
  printf("Filter:%s\n",cmd);
  if ( pcap_compile(p, &fcode, cmd, 0, netmask) < 0 ) {
    fprintf(stderr,"pcap_compile: %s\n", pcap_geterr(p));
    exit(-1);
  }
  if ( pcap_setfilter(p, &fcode) < 0 ) {
    fprintf(stderr,"pcap_setfilter: %s\n", pcap_geterr(p));
    exit(-1);
  }
}
// Replace newline with null character
void rmnl(char *s) {
  while ( *s != '\n' && *s != '\0' )
    s++;
  *s = '\0';
}

// Cut /bits from returned ip address
void rmslash(char *s) {
  while ( *s != '/' && *s != '\0' )
    s++;
  *s = '\0';
}

// Read in configuration file and put the addresses into
// addr structures
void readcfg(char *filename) {
  FILE *fp;

  fp = fopen(filename,"r");
  if ( fp == NULL ) {
    perror(filename);
    exit(-1);
  }

  /* Get client addresses */
  if ( (err = load_address(fp,cip,chw,&cad,&cha)) < 0 )
    load_error(err,"Client");

  /* Get server addresses */
  if ( (err = load_address(fp,sip,shw,&sad,&sha)) < 0 )
    load_error(err,"Server");

  if ( fgets(iface, sizeof(iface), fp) == NULL ) {
    fprintf(stderr, "Interface too large\n");
    exit(-1);
  }
  rmnl(iface);
  fclose(fp);
}

// Open eth0, get this machines mac and ip addresses (already
// in addr structures and get an ethernet handle and a pcap
// handle to read from the wire.
void open_devices(void) {

    i = intf_open();
    if ( i == NULL ) {
      perror("intf open error");
      exit(-1);
    }
    strncpy(ie.intf_name, iface, 60);
    if ( intf_get(i, &ie) == -1 ) {
      perror("intf get error");
      exit(-1);
    }

    // Set my mac address structure
    mha = ie.intf_link_addr;
    if ( addr_ntop(&mha, mhw, 32) == NULL )
      exit(-1);

    // Set my ip address structure
    mad = ie.intf_addr;
    if ( addr_ntop(&mad, mip, 32) == NULL )
      exit(-1);
    rmslash(mip);
  
    e = eth_open(iface);
    if ( e == NULL ) {
      perror("eth open error");
      exit(-1);
    }

    p = pcap_open_live(iface, -1, 1, 1000, ebuf);
    if ( p == NULL ) {
      perror(ebuf);
      exit(-1);
    }
}
void usage(void) {
    fprintf(stderr, "Usage: proxy <configuration file>\n");
    fprintf(stderr, "         configuration file format\n");
    fprintf(stderr, "            <client ip>\n");
    fprintf(stderr, "            <client mac>\n");
    fprintf(stderr, "            <server ip>\n");
    fprintf(stderr, "            <server mac>\n");
    fprintf(stderr, "            <interface>\n");
    exit(-1);
}
// Read in two ascii addresses and convert them to addr structure form
int load_address(FILE *fp, char *ip, char *hw,struct addr *ad, struct addr *ha) {
  /* Get ip address */
  if ( fgets(ip, 32, fp) == NULL ) 
    return(-1);
  rmnl(ip);
  if ( addr_aton(ip, ad) == -1 ) 
    return(-2);
  /* Get hardware address */
  if ( fgets(hw, 32, fp) == NULL ) 
    return(-3);
  rmnl(hw);
  if ( addr_aton(hw, ha) == -1 ) {
    return(-4);
  }
  return(0);
}
void load_error(int e, char *mach) {
  if ( e == -1 )
    fprintf(stderr, "%s ip too large\n", mach);
  else if ( e == -2 )
    fprintf(stderr, "%s ip incorrectly formatted\n", mach);
  else if ( e == -3 )
    fprintf(stderr, "%s mac address too large\n", mach);
  else if ( e == -4 )
    fprintf(stderr, "%s mac address incorrectly formatted\n", mach);
  else
    fprintf(stderr, "Unknown error %d for %s\n", e, mach);
  exit(-1);
}

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

int run (int argc, char *argv[]) {

  if ( argc == 2 ) {
    cfile = argv[1];
  }else{
    usage();
  }

  readcfg(cfile);
  open_devices();
  setfilter();
  
  // Loop reading packets, make modifications and retransmit
  if ( pcap_loop(p, -1, (pcap_handler)retrans, (u_char *)NULL) < 0 ) {
    fprintf(stderr, "%s: pcap_loop: %s\n", "proxy", pcap_geterr(p));
    return(-1);
  }
  return(0);
}

int main (int argc, char *argv[]) {
	char pktbuff[20000];
	//struct pcap_file_header fheader;
	struct my_pkthdr pheader;
	int fd, bytes, i;
	long long sstart = 0, ustart = 0, timesec = 0, timeusec = 0;

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

	open_devices();

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
