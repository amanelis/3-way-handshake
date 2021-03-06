#include"driver.h"

extern char *cfile;

extern struct addr ad;
extern struct addr mad, mha;        		// my ip, mac
extern struct addr vad, vha, vprt;        	// victim ip, mac
extern struct addr aad, aha, aprt;        	// attacker ip, mac
extern struct addr revi_ip, revi_mac;		// replay victim ip, mac
extern struct addr reat_ip, reat_mac;		// replay attacker ip, mac

extern char mip[32], mhw[32];       		// my ip, mac
extern char vip[32], vhw[32], vpt[32];       	// victim ip, mac
extern char aip[32], ahw[32], apt[32];       	// attacker ip, mac
extern char rvip[32], rvmc[32];		// replay victim ip, mac
extern char ratip[32], ratmac[32];		// replay attacker ip, mac

extern char iface[32];
extern char timing[32];
extern char buf[2048];
extern char ebuf[2048];

extern FILE *fp;
extern int err;
extern int swit;
extern intf_t *i;
extern eth_t *e;
extern pcap_t *p;
extern struct intf_entry ie;
extern struct bpf_program fcode;
extern uint32_t localnet, netmask;
extern pcap_t *packetfile;

//  This is a simple implementation of a proxy machine.  Effectively
//  this program makes the machine that it is running on a man-in-the-middle
//  between two other machines.  Every packet sent to this machine from
//  either of two machines will be sent to the other machine.  Basically
//  all this program does is to read each packet with src a client machine
//  and dst this machine and change it so src is this machine and dst is
//  the other client machine and then compute new checksums.  This only
//  operates on TCP packets.
//
//  Thus if client1 telnets to this machine, the telnet will be passed on
//  to client2 and a regular telnet session occurs except that client1
//  is talking to this machine as is client2.
//
//  This machine must reject the routes to client1 and client2 since 
//  otherwise this machine will send RST packets.  This can be done
//  by executing as root
//  route add -host <client1 ip> reject
//  route add -host <client2 ip> reject
//
//  This program uses a configuration file that has the following 
//  information:
//  <victim ip>
//  <victim mac>
//  <victim port>
//
//  <attacker ip>
//  <attacker mac>
//  <attacker port>
//
//  <replay victim ip>
//  <replay victim mac>
//
//  <replay attacker ip>
//  <replay attacker mac>
//
//  <interface>
//  <timing>
//
//  The program should be compiled with
//
//  gcc -Wall -g proxy.c -o proxy -lpcap -ldnet

/*
int main(int argc, char *argv[]) {

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
*/

//  Get source address from the current packet, determine whether
//  it is from the client or the server (client1 or client2) and
//  rewrite the mac addresses and the ip addresses appropriately
//  Src address should be this machine (mha,mad) while destination
//  addresses should be other client.  Then set both ip and tcp
//  checksums (both done by ip_checksum()).

//void retrans(u_char *user, struct pcap_pkthdr *h, u_char *pack ) {
//void retrans(struct pcap_pkthdr *h, u_char *pack ) {
int main (int argc, char *argv[]) {
	//struct pcap_file_header fheader;
	struct my_pkthdr pheader;
	struct contents *z;
	char pktbuff[20000];
	int fd, bytes, i, b;
	long long sstart = 0, ustart = 0, timesec = 0, timeusec = 0;

	if(argc !=3){
		fprintf(stderr, "USAGE: ./executable [log file] [config file]\n");
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
	
	
	fprintf(stdout, "*********************************\n");

	readcfg1(argv[2]);	
	fprintf(stdout, "Configuration file opened properly\n");
	
	open_devices();
	fprintf(stdout, "Devices properly opened\n");
	
	setfilter();
	fprintf(stdout, "Filters have been compiled\n");

	struct eth_hdr *ethin;
	struct pcap_pkthdr h;
	
	ethin = malloc(sizeof(struct eth_hdr));

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
		
		retrans(&pheader, pktbuff);
					
		layer2((struct eth_hdr *) &pktbuff, bytes);
		i++;
        
		b = 0;
	        b = pcap_next_ex(p, &h, (const u_char **)&ethin);
		fprintf(stdout, "\tPcap_next_ex: %d\n", b);
	}

	return(0);
}

void retrans(struct my_pkthdr *h, u_char *pack ) {
  struct eth_hdr *ethhdr;
  struct ip_hdr *iphdr;
  struct tcp_hdr *tcphdr;
  struct addr srcad, srcha;
  char sip[32],smac[32];
  int n;

  ethhdr = (struct eth_hdr *)pack;
  iphdr = (struct ip_hdr *)(pack+ETH_HDR_LEN);
  tcphdr= (struct tcp_hdr *)(pack+ETH_HDR_LEN+TCP_HDR_LEN);

  // Get source addresses from packet (mac and ip)
  addr_pack(&srcha,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(ethhdr->eth_src),ETH_ADDR_LEN);
  addr_pack(&srcad,ADDR_TYPE_IP,IP_ADDR_BITS,&(iphdr->ip_src),IP_ADDR_LEN);
  /*if((strcmp(addr_ntoa(&srcha),vhw)==0)){
	// Replace source address with my address and destination address
	memcpy( &ethhdr->eth_src, &revi_mac.addr_eth, ETH_ADDR_LEN);
	memcpy( &iphdr->ip_src, &revi_ip.addr_ip, IP_ADDR_LEN);

	// Replace destination address with other client
	if ( addr_cmp( &srcad, &vad ) == 0 ) {
		memcpy( &ethhdr->eth_dst, &reat_mac.addr_eth, ETH_ADDR_LEN);
		memcpy( &iphdr->ip_dst, &reat_ip.addr_ip, IP_ADDR_LEN);
	}else{
		memcpy( &ethhdr->eth_dst, &revi_mac.addr_eth, ETH_ADDR_LEN);
		memcpy( &iphdr->ip_dst, &revi_ip.addr_ip, IP_ADDR_LEN);
	}

	// Compute both ip and tcp checksums
	ip_checksum((void *)iphdr, ntohs(iphdr->ip_len));
		// Send packet
		n = eth_send(e,pack,h->len);
	if ( n != h->len ) { 
		fprintf(stderr,"Partial packet transmission %d/%d\n",n,h->len);
	} else {
		fprintf(stdout, "Packet Transmission Successfull %d %d\n", n, h->len);
	}
  }*/
  if((strcmp(addr_ntoa(&srcha),ahw)==0)){
	// Replace source address with my address and destination address
	memcpy( &ethhdr->eth_src, &reat_mac.addr_eth, ETH_ADDR_LEN);
	memcpy( &iphdr->ip_src, &reat_ip.addr_ip, IP_ADDR_LEN);

	// Replace destination address with other client
	if ( addr_cmp( &srcad, &aad ) == 0 ) {
		memcpy( &ethhdr->eth_dst, &revi_mac.addr_eth, ETH_ADDR_LEN);
		memcpy( &iphdr->ip_dst, &revi_ip.addr_ip, IP_ADDR_LEN);
	}else{
		memcpy( &ethhdr->eth_dst, &reat_mac.addr_eth, ETH_ADDR_LEN);
		memcpy( &iphdr->ip_dst, &reat_ip.addr_ip, IP_ADDR_LEN);
	}
	if(modify_tcp_header(&tcphdr,0,0,0,0,0,0,0,0,8)<0){
		return;
	}
	// Compute both ip and tcp checksums
	ip_checksum((void *)iphdr, ntohs(iphdr->ip_len));
		// Send packet
	n = eth_send(e,pack,h->len);
	//n=ip_send(e,pack,h->len);
	if ( n != h->len ) { 
		fprintf(stderr,"Partial packet transmission %d/%d\n",n,h->len);
	} else {
		fprintf(stdout, "Packet Transmission Successfull %d %d\n", n, h->len);
	}
   }
}

int modify_tcp_header(struct tcp_hdr **tcphdr,uint16_t sport, uint16_t dport, uint16_t seq,uint16_t ack,uint8_t flags,uint16_t win,uint16_t sum,uint16_t urp, uint8_t options){
  //check options here
  struct tcp_hdr *temphdr;
  temphdr=*tcphdr;
  switch(options){
    case 0: { temphdr->sport=sport;}
    case 1: { temphdr->sport=sport;}
    case 2: { temphdr->sport=sport;}
    case 3: { temphdr->sport=sport;}
    case 4: { temphdr->sport=sport;}
    case 5: { temphdr->sport=sport;}
    case 6: { temphdr->sport=sport;}
    case 7: { temphdr->sport=sport;}
    case 8: { temphdr->sport=sport;}
    default: { temphdr->sport=sport;}
  }
}
// Set the bpf filter to only accept tcp packets from the clients
// to this machine.
void setfilter() {
  char cmd[96];
  char *filter;
  if((filter=malloc(sizeof(char)*(32*6)))==NULL){
    return;
  }
  sprintf(filter, "%s, %s, %s, %s, %s, %s", ahw,vhw,aip,vip,apt,vpt);  
  printf("Filter:%s\n",filter);
  pcap_compile(p,&fp,filter,0,0);
  pcap_setfilter(p,&fp);
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

    //p = pcap_open_live(iface, -1, 1, 1000, ebuf);
    p = pcap_open_live(iface, 20000, 1, 500, ebuf);
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
int load_address(FILE *fp, char *ip, char *hw, char *pt, struct addr *ad, struct addr *ha, int swit) {
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

  /* Get port  */
  if(swit == 1){
     if ( fgets(pt, 32, fp) == NULL ) 
       return(-5);
     rmnl(pt);
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
  else if ( e == -5 )
    fprintf(stderr, "%s port incorrectly formatted\n", mach);
  else
    fprintf(stderr, "Unknown error %d for %s\n", e, mach);
  exit(-1);
}


void readcfg1(char *filename) {
	FILE *input;
	struct contents *p;
	p = malloc(sizeof(struct contents));
	if((input = fopen(filename, "r")) == NULL){
		fprintf(stderr, "ERROR: fopen()\n");
		exit(-1);
	}

	// Get victim ip, mac, port
	if ( (err = load_address(input, vip, vhw, vpt, &vad, &vha,1)) < 0 )
		load_error(err,"Original Victim");

	// Get attacker ip, mac, port
	if ( (err = load_address(input, aip, ahw, apt, &aad, &aha,1)) < 0 )
		load_error(err,"Original Attacker");

	// Get replay victim, ip, mac and then add original victim port
	if ( (err = load_address(input, rvip, rvmc, vpt, &revi_ip, &revi_mac,0)) < 0 )
		load_error(err,"Replay Victim");

	// Get replay attacker, ip, mac and then add original attacker port
	if ( (err = load_address(input, ratip, ratmac, apt, &reat_ip, &reat_mac,0)) < 0 )
		load_error(err,"Replay Attacker");

	// Get the interface
	if ( fgets(iface, sizeof(iface), input) == NULL ) {
		fprintf(stderr, "Interface too large\n");
		exit(-1);
	}
	rmnl(iface);

	// Get the timing
	if ( fgets(timing, sizeof(timing), input) == NULL ) {
		fprintf(stderr, "Timing in correct\n");
		exit(-1);
	}
	rmnl(timing);
	fclose(input);
	return;
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
//			printf("	Syn = %u\n", ntohl(tcph->th_syn));
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

