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

extern int next_ack;
extern int next_seq;
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

int main (int argc, char *argv[]) {
	struct my_pkthdr pheader;
	struct contents *z;
	char pktbuff[20000];
	int fd, bytes, i, b;
	long long sstart = 0, ustart = 0, timesec = 0, timeusec = 0;
    	struct eth_hdr *ethin;
	struct pcap_pkthdr h;
	struct tcp_hdr *tcphdr;
	next_ack=0;
	next_seq=0;
	int holder;
	char *progname="HOWDIDTHISGETHEREIAMNOTGOODWITHCOMPUTER";
	argv[0]=progname;
	if(argc !=3){
		fprintf(stderr, "USAGE: %s [log file] [config file]\n", argv[0]);
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
	readcfg(argv[2]);	
	open_devices();
	setfilter();
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
		if(strcmp(timing,"delay")==0){
		  sleep(2);
		}
		b = 0;
	        if((b = pcap_next_ex(p, &h, (const u_char **)&ethin))==1){
		  //tcphdr=(struct tcp_hdr *)(ethin+ETH_HDR_LEN+TCP_HDR_LEN);
	/*	  if(tcphdr->th_seq==next_seq){
		    holder=next_ack;
		    next_ack=tcphdr->th_seq+1;
		    next_seq=holder+1;
		}*/
		}
		
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
  addr_pack(&srcha,ADDR_TYPE_ETH,ETH_ADDR_BITS,&(ethhdr->eth_src),ETH_ADDR_LEN);
  addr_pack(&srcad,ADDR_TYPE_IP,IP_ADDR_BITS,&(iphdr->ip_src),IP_ADDR_LEN);
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
/*	if(modify_tcp_header(&tcphdr,tcphdr->th_sport,tcphdr->th_dport,next_seq,next_ack,tcphdr->th_flags,tcphdr->th_win,tcphdr->th_sum,tcphdr->th_urp,2)<0){
//		return;
	}
	if(modify_tcp_header(&tcphdr,tcphdr->th_sport,tcphdr->th_dport,next_seq,next_ack,tcphdr->th_flags,tcphdr->th_win,tcphdr->th_sum,tcphdr->th_urp,3)<0){
//		return;
	}*/
	ip_checksum((void *)iphdr, ntohs(iphdr->ip_len));
	n = eth_send(e,pack,h->len);
	//n=ip_send(e,pack,h->len);
	if ( n != h->len ) { 
		fprintf(stderr,"Partial packet transmission %d/%d\n",n,h->len);
	} else {
		fprintf(stdout, "Packet Transmission Successfull %d %d\n", n, h->len);
	}
   }
}

int modify_tcp_header(struct tcp_hdr **tcphdr,uint16_t sport, uint16_t dport, uint32_t seq,uint32_t ack,uint8_t flags,uint16_t win,uint16_t sum,uint16_t urp, uint8_t options){
  struct tcp_hdr *temphdr;
  temphdr=*tcphdr;
  switch(options){
    case 0: { temphdr->th_sport=sport;break;}
    case 1: { temphdr->th_dport=dport;break;}
    case 2: { temphdr->th_seq=seq;break;}
    case 3: { temphdr->th_ack=ack;break;}
    case 4: { temphdr->th_flags=flags;break;}
    case 5: { temphdr->th_win=win;break;}
    case 6: { temphdr->th_sum=sum;break;}
    case 7: { temphdr->th_urp=urp;break;}
    case 8: { return 0;}
    default: { return -1;}
  }
  return 0;
}
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
void rmnl(char *s) {
  while ( *s != '\n' && *s != '\0' )
    s++;
  *s = '\0';
}
void rmslash(char *s) {
  while ( *s != '/' && *s != '\0' )
    s++;
  *s = '\0';
}
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

    mha = ie.intf_link_addr;
    if ( addr_ntop(&mha, mhw, 32) == NULL ){
      exit(-1);
    }
    mad = ie.intf_addr;
    if ( addr_ntop(&mad, mip, 32) == NULL ){
      exit(-1);
    }
    rmslash(mip);
  
    e = eth_open(iface);
    if ( e == NULL ) {
      perror("eth open error");
      exit(-1);
    }
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

int load_address(FILE *fp, char *ip, char *hw, char *pt, struct addr *ad, struct addr *ha, int swit) {
  if ( fgets(ip, 32, fp) == NULL ) 
    return(-1);
  rmnl(ip);
  if ( addr_aton(ip, ad) == -1 ) 
    return(-2);

  if ( fgets(hw, 32, fp) == NULL ) 
    return(-3);
  rmnl(hw);
  if ( addr_aton(hw, ha) == -1 ) {
    return(-4);
  }
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

void readcfg(char *filename) {
	FILE *input;
	struct contents *p;
	//p = malloc(sizeof(struct contents));
	if((input = fopen(filename, "r")) == NULL){
		fprintf(stderr, "ERROR: fopen()\n");
		exit(-1);
	}
	if ( (err = load_address(input, vip, vhw, vpt, &vad, &vha,1)) < 0 ){
		load_error(err,"Original Victim");
	}
	if ( (err = load_address(input, aip, ahw, apt, &aad, &aha,1)) < 0 ){
		load_error(err,"Original Attacker");
	}
	if ( (err = load_address(input, rvip, rvmc, vpt, &revi_ip, &revi_mac,0)) < 0 ){
		load_error(err,"Replay Victim");
	}
	if ( (err = load_address(input, ratip, ratmac, apt, &reat_ip, &reat_mac,0)) < 0 ){
		load_error(err,"Replay Attacker");
	}
	if ( fgets(iface, sizeof(iface), input) == NULL ) {
		fprintf(stderr, "Interface too large\n");
		exit(-1);
	}
	rmnl(iface);
	if ( fgets(timing, sizeof(timing), input) == NULL ) {
		fprintf(stderr, "Timing in correct\n");
		exit(-1);
	}
	fclose(input);
	return;
}


void layer4(char *layer4p, uint8_t type) {
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

void layer3(char *layer3p, uint16_t type) {
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

void layer2(struct eth_hdr *ethhead, int size) {
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





