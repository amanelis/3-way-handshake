#include "parse.h"

int main (int argc, char *argv[]) {
	if(argc !=2){
		printf("USAGE: ./executable [input file]\n");
		return(-1);
	}

	/* Variable declarations */
	int fd, count = 0;
	pcap_file_header *phdr;
	my_pkthdr *mypkt;
	timev *ts;
	struct eth_hdr *myeth;
	struct ip_hdr *myip;
	struct tcp_hdr *mytcp;
	//struct eth_addr *myethadr;

	/* Mallocing */
	phdr = malloc(sizeof(pcap_file_header));
	mypkt = malloc(sizeof(my_pkthdr));
	ts = malloc(sizeof(timev));
	myeth = malloc(sizeof(struct eth_hdr));
	myip = malloc(sizeof(struct ip_hdr));
	mytcp = malloc(sizeof(struct tcp_hdr));
	//myethadr = malloc(sizeof(struct eth_addr));

	/* READS----------------------- */
	fd = open(argv[1], O_RDONLY);
	if(fd < 0) {
		fprintf(stderr,"ERROR: open failed on %s\n", argv[1]);
		return(-1);
	}
	if(read(fd, phdr, sizeof(pcap_file_header)) !=sizeof(pcap_file_header)){
		fprintf(stderr,"ERROR: read on %s failed, with call to pcap_file_header *phdr\n", argv[1]);
		close(fd);
		return(-1);
	}
	if(read(fd, mypkt, sizeof(my_pkthdr)) !=sizeof(my_pkthdr)){
		fprintf(stderr,"ERROR: read on %s failed, with call to my_pkthdr *mypkt\n", argv[1]);
		close(fd);
		return(-1);
	}
	if(read(fd, ts, sizeof(timev)) !=sizeof(timev)){
		fprintf(stderr,"ERROR: read on %s failed, with call to timev *ts\n", argv[1]);
		close(fd);
		return(-1);
	}
	if(read(fd, myeth, sizeof(struct eth_hdr)) !=sizeof(struct eth_hdr)){
		fprintf(stderr,"ERROR: read on %s failed, with call to eth_hdr myeth\n", argv[1]);
		close(fd);
		return(-1);
	}
	if(read(fd, myip, sizeof(struct ip_hdr)) !=sizeof(struct ip_hdr)){
		fprintf(stderr,"ERROR: read on %s failed, with call to ip_hdr myip\n", argv[1]);
		close(fd);
		return(-1);
	}
	if(read(fd, mytcp, sizeof(struct tcp_hdr)) !=sizeof(struct tcp_hdr)){
		fprintf(stderr, "ERROR: read on %s failed, with call to tcp_hdr mytcp\n", argv[1]);
		close(fd);
		return(-1);
	}
	/*
	if(read(fd, myethadr, sizeof(struct eth_addr)) !=sizeof(struct eth_addr)){
		fprintf(stderr, "ERROR: read on %s failed, with call to eth_addr myethadr\n", argv[1]);
		close(fd);
		return(-1);
	}
	*/

	fprintf(stdout,"PCAP_MAGIC\n\tVersion major number %d\n\tVersion minor number %d\n\tGMT to local correction %d\n\tTimestamp accuracy %d\n\tSnaplen %d\n\tLinktype %d\n\n",phdr->version_major,phdr->version_minor,phdr->thiszone,phdr->sigfigs,phdr->snaplen,phdr->linktype);
	fprintf(stdout,"Packet %d\n\tCaptured Packet Length: %d\n\tActual Packet Length: %d\n"
			,count,mypkt->caplen,mypkt->len);
	fprintf(stdout,"Ethernet Header\n\teth_src %s\n\teth_dst %s\n\teth_type %d\n"
			,eth_ntoa(&myeth->eth_src),eth_ntoa(&myeth->eth_dst),myeth->eth_type);
	fprintf(stdout,"IP\n\tip len %d\n\tip src %s\n\tip dst %s\n"
			,myip->ip_len,ip_ntoa(&myip->ip_src),ip_ntoa(&myip->ip_dst));
	fprintf(stdout,"TCP\n\tSrc Port %d\n\tDst Port %d\n\tSeq %d\n\tAck %d\n"
			,mytcp->th_sport,mytcp->th_dport,mytcp->th_seq,mytcp->th_ack);
	

	free(phdr);
	free(mypkt);
	free(ts);
	free(myeth);
	free(myip);
	free(mytcp);
	close(fd);
	return(0);
}
