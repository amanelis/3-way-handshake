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

#define CMD "tcp and dst host %s and ( src host %s or src host %s )"

struct timev {
	unsigned int tv_sec;
	unsigned int tv_usec;
};

struct my_pkthdr {
	struct timev ts;
	int caplen;
	int len;
};

char *cfile;

struct addr ad;
struct addr mad, mha;        		// my ip, mac
struct addr vad, vha, vprt;        	// victim ip, mac
struct addr aad, aha, aprt;        	// attacker ip, mac
struct addr revi_ip, revi_mac;		// replay victim ip, mac
struct addr reat_ip, reat_mac;		// replay attacker ip, mac

char mip[32], mhw[32];       		// my ip, mac
char vip[32], vhw[32], vpt[32];       	// victim ip, mac
char aip[32], ahw[32], apt[32];       	// attacker ip, mac
char rvip[32], rvmc[32];		// replay victim ip, mac
char ratip[32], ratmac[32];		// replay attacker ip, mac

char iface[32];
char timing[32];
char buf[2048];
char ebuf[2048];

FILE *fp;
int err;
int swit;
intf_t *i;
eth_t *e;
pcap_t *p;
struct intf_entry ie;
struct bpf_program fcode;
uint32_t localnet, netmask;
pcap_t *packetfile;


void retrans(struct my_pkthdr *h, u_char *pack );
int modify_tcp_header(struct tcp_hdr **tcphdr,uint16_t sport, uint16_t dport, uint32_t seq,uint32_t ack,uint8_t flags,uint16_t win,uint16_t sum,uint16_t urp, uint8_t options);
void open_devices(void);
void usage(void);
int load_address(FILE *fp, char *ip, char *hw, char *pt, struct addr *ad, struct addr *ha, int swit);
void load_error(int e, char *mach);
void readcfg1(char *filename);
void layer4 (char *layer4p, uint8_t type);
void layer3 (char *layer3p, uint16_t type);
void layer2 (struct eth_hdr *ethhead, int size);
void setfilter();
