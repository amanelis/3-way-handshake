#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <dnet.h>
#include <string.h>
#include "proxy.h"

#define CMD "tcp and dst host %s and ( src host %s or src host %s )"

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
//  <client1 ip>
//  <client1 mac>
//  <client2 ip>
//  <client2 mac>
//  <interface>
//
//  The program should be compiled with
//
//  gcc -Wall -g proxy.c -o proxy -lpcap -ldnet
//

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
void retrans(struct my_pkthdr *h, u_char *pack ) {
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
  if ( n != h->len ) { 
    fprintf(stderr,"Partial packet transmission %d/%d\n",n,h->len);
  } else {
    fprintf(stdout, "Packet Transmission Successfull %d %d\n", n, h->len);
  }
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
