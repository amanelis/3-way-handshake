void retrans(u_char *user, struct pcap_pkthdr *h, u_char *pack ); 
void setfilter();
void rmnl(char *s);
void rmslash(char *s);
void readcfg(char *filename);
void open_devices(void);
void usage(void);
int load_address(FILE *fp, char *ip, char *hw,struct addr *ad, struct addr *ha);
void load_error(int e, char *mach);
