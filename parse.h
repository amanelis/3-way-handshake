#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <dnet.h>

#define PCAP_MAGIC 			0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC		0xd4c3b2a1
#define	PCAP_MODIFIED_MAGIC		0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC	0x34cdb2a1

extern int errno;

/* Structures */
typedef struct {
	u_int32_t magic;
	u_int16_t version_major;
	u_int16_t version_minor;
	u_int32_t thiszone;
	u_int32_t sigfigs;
	u_int32_t snaplen;
	u_int32_t linktype;
}pcap_file_header;

typedef struct {
	unsigned int tv_sec;
	unsigned int tv_usec;
}timev;

typedef struct {
	timev ts;
	int caplen;
	int len;
}my_pkthdr;
