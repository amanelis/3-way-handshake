#include <stdio.h>
#include <stdlib.h>
#include <dnet.h>

int print_arp_entry(const struct arp_entry *ae, void *cp) {
  const struct addr *pa;
  const struct addr *ha;

  pa = &ae->arp_pa;
  ha = &ae->arp_ha;
  printf("%s -> %s\n", addr_ntoa(ha), addr_ntoa(pa));
  return(0);
}

int main(void) {
  arp_t *a;

  a=arp_open();
  if ( a == NULL ) {
    perror("Arp open error");
	exit(-1);
  }

  if ( arp_loop(a, print_arp_entry, NULL) == -1 ) {
    fprintf(stderr, "Error in arp cache print\n");
	exit(-1);
  }

  arp_close(a);
  exit(0);
}
