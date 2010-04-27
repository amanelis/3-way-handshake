#include <stdio.h>
#include <stdlib.h>
#include <dnet.h>

arp_t *a;

int rm_arp_entry(const struct arp_entry *ae, void *mac) {
  const struct addr *pa;
  const struct addr *ha;
  struct addr ma;

  pa = &ae->arp_pa;
  ha = &ae->arp_ha;
  addr_aton((const char *)mac,&ma);
  if ( !addr_cmp(&ma, ha) ) {
    printf("Deleting %s -> %s\n", addr_ntoa(ha), addr_ntoa(pa));
    if ( arp_delete(a, ae) == -1 ) 
      perror("Unable to delete entry");
  }
  return(0);
}

int main(int argc, char *argv[]) {

  if ( argc != 2 ) {
    fprintf(stderr, "Usage:rmarg macaddr\n");
    exit(-1);
  }

  a=arp_open();
  if ( a == NULL ) {
    perror("Arp open error");
    exit(-1);
  }

  if ( arp_loop(a, rm_arp_entry, (void*)(argv[1])) == -1 ) {
    fprintf(stderr, "Error in arp cache print\n");
    exit(-1);
  }

  arp_close(a);
  exit(0);
}
