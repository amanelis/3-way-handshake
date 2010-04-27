#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dnet.h>

int print_intf_entry(const struct intf_entry *ie, void *cp) {
  const struct addr *ia;
  const struct addr *il;
  u_short flags;
  int comma = 0;
  char a[32],l[32];

  flags = ie->intf_flags;
  ia = &ie->intf_addr;
  il = &(ie->intf_link_addr);

  printf("%s: ", ie->intf_name);
  if ( ie->intf_type == INTF_TYPE_OTHER )
    printf("OTHER ");
  else if ( ie->intf_type == INTF_TYPE_ETH )
    printf("ETH ");
  else if ( ie->intf_type == INTF_TYPE_LOOPBACK )
    printf("LOOPBACK ");
  else if ( ie->intf_type == INTF_TYPE_TUN )
    printf("TUN ");
  else if ( ie->intf_type == INTF_TYPE_TOKENRING )
    printf("TOKENRING ");
  else if ( ie->intf_type == INTF_TYPE_FDDI )
    printf("FDDI ");
  else if ( ie->intf_type == INTF_TYPE_PPP )
    printf("PPP ");
  else if ( ie->intf_type == INTF_TYPE_SLIP )
    printf("SLIP ");

  printf("flags=%x<", (int)flags);
  if ( flags & INTF_FLAG_UP ) {
    printf("UP");
    comma = 1;
  } 
  if ( flags & INTF_FLAG_LOOPBACK ) {
    if ( comma )
      printf(",");
    printf("LOOPBACK");
    comma = 1;
  } 
  if ( flags & INTF_FLAG_POINTOPOINT ) {
    if ( comma )
      printf(",");
    printf("POINTOPOINT");
    comma = 1;
  } 
  if ( flags & INTF_FLAG_NOARP ) {
    if ( comma )
      printf(",");
    printf("NOARP");
    comma = 1;
  } 
  if ( flags & INTF_FLAG_BROADCAST ) {
    if ( comma )
      printf(",");
    printf("BROADCAST");
    comma = 1;
  } 
  if ( flags & INTF_FLAG_MULTICAST ) {
    if ( comma )
      printf(",");
    printf("MULTICAST");
    comma = 1;
  }
  printf("> mtu %d\n\t", (int)ie->intf_mtu);

  if ( addr_ntop(ia,a,sizeof(a)) != NULL ) 
    printf("inet %s", a);

  if ( addr_ntop(il,l,sizeof(l)) != NULL )
    printf(" mac %s", l);

  printf("\n");

  return(0);
}

int main(void) {
  intf_t *i;

  i=intf_open();
  if ( i == NULL ) {
    perror("Intf open error");
    exit(-1);
  }

  if ( intf_loop(i, print_intf_entry, NULL) == -1 ) {
    fprintf(stderr, "Error in intf table print\n");
    exit(-1);
  }

  intf_close(i);
  exit(0);
}
