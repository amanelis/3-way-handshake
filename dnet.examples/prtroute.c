#include <stdio.h>
#include <stdlib.h>
#include <dnet.h>

int print_route_entry(const struct route_entry *re, void *cp) {
  const struct addr *dst;
  const struct addr *gw;

  dst = &re->route_dst;
  gw = &re->route_gw;
  printf("%s -> %s\n", addr_ntoa(dst), addr_ntoa(gw));
  return(0);
}

int main(void) {
  route_t *r;

  r=route_open();
  if ( r == NULL ) {
    perror("Route open error");
    exit(-1);
  }

  if ( route_loop(r, print_route_entry, NULL) == -1 ) {
    fprintf(stderr, "Error in route table print\n");
    exit(-1);
  }

  route_close(r);
  exit(0);
}
