
#include <string.h>
#include <netdb.h>
#include <zephyr/net/socket.h>
#include "address.h"
#include "utils.h"

int mdns_resolve_addr(const char *hostname, Address *addr)
{
  struct addrinfo hints = {
    .ai_family   = AF_INET,
    .ai_socktype = SOCK_DGRAM,
  };
  struct addrinfo *res = NULL;
  char addr_str[ADDRSTRLEN];

  int ret = getaddrinfo(hostname, NULL, &hints, &res);
  if (ret != 0 || !res) {
    LOGE("mdns_resolve_addr: failed to resolve %s (ret=%d)", hostname, ret);
    return 0;
  }

  addr_set_family(addr, AF_INET);
  memcpy(&addr->sin, res->ai_addr, sizeof(struct sockaddr_in));
  freeaddrinfo(res);

  addr_to_string(addr, addr_str, sizeof(addr_str));
  LOGD("mdns_resolve_addr: %s -> %s", hostname, addr_str);

  return 1;
}
