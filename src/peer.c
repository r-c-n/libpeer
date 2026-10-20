#if CONFIG_USE_LIBSRTP
#include <srtp2/srtp.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "peer.h"
#include "sctp.h"
#include "utils.h"

int peer_init() {
#if CONFIG_USE_LIBSRTP
  if (srtp_init() != srtp_err_status_ok) {
    LOGE("libsrtp init failed");
    return -1;
  }
#endif
  sctp_usrsctp_init();
  return 0;
}

void peer_deinit() {
#if CONFIG_USE_LIBSRTP
  srtp_shutdown();
#endif
  sctp_usrsctp_deinit();
}
