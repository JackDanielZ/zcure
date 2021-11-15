#include <stdio.h>
#include <stdlib.h>

#include "lib/client/client.h"
#include "common/common.h"

int main(int argc, char **argv)
{
  int cid;

  if (argc != 2)
  {
    LOGGER_ERROR("Usage: %s user@server:port\n", argv[0]);
    return EXIT_FAILURE;
  }

  zcure_client_init();

  cid = zcure_client_connect(argv[1], "IP_Logger");
  if (cid == -1)
  {
    LOGGER_ERROR("Cannot establish a secure connection to %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  zcure_client_disconnect(cid);

  zcure_client_shutdown();

  return EXIT_SUCCESS;
}
