#include <stdio.h>
#include <stdlib.h>

#include "lib/client/client.h"
#include "common/common.h"

int main(int argc, char **argv)
{
  int cid;
  char c = '\0';

  if (argc != 4)
  {
    fprintf(stderr, "Usage: %s client_name server port\n", argv[0]);
    return EXIT_FAILURE;
  }

  zcure_client_init();

  cid = zcure_client_connect(argv[2], argv[3], argv[1], "IP_Logger");
  if (cid == -1)
  {
    fprintf(stderr, "Cannot establish a secure connection to %s:%s as client %s\n", argv[2], argv[3], argv[1]);
    return EXIT_FAILURE;
  }

  if (zcure_client_send(cid, &c, sizeof(c)) != sizeof(c))
  {
    fprintf(stderr, "Send over secure connection failed\n");
    return EXIT_FAILURE;
  }

  zcure_client_disconnect(cid);

  zcure_client_shutdown();

  return EXIT_SUCCESS;
}
