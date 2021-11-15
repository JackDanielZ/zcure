#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/client/client.h"
#include "common/common.h"

int main(int argc, char **argv)
{
  int cid;
  unsigned char buffer[256];
  void *recv_buffer;
  int nb_recv_bytes;

  if (argc != 2) {
    LOGGER_ERROR("Usage: %s user@server:port\n", argv[0]);
    return EXIT_FAILURE;
  }

  zcure_client_init();

  cid = zcure_client_connect(argv[1], "LOOP");
  if (cid == -1)
  {
    LOGGER_ERROR("Cannot establish a secure connection to %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  zcure_data_randomize(sizeof(buffer), buffer);

  if (zcure_client_send(cid, buffer, sizeof(buffer)) != sizeof(buffer))
  {
    LOGGER_ERROR("Send over secure connection failed\n");
    return EXIT_FAILURE;
  }

  nb_recv_bytes = zcure_client_receive(cid, 1, &recv_buffer);
  if (nb_recv_bytes <= 0)
  {
    LOGGER_ERROR("Receive over secure connection failed\n");
    return EXIT_FAILURE;
  }

  zcure_client_disconnect(cid);

  zcure_client_shutdown();

  return EXIT_SUCCESS;
}
