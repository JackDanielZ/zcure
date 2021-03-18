#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zcure_client.h"
#include "zcure_common.h"

int main(int argc, char **argv)
{
  int cid;
  unsigned char buffer[256];
  void *recv_buffer;
  int nb_recv_bytes;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s server port\n", argv[0]);
    return EXIT_FAILURE;
  }

  zcure_client_init();

  cid = zcure_client_connect(argv[1], argv[2], "Zen", "LOOP");
  if (cid == -1)
  {
    fprintf(stderr, "Cannot establish a secure connection to %s:%s\n", argv[1], argv[2]);
    return EXIT_FAILURE;
  }

  zcure_data_randomize(sizeof(buffer), buffer);

  if (zcure_client_send(cid, buffer, sizeof(buffer)) != sizeof(buffer))
  {
    fprintf(stderr, "Send over secure connection failed\n");
    return EXIT_FAILURE;
  }

  nb_recv_bytes = zcure_client_receive(cid, &recv_buffer);
  if (nb_recv_bytes <= 0)
  {
    fprintf(stderr, "Receive over secure connection failed\n");
    return EXIT_FAILURE;
  }

  zcure_client_disconnect(cid);

  zcure_client_shutdown();

  return EXIT_SUCCESS;
}
