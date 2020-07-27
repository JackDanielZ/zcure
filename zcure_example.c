#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zcure_client.h"

int main(int argc, char **argv)
{
  int fd;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s server port\n", argv[0]);
    return EXIT_FAILURE;
  }

  fd = zcure_connect(argv[1], argv[2]);
  if (fd == -1)
  {
    fprintf(stderr, "Cannot establish a secure connection to %s:%s\n", argv[1], argv[2]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
