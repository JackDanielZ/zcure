#include <stdio.h>
#include <stdlib.h>

#include "lib/server/server.h"

int main(void)
{
  int fd = zcure_server_register("LOOP");
  int nb = 1; // Set to 1 to enter the loop

  printf("fd %d\n", fd);

  if (fd <= 0)
  {
    fprintf(stderr, "Cannot connect\n");
    return 1;
  }

  while (nb > 0)
  {
    Client_Info client;
    char *buf = NULL;
    int nb = zcure_server_receive(fd, (void **)&buf, &client);
    if (nb > 0)
    {
      printf("%d bytes received from client %d - IP %08X\n", nb, client.id, client.ip);
      zcure_server_send(fd, client.id, buf, nb);
      free(buf);
    }
  }

  return 0;
}
