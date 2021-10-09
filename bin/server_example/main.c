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
    uint32_t src_id;
    Server2ServerApp_DataType type;
    char *buf = NULL;
    int nb = zcure_server_receive(fd, (void **)&buf, &type, &src_id);
    if (nb > 0)
    {
      printf("%d bytes received from client %d\n", nb, src_id);
      switch (type)
      {
        case CLIENT_CONNECT_NOTIFICATION:
        {
          Server2ServerApp_ClientConnectNotification *notif = (Server2ServerApp_ClientConnectNotification *)buf;
          printf("New connection from %s - IP: %X\n", notif->name, notif->ip);
          break;
        }
        case CLIENT_DATA:
        {
          zcure_server_send(fd, src_id, buf, nb);
          break;
        }
        default:
        {
          printf("Unsupported data type: %d\n", type);
          break;
        }
      }
      free(buf);
    }
  }

  return 0;
}
