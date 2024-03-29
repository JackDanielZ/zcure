#include <stdio.h>
#include <stdlib.h>

#include "lib/server/server.h"

int main(void)
{
  int fd = zcure_server_register("LOOP");
  int nb = 1; // Set to 1 to enter the loop

  LOGGER_INFO("fd %d\n", fd);

  if (fd <= 0)
  {
    LOGGER_ERROR("Cannot connect\n");
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
      LOGGER_INFO("%d bytes received from client %d\n", nb, src_id);
      switch (type)
      {
        case CLIENT_CONNECT_NOTIFICATION:
        {
          Server2ServerApp_ClientConnectNotification *notif = (Server2ServerApp_ClientConnectNotification *)buf;
          LOGGER_INFO("New connection from %s - ID %d - IP: %X\n", notif->name, src_id, notif->ip);
          break;
        }
        case CLIENT_DISCONNECT_NOTIFICATION:
        {
          LOGGER_INFO("Disconnection of client %d\n", src_id);
          break;
        }
        case CLIENT_DATA:
        {
          zcure_server_send(fd, src_id, buf, nb);
          break;
        }
        default:
        {
          LOGGER_INFO("Unsupported data type: %d\n", type);
          break;
        }
      }
      free(buf);
    }
  }

  return 0;
}
