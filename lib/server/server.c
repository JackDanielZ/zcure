#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <getopt.h>
#include <sys/un.h>

#include "common/common.h"
#include "server.h"

int zcure_server_register(const char *service)
{
  int err = 0;
  int fd = -1;
  struct sockaddr_un socket_unix;
  ServerConnectionRequest req;

  if (!service) goto err;

  memcpy(req.service, service, strlen(service) + 1);

  // create the socket
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) goto err;

  // set the socket to close when we exec things so they don't inherit it
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) goto err;

  // set up some socket options on addr re-use
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) goto err;

  memset(&socket_unix, 0, sizeof(socket_unix));
  socket_unix.sun_family = AF_UNIX;
  strncpy(socket_unix.sun_path, "#zcure_server", sizeof(socket_unix.sun_path));
  socket_unix.sun_path[sizeof(socket_unix.sun_path) - 1] = 0;
  socket_unix.sun_path[0] = 0;

  if (connect(fd, (struct sockaddr *)&socket_unix, sizeof(socket_unix)) < 0) goto err;

  send(fd, &req, sizeof(req), 0);

  if (recv(fd, &err, sizeof(int), 0) != sizeof(int))
  {
    perror("recv connection status");
    goto err;
  }

  if (err != 0)
  {
    fprintf(stderr, "Error during connection for service %s\n", service);
    goto err;
  }

  return fd;

err:
  if (fd <= 0) close(fd);
  return -1;
}

int zcure_server_send(int fd, uint32_t client_id, const void *plain_buffer, unsigned int plain_size)
{
  ServerApp2Server_Header s_info;
  int rv;

  s_info.size = plain_size;
  s_info.dest_id = client_id;

  rv = send(fd, &s_info, sizeof(s_info), 0);
  if (rv <= 0)
  {
    perror("send ServerApp2Server_Header");
    return -1;
  }

  rv = send(fd, plain_buffer, plain_size, 0);
  if (rv <= 0)
  {
    perror("send data");
    return -1;
  }

  return rv;
}

int zcure_server_receive(int fd, void **plain_buffer, Server2ServerApp_DataType *type, uint32_t *src_id)
{
  Server2ServerApp_Header sh;
  int rv;

  if (!plain_buffer || !type) return -1;

  rv = recv(fd, &sh, sizeof(Server2ServerApp_Header), 0);
  if (rv <= 0 || rv != sizeof(Server2ServerApp_Header))
  {
    if (rv < 0) perror("recv Server2ServerApp_Header");
    return -1;
  }

  // FIXME: check size limitation

  if (sh.size != 0)
  {
    *plain_buffer = malloc(sh.size);
    rv = recv(fd, *plain_buffer, sh.size, 0);
    if (rv <= 0)
    {
      if (rv < 0) perror("recv data");
      return -1;
    }
  }

  if (src_id) *src_id = sh.src_id;
  *type = sh.data_type;

  return rv;
}
