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

int zcure_server_register(const char *service)
{
  int err = 0;
  int fd = -1;
  struct sockaddr_un socket_unix;

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

  send(fd, service, strlen(service) + 1, 0);

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
  close(fd);
  return -1;
}

int zcure_server_send(int fd, uint32_t client_id, const void *plain_buffer, unsigned int plain_size)
{
  Server_Data_Info s_info;
  int rv;

  s_info.size = plain_size;
  s_info.client_id = client_id;

  rv = send(fd, &s_info, sizeof(s_info), 0);
  if (rv <= 0)
  {
    perror("send Server_Data_Info");
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

int zcure_server_receive(int fd, void **plain_buffer, uint32_t *client_id)
{
  int rv;
  Server_Data_Info s_info;

  if (!client_id || !plain_buffer) return -1;

  rv = recv(fd, &s_info, sizeof(Server_Data_Info), 0);
  if (rv <= 0 || rv != sizeof(Server_Data_Info))
  {
    if (rv < 0) perror("recv Server_Data_Info");
    return -1;
  }

  *client_id = s_info.client_id;

  // FIXME: check size limitation

  *plain_buffer = malloc(s_info.size);
  rv = recv(fd, *plain_buffer, s_info.size, 0);
  if (rv <= 0)
  {
    if (rv < 0) perror("recv data");
    return -1;
  }

  return rv;
}
