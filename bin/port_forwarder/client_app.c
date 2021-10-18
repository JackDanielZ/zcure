#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <getopt.h>
#include <errno.h>

#include "lib/client/client.h"
#include "common/common.h"

#define MAX_EVENTS 5

struct _Connection
{
  int is_from_app;
  int app_fd; /* Socket from the app client */
  int zcure_id; /* Identifier to the zcure remote server */

  struct _Connection *next;
  struct _Connection *prev;
} _Connection;

typedef struct _Connection Connection;

static Connection *_connections = NULL;

static char *_app_buf[1000000];

static void
_connection_free(Connection *conn)
{
  if (!conn) return;
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
  if (_connections == conn) _connections = conn->next;
  free(conn);
}

static Connection *
_connection_find_by_id(int id)
{
  Connection *p = _connections;
  while (p)
  {
    if (p->app_fd == id || p->zcure_id == id) return p;
    p = p->next;
  }
  return NULL;
}

static void
_usage(const char *error)
{
  if (error) printf("%s\n", error);

  fprintf(stderr, "zcure_port_forwarder user@server:port local_port:service:service_port\n");
  exit(1);
}

static int
_local_server_create(unsigned int port)
{
  int sockfd;
  struct sockaddr_in servaddr;

  // socket create and verification
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
  {
    perror("socket");
    return -1;
  }
  memset(&servaddr, 0, sizeof(servaddr));

  // assign IP, PORT
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  servaddr.sin_port = htons(port);

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
  {
    perror("setsockopt");
    return -1;
  }

  // Binding newly created socket to given IP and verification
  if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0)
  {
    perror("bind");
    return -1;
  }

  // Now server is ready to listen and verification
  if ((listen(sockfd, 5)) != 0)
  {
    perror("listen");
    return -1;
  }

  return sockfd;
}

int main(int argc, char **argv)
{
  char path[256];
  char *twodots = NULL;
  unsigned int local_port = 0, server_port = 0;
  int local_fd = -1, epoll_fd = -1, event_count, i;
  char *service_name = NULL;
  const char *destination_str;
  char *forward_rule;
  int rc = EXIT_FAILURE;
  struct epoll_event event = {0}, events[MAX_EVENTS];

  if (argc != 3) _usage("Invalid number of parameters");

  destination_str = argv[1];
  forward_rule = argv[2];

  local_port = strtol(forward_rule, &forward_rule, 10);
  if (*forward_rule != ':') _usage("Expected ':' after local port in forward rule");
  forward_rule++;
  twodots = strchr(forward_rule, ':');
  if (twodots == NULL) _usage("Expected ':' after service name in forward rule");

  service_name = strndup(forward_rule, twodots - forward_rule);

  forward_rule = twodots + 1;
  server_port = strtol(forward_rule, NULL, 10);

  sprintf(path, "Port_Fwd_%s_%d", service_name, server_port);

  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1)
  {
    LOGGER_ERROR("Failed to create epoll file descriptor");
    goto exit;
  }

  local_fd = _local_server_create(local_port);
  if (local_fd == -1)
  {
    LOGGER_ERROR("Cannot create a server on local port %d", local_port);
    goto exit;
  }

  event.events = EPOLLIN | EPOLLET;
  event.data.fd = local_fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, local_fd, &event))
  {
    perror("epoll_ctl");
    goto exit;
  }

  zcure_client_init();

  while(1)
  {
    event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

    for (i = 0; i < event_count; i++)
    {
      if (events[i].data.fd == local_fd)
      {
        /* Connection from internal client - need to securely connect to the server */
        struct sockaddr_in in_addr;
        socklen_t in_len = sizeof in_addr;
        Connection *conn = calloc(1, sizeof(Connection)), *conn2;

        conn->is_from_app = 1;
        conn->app_fd = accept(local_fd, (struct sockaddr *)&in_addr, &in_len);
        if (conn->app_fd == -1)
        {
          LOGGER_ERROR("remote accept failed: %s", strerror(errno));
          goto exit;
        }

        conn->zcure_id = zcure_client_connect(destination_str, path);
        if (conn->zcure_id == -1)
        {
          fprintf(stderr, "Cannot establish a secure connection to %s\n", destination_str);
          goto exit;
        }

        conn->next = _connections;
        if (_connections) _connections->prev = conn;
        _connections = conn;

        event.data.ptr = conn;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->app_fd, &event))
        {
          LOGGER_ERROR("epoll_ctl app_fd failed: %s", strerror(errno));
          goto exit;
        }

        conn2 = calloc(1, sizeof(Connection));
        memcpy(conn2, conn, sizeof(Connection));

        conn2->is_from_app = 0;
        conn2->next = _connections;
        if (_connections) _connections->prev = conn2;
        _connections = conn2;
        event.data.ptr = conn2;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, zcure_client_get_fd(conn2->zcure_id), &event))
        {
          LOGGER_ERROR("epoll_ctl zcure_fd failed: %s", strerror(errno));
          goto exit;
        }

        LOGGER_INFO("Connection to client %d", conn->zcure_id);
      }
      else
      {
        Connection *conn = events[i].data.ptr;
        if (conn != NULL)
        {
          if ((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP))
          {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->app_fd, NULL);
            zcure_client_disconnect(conn->zcure_id);
            _connection_free(conn);
            conn = _connection_find_by_id(conn->app_fd);
            _connection_free(conn);
          }
          else
          {
            if (conn->is_from_app == 1)
            {
              /* Data coming from the application to the zcure server */
              int nb_bytes = recv(conn->app_fd, _app_buf, sizeof(_app_buf), 0);
              if (nb_bytes <= 0)
              {
                printf("Socket closed\n");
                close(conn->app_fd);
              }
              else
              {
                printf("Received %d bytes from the application to zcure\n", nb_bytes);
                nb_bytes = zcure_client_send(conn->zcure_id, _app_buf, nb_bytes);
                if (nb_bytes <= 0)
                {
                  close(conn->app_fd);
                }
              }
            }
            else
            {
              /* Data coming from the zcure server to the application */
              void *zcure_buf = NULL;
              printf("Receiving zcure data\n");
              int nb_bytes = zcure_client_receive(conn->zcure_id, &zcure_buf);
              if (nb_bytes <= 0)
              {
                printf("Socket closed\n");
                close(conn->app_fd);
              }
              else
              {
                printf("Received %d bytes from zcure to the application\n", nb_bytes);
                nb_bytes = send(conn->app_fd, zcure_buf, nb_bytes, 0);
                if (nb_bytes <= 0)
                {
                  close(conn->app_fd);
                }
                free(zcure_buf);
              }
            }
          }
        }
      }
    }
  }

  rc = EXIT_SUCCESS;
exit:
  return rc;
}
