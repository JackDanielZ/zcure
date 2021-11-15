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
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <getopt.h>
#include <errno.h>

#include "lib/server/server.h"

#define MAX_EVENTS 5

struct _Connection
{
  char client_name[USERNAME_SIZE];
  int app_fd; /* Socket to the app server */
  int zcure_id; /* zcure identifier of the client */

  struct _Connection *next;
  struct _Connection *prev;
} _Connection;

typedef struct _Connection Connection;

static Connection *_connections = NULL;

static char *_app_buf[1000000];

static void
_connection_free(Connection *conn)
{
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
  if (error) LOGGER_INFO("%s", error);

  LOGGER_ERROR("zcure_port_forwarder_server service_port");
  exit(1);
}

int main(int argc, char **argv)
{
  char path[256];
  int zcure_fd;
  int nb;
  unsigned int server_port = 0;
  int epoll_fd = -1, event_count, i;
  char *forward_rule;
  int rc = EXIT_FAILURE;
  struct epoll_event event = {0}, events[MAX_EVENTS];

  if (argc != 2) _usage("Invalid number of arguments");

  forward_rule = argv[1];

  server_port = strtol(forward_rule, NULL, 10);

  sprintf(path, "Port_Fwd_%d", server_port);

  LOGGER_INFO("START");

  zcure_fd = zcure_server_register(path);
  if (zcure_fd <= 0)
  {
    LOGGER_ERROR("Cannot register a port forwarder for the port %d", server_port);
    goto exit;
  }

  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1)
  {
    LOGGER_ERROR("Failed to create epoll file descriptor");
    goto exit;
  }

  event.events = EPOLLIN | EPOLLET;
  event.data.fd = zcure_fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, zcure_fd, &event))
  {
    perror("epoll_ctl");
    goto exit;
  }
  LOGGER_INFO("INIT DONE");

  while(1)
  {
    event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

    for (i = 0; i < event_count; i++)
    {
      if (events[i].data.fd == zcure_fd)
      {
        uint32_t cid;
        Server2ServerApp_DataType type;
        char *buf = NULL;
        nb = zcure_server_receive(zcure_fd, (void **)&buf, &type, &cid);
        if (nb > 0)
        {
          if (type == CLIENT_CONNECT_NOTIFICATION)
          {
            struct sockaddr_in servaddr;
            Server2ServerApp_ClientConnectNotification *notif = (Server2ServerApp_ClientConnectNotification *)buf;
            Connection *conn = calloc(1, sizeof(Connection));

            memcpy(conn->client_name, notif->name, USERNAME_SIZE);
            conn->app_fd = socket(AF_INET, SOCK_STREAM, 0);
            conn->zcure_id = cid;

            if (conn->app_fd == -1)
            {
              LOGGER_ERROR("socket() failed: %s", strerror(errno));
              free(conn);
              continue;
            }
            bzero(&servaddr, sizeof(servaddr));

            // assign IP, PORT
            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
            servaddr.sin_port = htons(server_port);

            // connect the client socket to server socket
            if (connect(conn->app_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
            {
              LOGGER_ERROR("Connection to local server port %d failed: %s", server_port, strerror(errno));
              free(conn);
              continue;
            }

            conn->next = _connections;
            if (_connections) _connections->prev = conn;
            _connections = conn;

            event.data.ptr = conn;
            event.events = EPOLLIN | EPOLLET;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->app_fd, &event))
            {
              LOGGER_ERROR("epoll_ctl app_fd failed: %s", strerror(errno));
              _connection_free(conn);
              continue;
            }

            LOGGER_INFO("New connection to port %d from client %s - socket %d", server_port, notif->name, conn->app_fd);
          }
          else if (type == CLIENT_DISCONNECT_NOTIFICATION)
          {
            Connection *conn = _connection_find_by_id(cid);
            if (conn)
            {
              LOGGER_INFO("Disconnection from port %d of client %s - closing fd %d", server_port, conn->client_name, conn->app_fd);
              close(conn->app_fd);
            }
          }
          else if (type == CLIENT_DATA)
          {
            Connection *conn = _connection_find_by_id(cid);
            if (conn)
            {
              int nb_bytes = send(conn->app_fd, buf, nb, 0);
              if (nb_bytes <= 0)
              {
                LOGGER_INFO("Socket %d closed", conn->app_fd);
                close(conn->app_fd);
              }
              else
              {
//                LOGGER_INFO("%d bytes sent to app (fd %d)", nb_bytes, conn->app_fd);
              }
            }
          }
        }
        free(buf);
      }
      else
      {
        Connection *conn = events[i].data.ptr;
        if (conn != NULL)
        {
          if ((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP))
          {
            LOGGER_INFO("Connection closed with zcure server fd=%d", conn->app_fd);
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->app_fd, NULL);
            close(conn->app_fd);
            _connection_free(conn);
          }
          else
          {
            int flags = 0;
            int nb_bytes;

            do
            {
              /* Data coming from the application to the zcure server */
              nb_bytes = recv(conn->app_fd, _app_buf, sizeof(_app_buf), flags);
              if (nb_bytes <= 0)
              {
                if (flags == 0)
                {
                  LOGGER_INFO("Closing connection with app (fd %d) - recv", conn->app_fd);
                  close(conn->app_fd);
                }
              }
              else
              {
//                LOGGER_INFO("%d bytes received from app (fd %d) to zcure (id %d)", nb_bytes, conn->app_fd, conn->zcure_id);
                nb_bytes = zcure_server_send(zcure_fd, conn->zcure_id, _app_buf, nb_bytes);
                if (nb_bytes <= 0)
                {
                  LOGGER_INFO("Closing connection with app (fd %d) - send", conn->app_fd);
                  close(conn->app_fd);
                }
              }
              flags = MSG_DONTWAIT;
            }
            while (nb_bytes > 0);
          }
        }
      }
    }
  }

  rc = EXIT_SUCCESS;
exit:
  return rc;
}
