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

#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "common/common.h"

#define BUF_SIZE 500
#define MAX_EVENTS 5

typedef enum
{
  STATE_WAIT_FOR_CONNECTION_REQUEST,
  STATE_OPERATIONAL
} Connection_State;

struct _Connection
{
  unsigned int is_server;

  int fd;

  Connection_State state;

  union
  {
    struct // client
    {
      struct _Connection *service; /* Connection to the server */

      unsigned int id;

      unsigned char aes_gcm_key[32];
      unsigned char aes_gcm_iv[AES_BLOCK_SIZE];
    };
    struct // server
    {
      const char *name;
    };
  };

  struct _Connection *next;
  struct _Connection *prev;
} _Connection;

typedef struct _Connection Connection;

static Connection *_connections = NULL;

static unsigned int _last_id = 0;

static const char *_port = NULL;

static Connection *
_server_find_by_name(const char *name)
{
  Connection *p = _connections;
  while (p)
  {
    if (p->is_server && !strcmp(p->name, name)) return p;
    p = p->next;
  }
  return NULL;
}

static Connection *
_client_find_by_id(unsigned int id)
{
  Connection *p = _connections;
  while (p)
  {
    if (p->is_server == 0 && p->id == id) return p;
    p = p->next;
  }
  return NULL;
}

static void
_connection_free(Connection *conn)
{
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
  free(conn);
}

static int
_make_socket_non_blocking(int sfd)
{
  int flags, s;

  flags = fcntl(sfd, F_GETFL, 0);
  if(flags == -1)
  {
    perror("fcntl");
    return -1;
  }

  flags |= O_NONBLOCK;
  s = fcntl(sfd, F_SETFL, flags);
  if(s == -1)
  {
    perror("fcntl");
    return -1;
  }

  return 0;
}

static int
_server_create(const char *port)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd, s;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
  hints.ai_protocol = 0;          /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  s = getaddrinfo(NULL, port, &hints, &result);
  if (s != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }

  /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully bind(2).
     If socket(2) (or bind(2)) fails, we (close the socket
     and) try the next address. */
  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) continue;

    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
      goto exit;

    if (0) _make_socket_non_blocking(sfd);

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(sfd, 5) == 0)
      goto exit;

    close(sfd);
  }

  fprintf(stderr, "Could not bind\n");
  sfd = -1;

exit:
  freeaddrinfo(result); /* No longer needed */

  return sfd;
}

static int
_create_local_socket(const char *filename)
{
  struct sockaddr_un name;
  int sock;
  int yes=1;

  /* Create the socket. */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
  {
    perror("socket");
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
  {
    perror("setsockopt");
    return -1;
  }

  /* Bind a name to the socket. */
  name.sun_family = AF_UNIX;
  strncpy(name.sun_path, filename, sizeof(name.sun_path));
  name.sun_path[sizeof(name.sun_path) - 1] = '\0';

  if (bind(sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)) < 0)
  {
    perror("bind");
    return -1;
  }

  listen(sock, 5);

  return sock;
}

static int
_handle_server(Connection *conn)
{
  int rv;

  switch (conn->state)
  {
    case STATE_WAIT_FOR_CONNECTION_REQUEST:
    {
      char service[SERVICE_SIZE];

      memset(service, 0, sizeof(service));

      rv = recv(conn->fd, service, sizeof(service), 0);
      if (rv <= 0)
      {
        if (rv < 0) perror("recv");
        return -1;
      }

      if (memchr(service, '\0', sizeof(service)) == NULL)
      {
        return -1;
      }

      if (_server_find_by_name(service))
      {
        return -1;
      }

      conn->name = strdup(service);
      conn->state = STATE_OPERATIONAL;
      break;
    }
    case STATE_OPERATIONAL:
    {
      Connection *client;
      Server_Data_Info s_info;
      Client_Data_Info *c_info;
      char *data;

      memset(&s_info, 0, sizeof(s_info));

      rv = recv(conn->fd, &s_info, sizeof(s_info), 0);
      if (rv <= 0 || rv != sizeof(s_info))
      {
        if (rv < 0) perror("recv Server_Data_Info");
        return -1;
      }

      client = _client_find_by_id(s_info.client_id);
      if (client == NULL)
      {
        fprintf(stderr, "Client with id %d not found\n", s_info.client_id);
        /* Positive return code to not close the server connection when a client disconnected suddenly */
        return 1;
      }

      // FIXME: check size limitation

      data = malloc(sizeof(Client_Data_Info) + s_info.size);
      c_info = (Client_Data_Info *)data;
      c_info->size = s_info.size;

      rv = recv(conn->fd, data + sizeof(Client_Data_Info), c_info->size, 0);
      if (rv <= 0)
      {
        if (rv < 0) perror("recv");
        return -1;
      }

      rv = zcure_gcm_encrypt(client->aes_gcm_key, client->aes_gcm_iv, sizeof(client->aes_gcm_iv),
                             data, sizeof(c_info->size),
                             data + sizeof(Client_Data_Info), c_info->size,
                             data + sizeof(Client_Data_Info),
                             c_info->tag, sizeof(c_info->tag));
      if (rv != 0)
      {
        fprintf(stderr, "zcure_gcm_encrypt to client failed\n");
        return -1;
      }

      rv = send(client->fd, data, sizeof(Client_Data_Info) + c_info->size, 0);

      free(data);

      return rv;
    }
    default:
    {
      return -1;
    }
  }
  return 1;
}

static int
_handle_client(Connection *conn)
{
  int rv;

  switch (conn->state)
  {
    case STATE_WAIT_FOR_CONNECTION_REQUEST:
    {
      int data_size;
      unsigned char *ecdh_key = NULL;
      int secret_len = 32;
      unsigned char iv0[12] = {0};
      ConnectionRequest conn_req;
      ConnectionResponse conn_rsp;

      /* Receive the encrypted CCReq */
      data_size = recv(conn->fd, &conn_req, sizeof(ConnectionRequest), 0);
      if (data_size != sizeof(ConnectionRequest))
      {
        if (data_size < 0) perror("recv");
        return -1;
      }

      if (memchr(conn_req.username, '\0', sizeof(conn_req.username)) == NULL)
      {
        return -1;
      }

      ecdh_key = zcure_ecdh_key_compute_for_username(conn_req.username, conn_req.salt, sizeof(conn_req.salt), secret_len);

      for (int i = 0; i < secret_len; i++)
        printf("%02X ", ecdh_key[i]);
      printf("\n");

      rv = zcure_gcm_decrypt(ecdh_key, iv0, sizeof(iv0),
                             conn_req.username, sizeof(conn_req.username) + sizeof(conn_req.salt),
                             conn_req.service, sizeof(conn_req.service),
                             conn_req.service,
                             conn_req.tag, sizeof(conn_req.tag));
      if (rv != 0)
      {
        fprintf(stderr, "GCM Decryption of ConnectionRequest failed\n");
        return -1;
      }

      /* Prepare connection response */
      zcure_data_randomize(sizeof(conn_rsp), &conn_rsp);

      /* Store AES info */
      memcpy(conn->aes_gcm_key, conn_rsp.aes_gcm_key, sizeof(conn_rsp.aes_gcm_key));
      memcpy(conn->aes_gcm_iv, conn_rsp.aes_gcm_iv, sizeof(conn_rsp.aes_gcm_iv));
      conn_rsp.status = 0;

      rv = zcure_gcm_encrypt(ecdh_key, iv0, sizeof(iv0),
                             NULL, 0,
                             &conn_rsp, sizeof(conn_rsp) - sizeof(conn_rsp.tag),
                             &conn_rsp,
                             conn_rsp.tag, sizeof(conn_rsp.tag));
      if (rv != 0)
      {
        fprintf(stderr, "GCM Encryption of ConnectionResponse failed\n");
        return -1;
      }

      conn->state = STATE_OPERATIONAL;

      memset(ecdh_key, '0', secret_len);
      free(ecdh_key);

      /* Send the encrypted SCRsp */
      return send(conn->fd, &conn_rsp, sizeof(conn_rsp), 0);
    }
    case STATE_OPERATIONAL:
    {
      Client_Data_Info c_info;
      Server_Data_Info *s_info;
      char *data;

      rv = recv(conn->fd, &c_info, sizeof(Client_Data_Info), 0);
      if (rv != sizeof(Client_Data_Info))
      {
        if (rv < 0) perror("recv Client_Data_Info");
        return -1;
      }

      // FIXME: check size limitation

      data = malloc(sizeof(Server_Data_Info) + c_info.size);
      s_info = (Server_Data_Info *)data;
      s_info->size = c_info.size;
      s_info->client_id = conn->id;

      rv = recv(conn->fd, data + sizeof(Server_Data_Info), s_info->size, 0);
      if (rv <= 0)
      {
        if (rv < 0) perror("recv");
        return -1;
      }

      rv = zcure_gcm_decrypt(conn->aes_gcm_key, conn->aes_gcm_iv, sizeof(conn->aes_gcm_iv),
                             &c_info, sizeof(c_info.size),
                             data + sizeof(Server_Data_Info), s_info->size,
                             data + sizeof(Server_Data_Info),
                             c_info.tag, sizeof(c_info.tag));
      if (rv != 0)
      {
        fprintf(stderr, "zcure_gcm_decrypt from client failed\n");
        return -1;
      }

      if (conn->service)
      {
        rv = send(conn->service->fd, data, sizeof(Server_Data_Info) + s_info->size, 0);
      }
      else
      {
        fprintf(stderr, "No server for the client %d\n", conn->id);
        rv = -1;
      }

      free(data);

      return rv;
    }
  }

  return -1;
}

static struct option _long_options[] =
{
  {"port",     required_argument, 0, 'p'},
  {0, 0, 0, 0}
};

static void
_help(const char *prg_name)
{
  fprintf(stderr, "%s -p/--port port", prg_name);
}

int main(int argc, char **argv)
{
  int master_fd = -1, local_fd = -1, epoll_fd = -1, event_count, i;
  int rv = EXIT_FAILURE;
  struct epoll_event event, events[MAX_EVENTS];

  while (1)
  {
    /* getopt_long stores the option index here. */
    int option_index = 0, c;

    c = getopt_long (argc, argv, "p:", _long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1) break;

    switch (c)
    {
      case 'p':
        {
          _port = optarg;
          break;
        }

      default:
        break;
    }
  }

  if (!_port)
  {
    _help(argv[0]);
    return EXIT_FAILURE;
  }

  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1)
  {
    fprintf(stderr, "Failed to create epoll file descriptor\n");
    return EXIT_FAILURE;
  }

  master_fd = _server_create(_port);
  if (master_fd == -1)
  {
    fprintf(stderr, "Cannot create a server on port %s\n", _port);
    return EXIT_FAILURE;
  }

  event.events = EPOLLIN | EPOLLET;
  event.data.fd = master_fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_fd, &event))
  {
    perror("epoll_ctl");
    goto exit;
  }

  local_fd = _create_local_socket("/tmp/zcure_server");
  if (local_fd == -1)
  {
    fprintf(stderr, "Cannot create a local socket\n");
    return EXIT_FAILURE;
  }

  event.events = EPOLLIN | EPOLLET;
  event.data.fd = local_fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, local_fd, &event))
  {
    perror("epoll_ctl");
    goto exit;
  }

  while(1)
  {
    event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

    for (i = 0; i < event_count; i++)
    {
      if (events[i].data.fd == master_fd)
      {
        /* New secure connection */
        Connection *conn;
        int new_fd;
        struct sockaddr in_addr;
        socklen_t in_len = sizeof in_addr;
        new_fd = accept(master_fd, &in_addr, &in_len);
        if (new_fd == -1)
        {
          perror("accept tcp");
          return EXIT_FAILURE;
        }
        event.data.fd = new_fd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event))
        {
          perror("epoll_ctl");
          return EXIT_FAILURE;
        }

        conn = calloc(1, sizeof(Connection));
        conn->is_server = 0;
        conn->fd = new_fd;
        conn->state = STATE_WAIT_FOR_CONNECTION_REQUEST;
        conn->id = ++_last_id;

        conn->next = _connections;
        _connections->prev = conn;
        _connections = conn;
      }
      else if (events[i].data.fd == local_fd)
      {
        /* New local connection */
        Connection *conn;
        int new_fd;
        struct sockaddr in_addr;
        socklen_t in_len = sizeof in_addr;
        new_fd = accept(local_fd, &in_addr, &in_len);
        if (new_fd == -1)
        {
          perror("accept local");
          return EXIT_FAILURE;
        }
        event.data.fd = new_fd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event))
        {
          perror("epoll_ctl");
          return EXIT_FAILURE;
        }

        conn = calloc(1, sizeof(Connection));
        conn->is_server = 1;
        conn->fd = new_fd;
        conn->state = STATE_WAIT_FOR_CONNECTION_REQUEST;
        conn->next = _connections;
        _connections->prev = conn;
        _connections = conn;
      }
      else
      {
        Connection *conn = events[i].data.ptr;
        if (conn != NULL)
        {
          if (events[i].events & EPOLLRDHUP)
          {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
            _connection_free(conn);
          }
          else
          {
            if (conn->is_server)
            {
              if (_handle_server(conn) <= 0)
              {
                close(conn->fd);
              }
            }
            else
            {
              if (_handle_client(conn) <= 0)
              {
                close(conn->fd);
              }
            }
          }
        }
      }
    }
  }

exit:
  if (epoll_fd != -1 && close(epoll_fd)) perror("close");

  if (master_fd != -1 && close(master_fd)) perror("close");

  if (local_fd != -1 && close(local_fd)) perror("close");

  return rv;
}
