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

#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "zcure_common.h"

#define BUF_SIZE 500
#define MAX_EVENTS 5

typedef enum
{
  STATE_WAIT_FOR_CONNECTION_REQUEST,
  STATE_OPERATIONAL
} Connection_State;

typedef struct
{
  int fd;
  Connection_State state;
  unsigned char aes_gcm_key[32];
  unsigned char aes_gcm_iv[AES_BLOCK_SIZE];
} Connection;

typedef int (*service_cb)(void *data, unsigned int data_len, void *user_data);

struct _Service
{
  const char *name;
  unsigned int id;

  service_cb cb;
  void *user_data;

  struct _Service *next;
} _Service;

typedef struct _Service Service;

static const char *_port = NULL;

static Service *_services = NULL;

static Service *
_service_find_by_id(unsigned int id)
{
  Service *s = _services;
  while (s)
  {
    if (s->id == id) return s;
    s = s->next;
  }
  return NULL;
}

static Service *
_service_find_by_name(const char *name)
{
  Service *s = _services;
  while (s)
  {
    if (!strcmp(s->name, name)) return s;
    s = s->next;
  }
  return NULL;
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
  freeaddrinfo(result);           /* No longer needed */

  return sfd;
}

static int
_dispatch_request(Connection *conn, void *data, unsigned int data_len)
{
  unsigned int service_id = *(unsigned int *)data;
  Service *svc = _service_find_by_id(service_id);

  data = (char *)data + sizeof(service_id);
  data_len -= sizeof(service_id);

  if (!svc)
  {
    fprintf(stderr, "Service %d unknown\n", service_id);
    return -1;
  }

  if (!svc->cb)
  {
    fprintf(stderr, "No callback for service %d\n", service_id);
    return -1;
  }

  return svc->cb(data, data_len, svc->user_data);
}

static int
_handle_connection(Connection *conn)
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

      // FIXME: check username size before use

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
      unsigned char buf[10000];
      int data_size;

      /* Receive the encrypted CCRsp */
      data_size = recv(conn->fd, buf, sizeof(buf), 0);
      if (data_size <= 0)
      {
        if (data_size < 0) perror("recv");
        return -1;
      }

      /* Decrypt data */
      rv = zcure_gcm_decrypt(conn->aes_gcm_key, conn->aes_gcm_iv, sizeof(conn->aes_gcm_iv),
                             NULL, 0,
                             buf + 16, data_size - 16,
                             buf + 16,
                             buf, 16);
      if (rv != 0)
      {
        fprintf(stderr, "Decryption failed\n");
        return -1;
      }

      _dispatch_request(conn, buf + 16, data_size - 16);

      printf("Received buffer of size %d\n", data_size - 16);
      /* FIXME Here we should extract the service, convert to a fd and send the data there */
      return data_size - 16;
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
  int master_fd = -1, epoll_fd = -1, event_count, i;
  int rv = EXIT_FAILURE;
  struct epoll_event event, events[MAX_EVENTS];
  Connection master_conn;

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

  master_conn.fd = master_fd;
  event.events = EPOLLIN | EPOLLET;
  event.data.ptr = &master_conn;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_fd, &event))
  {
    perror("epoll_ctl");
    goto exit;
  }

  while(1)
  {
    event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

    for (i = 0; i < event_count; i++)
    {
      Connection *conn = events[i].data.ptr;
      if (conn->fd == master_fd)
      {
        int new_fd;
        struct sockaddr in_addr;
        socklen_t in_len = sizeof in_addr;
        new_fd = accept(master_fd, &in_addr, &in_len);
        if (new_fd == -1)
        {
          perror("accept");
          return EXIT_FAILURE;
        }
        conn = calloc(1, sizeof(Connection));
        conn->fd = new_fd;
        event.data.ptr = conn;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event))
        {
          perror("epoll_ctl");
          return EXIT_FAILURE;
        }
      }
      else {
        if (_handle_connection(conn) <= 0)
        {
          /* Closing connection */
          close(conn->fd);
          epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
          free(conn);
        }
      }
    }
  }

exit:
  if (epoll_fd != -1 && close(epoll_fd)) perror("close");

  if (master_fd != -1 && close(master_fd)) perror("close");

  return rv;
}
