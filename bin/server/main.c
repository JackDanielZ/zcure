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
#include "lib/server/server.h"

#define BUF_SIZE 500
#define MAX_EVENTS 5

typedef enum
{
  STATE_WAIT_FOR_CONNECTION_REQUEST,
  STATE_OPERATIONAL
} Connection_State;

typedef struct
{
  char *name;
  char *allowed_clients;
} Service_Permission;

struct _Connection
{
  unsigned int is_server;

  int fd;

  Connection_State state;

  struct
  {
    /*
     * Server: service name
     * Client: username
     */
    const char *name;
    uint32_t flags; // Server
    struct // client
    {
      struct _Connection *service; /* Connection to the server */

      unsigned int id;
      uint32_t ip;

      unsigned char aes_gcm_key[32];
    };
  };

  struct _Connection *next;
  struct _Connection *prev;
} _Connection;

typedef struct _Connection Connection;

static Connection *_connections = NULL;

static unsigned int _last_id = 0;

static const char *_port = NULL;

static Service_Permission *services_permissions = NULL;

static Connection *
_server_find_by_name(const char *name)
{
  Connection *p = _connections;
  while (p)
  {
    if (p->is_server && p->name && !strcmp(p->name, name)) return p;
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
  if (_connections == conn) _connections = conn->next;
  free(conn);
}

static int
_permissions_parse(void)
{
  int rc = 1;
  char path[256];
  char *permissions_file_content = NULL;
  char *home = getenv("HOME");
  char *cur, *tmp;
  Service_Permission *sp;
  unsigned int nb_lines, no_line;

  /* Clean the permissions table to handle the on-purpose file deletion */
  sp = services_permissions;
  while (sp && sp->name)
  {
    free(sp->name);
    free(sp->allowed_clients);
    sp++;
  }
  free(services_permissions);
  services_permissions = NULL;

  if (home == NULL)
  {
    LOGGER_ERROR("Cannot get $HOME from getenv\n");
    goto exit;
  }

  sprintf(path, "%s/.config/zcure/permissions.conf", home);
  permissions_file_content = get_file_content_as_string(path, NULL);
  if (!permissions_file_content)
  {
    LOGGER_ERROR("Cannot read %s", path);
    goto exit;
  }

  tmp = permissions_file_content;
  nb_lines = 0;

  while (tmp != NULL)
  {
    tmp = strchr(tmp, '\n');
    if (tmp) tmp++;
    nb_lines++;
  }

  services_permissions = calloc(nb_lines + 1, sizeof(Service_Permission));
  cur = permissions_file_content;
  sp = services_permissions;
  no_line = 1;

  while (*cur != '\0')
  {
    while (*cur == ' ' || *cur == '\t') cur++;

    /* Isolate the current line of the next lines */
    char *endl = strchr(cur, '\n');
    if (endl)
    {
      *endl = '\0';
    }

    if (*cur != '\0')
    {
      /* Hide the comment #... */
      tmp = strchr(cur, '#');
      if (tmp)
      {
        tmp--;
        while (*tmp == ' ' || *tmp == '\t') tmp--;
        tmp++;
        *tmp = '\0';
      }

      /* Look for ':' */
      tmp = strchr(cur, ':');
      if (!tmp)
      {
        LOGGER_ERROR("Permission file parsing failed, line %d: expected ':'", no_line);
        goto exit;
      }

      sp->name = strndup(cur, tmp - cur);

      /* Move after the ':' */
      cur = tmp + 1;

      sp->allowed_clients = malloc(strlen(cur) + 2); /* Let room for a space at the end of the clients list and for the termination character */
      memcpy(sp->allowed_clients, cur, strlen(cur));
      sp->allowed_clients[strlen(cur)] = ' ';
      sp->allowed_clients[strlen(cur) + 1] = '\0';

      LOGGER_INFO("Permission for service %s: %s", sp->name, sp->allowed_clients);
    }
    cur = endl + 1;
    sp++;
    no_line++;
  }

  rc = 0;

exit:
  if (permissions_file_content) free(permissions_file_content);
  return rc;
}

static int
_is_service_allowed_for_client(const char *service, const char *user)
{
  Service_Permission *sp;

  sp = services_permissions;
  while (sp && sp->name)
  {
    if (!strcmp(sp->name, service))
    {
      if (strstr(sp->allowed_clients, ":all:") != NULL || strstr(sp->allowed_clients, user) != NULL)
      {
        return 1;
      }
    }
    sp++;
  }
  return 0;
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
    LOGGER_ERROR("getaddrinfo: %s", gai_strerror(s));
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

  LOGGER_ERROR("Could not bind");
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

  /* Create the socket. */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
  {
    perror("socket");
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
  {
    perror("setsockopt");
    return -1;
  }

  /* Bind a name to the socket. */
  name.sun_family = AF_UNIX;
  strncpy(name.sun_path, filename, sizeof(name.sun_path));
  name.sun_path[sizeof(name.sun_path) - 1] = '\0';
  name.sun_path[0] = '\0';

  if (bind(sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)) < 0)
  {
    perror("bind");
    return -1;
  }

  listen(sock, 5);

  return sock;
}

static int
_handle_server(Connection *conn, uint8_t is_blocking)
{
  int rv;

  switch (conn->state)
  {
    case STATE_WAIT_FOR_CONNECTION_REQUEST:
    {
      Connection *server_conn;
      ServerConnectionRequest req;

      memset(&req, 0, sizeof(req));

      rv = recv(conn->fd, &req, sizeof(req), MSG_WAITALL);
      if (rv <= 0)
      {
        if (rv < 0) LOGGER_ERROR("recv from server failed: %s", strerror(errno));
        return -1;
      }

      /* Check the service is a NULL terminated string */
      if (memchr(req.service, '\0', sizeof(req.service)) == NULL)
      {
        LOGGER_ERROR("Service name %.*s... for socket %d too long", (int)sizeof(req.service), req.service, conn->fd);
        send(conn->fd, &(int){1}, sizeof(int), 0);
        return -1;
      }

      /* Check that no app is already connected to the requested service */
      server_conn = _server_find_by_name(req.service);
      if (server_conn && server_conn->fd != 0)
      {
        LOGGER_ERROR("Service %s already registered", req.service);
        send(conn->fd, &(int){1}, sizeof(int), 0);
        return -1;
      }

      conn->name = strdup(req.service);
      conn->state = STATE_OPERATIONAL;

      LOGGER_INFO("Service %s registered", req.service);

      send(conn->fd, &(int){0}, sizeof(int), 0);
      break;
    }
    case STATE_OPERATIONAL:
    {
      Connection *client;
      ServerApp2Server_Header s_info;
      Client_Header *c_info;
      char *data;

      LOGGER_INFO("Handle zcure server fd = %d", conn->fd);
      memset(&s_info, 0, sizeof(s_info));

      rv = recv(conn->fd, &s_info, sizeof(s_info), is_blocking ? MSG_WAITALL : MSG_DONTWAIT);
      if (rv <= 0 || rv != sizeof(s_info))
      {
        if (is_blocking == 0) return -1;
        if (rv < 0) LOGGER_ERROR("recv Server2ServerApp_Header failed: %s", strerror(errno));
        return -1;
      }

      client = _client_find_by_id(s_info.dest_id);
      if (client == NULL)
      {
        LOGGER_ERROR("Client with id %d not found", s_info.dest_id);
        /* Positive return code to not close the server connection when a client disconnected suddenly */
        return 1;
      }

      // FIXME: check size limitation

      data = malloc(sizeof(Client_Header) + s_info.size);
      c_info = (Client_Header *)data;
      c_info->size = s_info.size;
      zcure_data_randomize(sizeof(c_info->iv), c_info->iv);

      rv = recv(conn->fd, data + sizeof(Client_Header), c_info->size, MSG_WAITALL);
      if (rv <= 0)
      {
        if (rv < 0) LOGGER_ERROR("recv data from server failed: %s", strerror(errno));
        return -1;
      }
      if (rv != (int)c_info->size)
      {
        LOGGER_ERROR("recv: wrong size received %d, expected %d", rv, c_info->size);
        return -1;
      }

      /*
       * Data to authenticate: size + data
       * Data to decrypt: data
       */
      rv = zcure_gcm_encrypt(client->aes_gcm_key, c_info->iv, sizeof(c_info->iv),
                             data, sizeof(c_info->size) + sizeof(c_info->iv),
                             data + sizeof(Client_Header), c_info->size,
                             data + sizeof(Client_Header),
                             c_info->tag, sizeof(c_info->tag));
      if (rv != 0)
      {
        LOGGER_ERROR("zcure_gcm_encrypt data from service %s to client %s failed", conn->name, client->name);
        return -1;
      }

      rv = send(client->fd, data, sizeof(Client_Header) + c_info->size, 0);
      if (rv != (int)(sizeof(Client_Header) + c_info->size))
      {
        LOGGER_ERROR("send to client %s failed: %s", conn->name, strerror(errno));
        return -1;
      }

      LOGGER_INFO("xfer %d bytes from app server %d to zcure client %d", c_info->size, conn->fd, client->fd);
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
_handle_client(Connection *conn, uint8_t is_blocking)
{
  int rv;
  Server2ServerApp_Header hdr;

  switch (conn->state)
  {
    case STATE_WAIT_FOR_CONNECTION_REQUEST:
    {
      int nb_bytes;
      int data_size;
      unsigned char *ecdh_key = NULL;
      int secret_len = 32;
      unsigned char iv0[12] = {0};
      ClientConnectionRequest conn_req;
      ClientConnectionResponse conn_rsp;
      Server2ServerApp_ClientConnectNotification notif;

      /* Receive the encrypted ClientConnectionRequest */
      LOGGER_INFO("Recv ClientConnectionRequest");
      data_size = recv(conn->fd, &conn_req, sizeof(ClientConnectionRequest), MSG_WAITALL);
      if (data_size != sizeof(ClientConnectionRequest))
      {
        LOGGER_ERROR("recv ClientConnectionRequest (size %d/%ld) failed: %s", data_size, sizeof(ClientConnectionRequest), strerror(errno));
        return -1;
      }

      /* Check the username is a NULL terminated string */
      if (memchr(conn_req.username, '\0', sizeof(conn_req.username)) == NULL)
      {
        LOGGER_ERROR("Invalid username in request from client");
        return -1;
      }

      ecdh_key = zcure_ecdh_key_compute_for_username(conn_req.username, conn_req.salt, sizeof(conn_req.salt), secret_len);
      if (ecdh_key == NULL)
      {
        LOGGER_ERROR("Failed to compute ECDH key for client %s", conn_req.username);
        return -1;
      }

      /*
       * Data to authenticate: username + salt + service
       * Data to decrypt: service
       */
      LOGGER_INFO("Decrypt ClientConnectionRequest");
      rv = zcure_gcm_decrypt(ecdh_key, iv0, sizeof(iv0),
                             conn_req.username, sizeof(conn_req.username) + sizeof(conn_req.salt),
                             conn_req.service, sizeof(conn_req.service),
                             conn_req.service,
                             conn_req.tag, sizeof(conn_req.tag));
      if (rv != 0)
      {
        LOGGER_ERROR("GCM Decryption of ClientConnectionRequest from client %s failed", conn_req.username);
        return -1;
      }

      /* Force the service to be a NULL terminated string */
      conn_req.service[sizeof(conn_req.service) - 1] = '\0';

      conn->service = _server_find_by_name(conn_req.service);
      if (!conn->service)
      {
        LOGGER_ERROR("Service in request from client unknown: %s", conn_req.service);
        return -1;
      }

      if (!_is_service_allowed_for_client(conn_req.service, conn_req.username))
      {
        LOGGER_ERROR("Client %s not allowed for service %s", conn_req.username, conn_req.service);
        return -1;
      }

      /* Prepare connection response */
      zcure_data_randomize(sizeof(conn_rsp), &conn_rsp);

      /* Store AES info */
      memcpy(conn->aes_gcm_key, conn_rsp.aes_gcm_key, sizeof(conn_rsp.aes_gcm_key));
      conn_rsp.status = 0;
      conn_rsp.id = conn->id;

      /*
       * Data to encrypt: response - tag
       */
      LOGGER_INFO("Encrypt ClientConnectionResponse");
      rv = zcure_gcm_encrypt(ecdh_key, conn_rsp.iv, sizeof(conn_rsp.iv),
                             conn_rsp.iv, sizeof(conn_rsp.iv),
                             &(conn_rsp.status), offsetof(ClientConnectionResponse, tag) - offsetof(ClientConnectionResponse, status),
                             &(conn_rsp.status),
                             conn_rsp.tag, sizeof(conn_rsp.tag));
      if (rv != 0)
      {
        LOGGER_ERROR("GCM Encryption of ClientConnectionResponse to client %s failed", conn_req.username);
        return -1;
      }

      conn->state = STATE_OPERATIONAL;
      conn->name = strdup(conn_req.username);

      LOGGER_INFO("Connection from client %s (%d) to service %s", conn->name, conn->id, conn_req.service);
      memset(ecdh_key, '0', secret_len);
      free(ecdh_key);

      /* Send the encrypted ClientConnectionResponse */
      nb_bytes = send(conn->fd, &conn_rsp, sizeof(conn_rsp), 0);
      LOGGER_INFO("Send ClientConnectionResponse: %d", nb_bytes);

      if (nb_bytes > 0)
      {
        /* Notify the server about the new client connection */
        hdr.size = sizeof(notif);
        hdr.data_type = CLIENT_CONNECT_NOTIFICATION;
        hdr.src_id = conn->id;
        notif.ip = conn->ip;
        strcpy(notif.name, conn->name);

        send(conn->service->fd, &hdr, sizeof(hdr), MSG_DONTWAIT);
        send(conn->service->fd, &notif, sizeof(notif), MSG_DONTWAIT);
      }

      return nb_bytes;
    }
    case STATE_OPERATIONAL:
    {
      Client_Header c_info;
      Server2ServerApp_Header *s_info;
      char *data;

      LOGGER_INFO("Handle zcure client fd = %d", conn->fd);

      /* Receive the header */
      rv = recv(conn->fd, &c_info, sizeof(Client_Header), is_blocking ? MSG_WAITALL : MSG_DONTWAIT);
      if (rv != sizeof(Client_Header))
      {
        if (is_blocking == 0) return -1;
        if (rv < 0) LOGGER_ERROR("recv Client_Header failed: %s", strerror(errno));

        /* Notify the server about the client disconnection */
        hdr.size = 0;
        hdr.data_type = CLIENT_DISCONNECT_NOTIFICATION;
        hdr.src_id = conn->id;

        send(conn->service->fd, &hdr, sizeof(hdr), 0);
        return -1;
      }

      // FIXME: check size limitation

      data = malloc(sizeof(Server2ServerApp_Header) + c_info.size);
      memset(data, 0, sizeof(Server2ServerApp_Header));
      s_info = (Server2ServerApp_Header *)data;
      s_info->size = c_info.size;
      s_info->src_id = conn->id;
      s_info->data_type = CLIENT_DATA;

      rv = recv(conn->fd, data + sizeof(Server2ServerApp_Header), c_info.size, MSG_WAITALL);
      if (rv <= 0)
      {
        if (rv < 0) LOGGER_ERROR("recv Server2ServerApp_Header failed: %s", strerror(errno));
        return -1;
      }

      /*
       * Data to authenticate: size + data
       * Data to decrypt: data
       */
      rv = zcure_gcm_decrypt(conn->aes_gcm_key, c_info.iv, sizeof(c_info.iv),
                             &c_info, sizeof(c_info.size) + sizeof(c_info.iv),
                             data + sizeof(Server2ServerApp_Header), c_info.size,
                             data + sizeof(Server2ServerApp_Header),
                             c_info.tag, sizeof(c_info.tag));
      if (rv != 0)
      {
        LOGGER_ERROR("zcure_gcm_decrypt from client %s failed", conn->name);
        return -1;
      }

      if (conn->service)
      {
        rv = send(conn->service->fd, data, sizeof(Server2ServerApp_Header) + c_info.size, MSG_DONTWAIT);
        LOGGER_INFO("xfer %d bytes from zcure client %d to app server %d", c_info.size, conn->fd, conn->service->fd);
      }
      else
      {
        LOGGER_ERROR("No server for the client %s", conn->name);
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
  LOGGER_ERROR("%s -p/--port port", prg_name);
}

static void
_connection_close(Connection *conn, int epoll_fd)
{
  if (!conn) return;

  if (conn->is_server)
  {
    LOGGER_INFO("Connection closed with server %s", conn->name);
  }
  else
  {
    LOGGER_INFO("Connection closed with client %s", conn->name);
  }
  close(conn->fd);
  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
  _connection_free(conn);
}

int main(int argc, char **argv)
{
  char *permissions_file_content = NULL;
  int master_fd = -1, local_fd = -1, epoll_fd = -1, event_count, i;
  int rv = EXIT_FAILURE;
  struct epoll_event event = {0}, events[MAX_EVENTS];

  LOGGER_INFO("START");

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
    LOGGER_ERROR("Port not provided");
    _help(argv[0]);
    return EXIT_FAILURE;
  }

  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1)
  {
    LOGGER_ERROR("Failed to create epoll file descriptor");
    return EXIT_FAILURE;
  }

  master_fd = _server_create(_port);
  if (master_fd == -1)
  {
    LOGGER_ERROR("Cannot create a server on port %s", _port);
    return EXIT_FAILURE;
  }

  event.events = EPOLLIN | EPOLLET;
  event.data.fd = master_fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, master_fd, &event))
  {
    perror("epoll_ctl");
    goto exit;
  }

  local_fd = _create_local_socket("#zcure_server");
  if (local_fd == -1)
  {
    LOGGER_ERROR("Cannot create a local socket");
    return EXIT_FAILURE;
  }

  event.events = EPOLLIN | EPOLLET;
  event.data.fd = local_fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, local_fd, &event))
  {
    perror("epoll_ctl");
    goto exit;
  }

  if (_permissions_parse() != 0)
  {
    LOGGER_ERROR("Failed to parse the permissions config file");
    goto exit;
  }

  LOGGER_INFO("INIT DONE");

  while(1)
  {
    event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
//    LOGGER_INFO("EPOLL wake up for %d events", event_count);

    for (i = 0; i < event_count; i++)
    {
      if (events[i].data.fd == master_fd)
      {
        /* New secure connection from client */
        Connection *conn;
        int new_fd;
        struct sockaddr_in in_addr;
        socklen_t in_len = sizeof in_addr;
        new_fd = accept(master_fd, (struct sockaddr *)&in_addr, &in_len);
        if (new_fd == -1)
        {
          LOGGER_ERROR("remote accept failed: %s", strerror(errno));
          continue;
        }

        conn = calloc(1, sizeof(Connection));
        conn->is_server = 0;
        conn->fd = new_fd;
        conn->state = STATE_WAIT_FOR_CONNECTION_REQUEST;
        conn->id = ++_last_id;
        conn->ip = in_addr.sin_addr.s_addr;

        conn->next = _connections;
        if (_connections) _connections->prev = conn;
        _connections = conn;

        event.data.ptr = conn;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event))
        {
          LOGGER_ERROR("remote epoll_ctl failed: %s", strerror(errno));
          close(new_fd);
          continue;
        }

        LOGGER_INFO("Connection from client %d", conn->id);
      }
      else if (events[i].data.fd == local_fd)
      {
        /* New local connection from server application */
        Connection *conn;
        int new_fd;
        struct sockaddr in_addr;
        socklen_t in_len = sizeof in_addr;
        new_fd = accept(local_fd, &in_addr, &in_len);
        if (new_fd == -1)
        {
          LOGGER_ERROR("local accept failed: %s", strerror(errno));
          continue;
        }

        conn = calloc(1, sizeof(Connection));
        conn->is_server = 1;
        conn->fd = new_fd;
        conn->state = STATE_WAIT_FOR_CONNECTION_REQUEST;

        conn->next = _connections;
        if (_connections) _connections->prev = conn;
        _connections = conn;

        event.data.ptr = conn;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event))
        {
          LOGGER_ERROR("local epoll_ctl failed: %s", strerror(errno));
          close(new_fd);
          continue;
        }

        LOGGER_INFO("Connection from server");
      }
      else
      {
        Connection *conn = events[i].data.ptr;
        if (conn != NULL)
        {
//          LOGGER_INFO("EPOLL event %d fd %d is_server %d events %X", i, conn->fd, conn->is_server, events[i].events);
          if ((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLHUP))
          {
            _connection_close(conn, epoll_fd);
          }
          else
          {
            if (conn->is_server)
            {
              /* Data coming from a server application */
              if (_handle_server(conn, 1) <= 0)
              {
                LOGGER_INFO("Closing connection with server: Name=%s fd=%d", conn->name ? conn->name : "none", conn->fd);
                _connection_close(conn, epoll_fd);
              }
              else
              {
                while (_handle_server(conn, 0) > 0);
              }
            }
            else
            {
              /* Data coming from a client */
              if (_handle_client(conn, 1) <= 0)
              {
                LOGGER_INFO("Closing connection with client: Name=%s id=%d fd=%d", conn->name ? conn->name : "none", conn->id, conn->fd);
                _connection_close(conn, epoll_fd);
              }
              else
              {
                while (_handle_client(conn, 0) > 0);
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

  if (permissions_file_content) free(permissions_file_content);
  return rv;
}
