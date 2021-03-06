#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>

#include "lib/client/client.h"
#include "common/common.h"

typedef struct
{
  unsigned char *data;
  unsigned int size;
} MemoryStruct;

struct Connection
{
  int cid;
  int fd;
  uint8_t aes_gcm_key[32];
  uint8_t aes_gcm_iv[AES_BLOCK_SIZE];

  struct Connection *next;
} Connection;

static BIO *_bio_output = NULL;

static struct Connection *_connections = NULL;

static struct Connection *
_connection_find_by_cid(int cid)
{
  struct Connection *c = _connections;
  while (c)
  {
    if (c->cid == cid) return c;
    c = c->next;
  }
  return NULL;
}

static int
_connection_remove(struct Connection *conn)
{
  struct Connection *c = _connections, *prev_c = NULL;
  while (c)
  {
    if (c == conn)
    {
      if (prev_c) prev_c->next = c->next;
      else _connections = c->next;
      return 0;
    }
    prev_c = c;
    c = c->next;
  }
  return -1;
}

static int
_tcp_connect(const char *host, const char *port)
{
  int s, sfd;
  struct addrinfo hints, *result, *rp;

  /* Obtain address(es) matching host/port */

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;          /* Any protocol */

  s = getaddrinfo(host, port, &hints, &result);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }

  /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully connect(2).
     If socket(2) (or connect(2)) fails, we (close the socket
     and) try the next address. */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) continue;

    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
      goto exit; /* Success */

    close(sfd);
  }

  fprintf(stderr, "Could not connect to %s:%s\n", host, port);
  sfd = -1;

exit:
  freeaddrinfo(result);           /* No longer needed */
  return sfd;
}

int
zcure_client_connect(const char *server, const char *port, const char *username, const char *service)
{
  int fd;
  unsigned char *ecdh_key = NULL;
  int secret_len = 32;
  ClientConnectionRequest conn_req;
  ClientConnectionResponse conn_rsp;
  unsigned char iv0[12] = {0};
  int size;
  int rv;

  if (!server || !port) return -1;

  fd = _tcp_connect(server, port);

  if (fd <= 0)
  {
    fprintf(stderr, "TCP connection failed\n");
    return -1;
  }
  printf("TCP connection to %s:%s established\n", server, port);

  zcure_data_randomize(sizeof(conn_req), &conn_req);
  strncpy(conn_req.username, username, sizeof(conn_req.username) - 1);
  strncpy(conn_req.service, service, sizeof(conn_req.service) - 1);

  ecdh_key = zcure_ecdh_key_compute_for_username(server, conn_req.salt, sizeof(conn_req.salt), secret_len);
  for (int i = 0; i < secret_len; i++)
    printf("%02X ", ecdh_key[i]);
  printf("\n");

  rv = zcure_gcm_encrypt(ecdh_key, iv0, sizeof(iv0),
                         conn_req.username, sizeof(conn_req.username) + sizeof(conn_req.salt),
                         conn_req.service, sizeof(conn_req.service),
                         conn_req.service,
                         conn_req.tag, sizeof(conn_req.tag));
  if (rv != 0)
  {
    fprintf(stderr, "GCM Encryption of ClientConnectionRequest failed\n");
    return -1;
  }

  if (send(fd, &conn_req, sizeof(ClientConnectionRequest), 0) != sizeof(ClientConnectionRequest))
  {
    fprintf(stderr, "Sending ClientConnectionRequest failed\n");
    return -1;
  }

  size = recv(fd, &conn_rsp, sizeof(conn_rsp), 0);
  if (size <= 0)
  {
    fprintf(stderr, "Error in reception of ClientConnectionResponse\n");
    return -1;
  }

  rv = zcure_gcm_decrypt(ecdh_key, iv0, sizeof(iv0),
                         NULL, 0,
                         &conn_rsp, sizeof(conn_rsp) - sizeof(conn_rsp.tag),
                         &conn_rsp,
                         conn_rsp.tag, sizeof(conn_rsp.tag));
  if (rv != 0)
  {
    fprintf(stderr, "GCM Decryption of ClientConnectionResponse failed\n");
    return -1;
  }

  struct Connection *c = calloc(1, sizeof(*c));
  c->fd = fd;
  memcpy(c->aes_gcm_key, conn_rsp.aes_gcm_key, sizeof(c->aes_gcm_key));
  memcpy(c->aes_gcm_iv, conn_rsp.aes_gcm_iv, sizeof(c->aes_gcm_iv));

  c->cid = fd;
  c->next = _connections;
  _connections = c;

  return c->cid;
}

int
zcure_client_disconnect(int cid)
{
  struct Connection *c = _connection_find_by_cid(cid);
  if (!c) return -1;

  _connection_remove(c);

  free(c);
  return 0;
}

int zcure_client_send(int cid, const void *plain_buffer, unsigned int plain_size)
{
  void *cipher_buffer = NULL;
  unsigned int nb_sent_bytes;
  Client_Data_Info *c_info;
  struct Connection *c = _connection_find_by_cid(cid);
  int rv;

  if (!c) return -1;

  cipher_buffer = malloc(sizeof(Client_Data_Info) + plain_size);

  c_info = (Client_Data_Info *)cipher_buffer;
  c_info->size = plain_size;

  rv = zcure_gcm_encrypt(c->aes_gcm_key, c->aes_gcm_iv, sizeof(c->aes_gcm_iv),
                         c_info, sizeof(c_info->size),
                         plain_buffer, plain_size,
                         cipher_buffer + sizeof(Client_Data_Info),
                         c_info->tag, sizeof(c_info->tag));
  if (rv != 0)
  {
    fprintf(stderr, "Cannot gcm encrypt data\n");
    return -1;
  }
  else
  {
    nb_sent_bytes = send(c->fd, cipher_buffer, sizeof(Client_Data_Info) + plain_size, 0);
    if (nb_sent_bytes != sizeof(Client_Data_Info) + plain_size)
    {
      fprintf(stderr, "Cannot send all the data through the secure channel\n");
      return -1;
    }
  }

  free(cipher_buffer);

  return plain_size;
}

int zcure_client_receive(int cid, void **plain_buffer)
{
  void *cipher_buffer = NULL;
  Client_Data_Info c_info;
  struct Connection *c = _connection_find_by_cid(cid);
  int rv;

  if (!plain_buffer) return -1;

  if (!c) return -1;

  rv = recv(c->fd, &c_info, sizeof(Client_Data_Info), 0);
  if (rv != sizeof(Client_Data_Info))
  {
    perror("recv info from server");
    return -1;
  }

  cipher_buffer = malloc(c_info.size);

  rv = recv(c->fd, cipher_buffer, c_info.size, 0);
  if (rv != (int)c_info.size)
  {
    perror("recv data from server");
    return -1;
  }

  rv = zcure_gcm_decrypt(c->aes_gcm_key, c->aes_gcm_iv, sizeof(c->aes_gcm_iv),
                         &c_info, sizeof(c_info.size),
                         cipher_buffer, c_info.size,
                         cipher_buffer,
                         c_info.tag, sizeof(c_info.tag));
  if (rv != 0)
  {
    fprintf(stderr, "Cannot GCM decrypt data\n");
    return -1;
  }

  *plain_buffer = cipher_buffer;

  return c_info.size;
}

int
zcure_client_init(void)
{
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  _bio_output = BIO_new_fp(stdout, BIO_NOCLOSE);

  return 0;
}

int
zcure_client_shutdown(void)
{
  EVP_cleanup();
  return 0;
}
