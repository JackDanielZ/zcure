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
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "zcure_common.h"

#define BUF_SIZE 500
#define MAX_EVENTS 5

typedef enum
{
  STATE_INIT,
  STATE_WAIT_FOR_CLIENT_CHALLENGE,
  STATE_WAIT_FOR_CLIENT_CHALLENGE_RESPONSE,
} Connection_State;

typedef struct
{
  int fd;
  Connection_State state;
  unsigned char aes_cbc_key[32];
  unsigned char aes_cbc_iv[AES_BLOCK_SIZE];
  unsigned char challenge[32];
} Connection;

static const char *_port = NULL;

static unsigned char *_cert_data = NULL;
static unsigned int _cert_data_size = 0;

static unsigned char *_priv_data = NULL;
static unsigned int _priv_data_size = 0;
static EVP_PKEY *_priv_key = NULL;

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
_handle_request(Connection *conn)
{
  /*
  char read_buffer[100];

  int nb_bytes = recv(conn->fd, buf, max_nb_bytes, 0);
  if (nb_bytes <= 0) return nb_bytes;
  */

  switch (conn->state)
  {
    case STATE_INIT:
    {
      char c;
      if (recv(conn->fd, &c, 1, 0) != 1)
      {
        perror("recv");
        return -1;
      }

      if (c != CERT_GET_OP)
      {
        fprintf(stderr, "Invalid first init byte\n");
        return -1;
      }

      conn->state = STATE_WAIT_FOR_CLIENT_CHALLENGE;

      return send(conn->fd, _cert_data, _cert_data_size, 0);
    }
    case STATE_WAIT_FOR_CLIENT_CHALLENGE:
    {
      unsigned char buf[1000];
      int data_size;
      void *out;
      unsigned int out_len;
      ClientChallengeRequest *ccr;
      ServerChallengeResponse scr;

      /* Receive the encrypted CCReq */
      data_size = recv(conn->fd, buf, sizeof(buf), 0);
      if (data_size <= 0)
      {
        if (data_size < 0) perror("recv");
        return -1;
      }

      /* Decrypt CCReq */
      out_len = zcure_asym_decrypt(buf, data_size, _priv_key, &out);
      if (out_len <= 0)
      {
        fprintf(stderr, "Decryption failed\n");
        return -1;
      }

      /* Extraction and verification of the username */
      ccr = (ClientChallengeRequest *)out;
      ccr->username[sizeof(ccr->username) - 1] = '\0';
      EVP_PKEY *user_pkey = retrieve_key_by_username(ccr->username, 0);
      if (!user_pkey)
      {
        fprintf(stderr, "No public key found for user %s\n", ccr->username);
        return -1;
      }

      /* Prepare SCRsp */
      zcure_data_randomize(sizeof(scr), &scr);
      memcpy(scr.challenge_response, ccr->challenge_request, sizeof(scr.challenge_response));

      /* Store AES info and challenge */
      memcpy(conn->aes_cbc_key, scr.aes_cbc_key, sizeof(scr.aes_cbc_key));
      memcpy(conn->aes_cbc_iv, scr.aes_cbc_iv, sizeof(scr.aes_cbc_iv));
      memcpy(conn->challenge, scr.challenge_request, sizeof(scr.challenge_request));

      /* Encrypt SCRsp */
      out_len = zcure_asym_encrypt(&scr, sizeof(scr), user_pkey, &out);

      conn->state = STATE_WAIT_FOR_CLIENT_CHALLENGE_RESPONSE;

      /* Send the encrypted SCRsp */
      return send(conn->fd, out, out_len, 0);
    }
    case STATE_WAIT_FOR_CLIENT_CHALLENGE_RESPONSE:
    {
      unsigned char buf[1000];
      int data_size;
      void *out;
      int out_len;
      ClientChallengeResponse *ccr;

      /* Receive the encrypted CCRsp */
      data_size = recv(conn->fd, buf, sizeof(buf), 0);
      if (data_size <= 0)
      {
        if (data_size < 0) perror("recv");
        return -1;
      }

      /* Decrypt CCRsp */
      out_len = zcure_sym_decrypt(buf, data_size, conn->aes_cbc_key, conn->aes_cbc_iv, &out);
      if (out_len <= 0)
      {
        fprintf(stderr, "Decryption failed\n");
        return -1;
      }

      if (out_len != sizeof(ClientChallengeResponse))
      {
        fprintf(stderr, "Expecting ClientChallengeResponse of %lu bytes - received %d bytes\n",
            sizeof(ClientChallengeResponse), out_len);
        return -1;
      }

      /* Check challenge response */
      ccr = (ClientChallengeResponse *)out;
      if (memcmp(ccr->challenge_response, conn->challenge, sizeof(conn->challenge)) != 0)
      {
        fprintf(stderr, "Wrong challenge\n");
        return -1;
      }

      /* Prepare response */
      unsigned int rsp_rc = 0;

      /* Encrypt response */
      out_len = zcure_sym_encrypt(&rsp_rc, sizeof(rsp_rc), conn->aes_cbc_key, conn->aes_cbc_iv, &out);

      conn->state = STATE_WAIT_FOR_CLIENT_CHALLENGE_RESPONSE;

      /* Send the encrypted SCRsp */
      return send(conn->fd, out, out_len, 0);
    }
  }

  return -1;
}

static struct option _long_options[] =
{
  {"port",     required_argument, 0, 'p'},
  {"cert",     required_argument, 0, 'c'},
  {"priv_key", required_argument, 0, 'k'},
  {0, 0, 0, 0}
};

static void
_help(const char *prg_name)
{
  fprintf(stderr, "%s -p/--port port -c/--cert certificate -k/--priv_key private_key.pem", prg_name);
}

int main(int argc, char **argv)
{
  int master_fd = -1, epoll_fd = -1, event_count, i;
  int rv = EXIT_FAILURE;
  struct epoll_event event, events[MAX_EVENTS];
  Connection master_conn;
  const char *cert_file_name = NULL;
  const char *priv_file_name = NULL;

  while (1)
  {
    /* getopt_long stores the option index here. */
    int option_index = 0, c;

    c = getopt_long (argc, argv, "p:c:k:", _long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1) break;

    switch (c)
    {
      case 'c':
        {
          cert_file_name = optarg;
          break;
        }

      case 'k':
        {
          priv_file_name = optarg;
          break;
        }

      case 'p':
        {
          _port = optarg;
          break;
        }

      default:
        break;
    }
  }

  if (!_port || !cert_file_name || !priv_file_name)
  {
    _help(argv[0]);
    return EXIT_FAILURE;
  }

  _cert_data = get_file_content_as_string(cert_file_name, &_cert_data_size);
  if (!_cert_data || !_cert_data_size)
  {
    fprintf(stderr, "Failed to read certificate\n");
    goto exit;
  }

  _priv_data = get_file_content_as_string(priv_file_name, &_priv_data_size);
  if (!_priv_data || !_priv_data_size)
  {
    fprintf(stderr, "Failed to read private key\n");
    goto exit;
  }

  BIO *bio = BIO_new_mem_buf((void*)_priv_data, _priv_data_size);
  PEM_read_bio_PrivateKey(bio, &_priv_key, NULL, NULL);
  BIO_free(bio);
  if (!_priv_key)
  {
    fprintf(stderr, "Failed to extract private key\n");
    goto exit;
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
        if (_handle_request(conn) <= 0)
        {
          /* Closing connection */
          epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
          free(conn);
        }
      }
    }
  }

exit:
  if (_cert_data) free(_cert_data);

  if (epoll_fd != -1 && close(epoll_fd)) perror("close");

  if (master_fd != -1 && close(master_fd)) perror("close");

  return rv;
}
