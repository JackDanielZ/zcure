#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "zcure_client.h"
#include "zcure_common.h"

static BIO *_bio_output = NULL;
static unsigned char _server_cert[100*1024] = {0};
static int _server_cert_length = 0;

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

static X509 *
_certificate_retrieve(int fd)
{
  BIO *bio = NULL;
  char op = CERT_GET_OP;
  X509 *x_cert = NULL;

  if (send(fd, &op, 1, 0) != 1)
  {
    perror("Certificate request sending");
    return NULL;
  }
  if ((_server_cert_length = recv(fd, &_server_cert, sizeof(_server_cert), 0)) == -1)
  {
    perror("Certificate response reception");
    return NULL;
  }

  // Create a read-only BIO backed by the supplied memory buffer
  bio = BIO_new_mem_buf((void*)_server_cert, _server_cert_length);
  PEM_read_bio_X509(bio, &x_cert, NULL, NULL);
  BIO_free(bio);

  return x_cert;
}

int
zcure_connect(const char *server, const char *port)
{
  int fd;
  X509* x_cert;

  if (!server || !port) return -1;

  fd = _tcp_connect(server, port);

  if (fd <= 0)
  {
    fprintf(stderr, "_tcp_connect failed\n");
    return -1;
  }

  x_cert = _certificate_retrieve(fd);
  if (!x_cert) return -1;

  ASN1_INTEGER *asn1_serial = NULL;
  asn1_serial = X509_get_serialNumber(x_cert);
  if (asn1_serial == NULL)
    BIO_printf(_bio_output, "Error getting serial number from certificate");

  /* ---------------------------------------------------------- *
   * Print the serial number value, openssl x509 -serial style  *
   * ---------------------------------------------------------- */
  BIO_puts(_bio_output,"serial (openssl x509 -serial style): ");
  i2a_ASN1_INTEGER(_bio_output, asn1_serial);
  BIO_puts(_bio_output,"\n");

  return 0;
}

int
zcure_disconnect(int fd)
{
  close(fd);
  return 0;
}

int
zcure_init(void)
{
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  _bio_output = BIO_new_fp(stdout, BIO_NOCLOSE);
  return 0;
}

int
zcure_shutdown(void)
{
  return 0;
}
