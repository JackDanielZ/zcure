#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <curl/curl.h>

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

#include "zcure_client.h"
#include "zcure_common.h"

typedef struct
{
  unsigned char *data;
  unsigned int size;
} MemoryStruct;

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

static size_t
_curl_write_data(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  MemoryStruct *mem = (MemoryStruct *)userp;

  unsigned char *ptr = realloc(mem->data, mem->size + realsize + 1);
  if(ptr == NULL)
  {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->data = ptr;
  memcpy(&(mem->data[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->data[mem->size] = 0;

  return realsize;
}

static int
_curl_download(const char *uri, MemoryStruct *mem)
{
  CURL *curl_handle;

  curl_global_init(CURL_GLOBAL_ALL);

  mem->size = 0;

  /* init the curl session */
  curl_handle = curl_easy_init();

  /* set URL to get here */
  curl_easy_setopt(curl_handle, CURLOPT_URL, uri);

  /* disable progress meter, set to 0L to enable it */
  curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

  /* send all data to this function  */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, _curl_write_data);

  /* write the page body to the memory handle */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, mem);

  /* get it! */
  curl_easy_perform(curl_handle);

  /* cleanup curl stuff */
  curl_easy_cleanup(curl_handle);

  curl_global_cleanup();

  return 0;
}

static X509 *
_main_certificate_retrieve(int fd)
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

static int
_append_ia5(STACK_OF(OPENSSL_STRING) **sk, const ASN1_IA5STRING *email)
{
  char *emtmp;

  /* First some sanity checks */
  if (email->type != V_ASN1_IA5STRING) return 1;
  if (!email->data || !email->length) return 1;

  if (*sk == NULL) *sk = sk_OPENSSL_STRING_new_null();
  if (*sk == NULL) return 0;

  /* Don't add duplicates */
  if (sk_OPENSSL_STRING_find(*sk, (char *)email->data) != -1) return 1;

  emtmp = OPENSSL_strdup((char *)email->data);
  if (emtmp == NULL || !sk_OPENSSL_STRING_push(*sk, emtmp))
  {
    OPENSSL_free(emtmp); /* free on push failure */
    X509_email_free(*sk);
    *sk = NULL;
    return 0;
  }

  return 1;
}

static STACK_OF(OPENSSL_STRING) *
_X509_get_aia(X509 *x)
{
  AUTHORITY_INFO_ACCESS *info;
  STACK_OF(OPENSSL_STRING) *ret = NULL;
  int i;

  info = X509_get_ext_d2i(x, NID_info_access, NULL, NULL);
  if (!info) return NULL;

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++)
  {
    ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
    if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers)
    {
      if (ad->location->type == GEN_URI)
      {
        if (!_append_ia5(&ret, ad->location->d.uniformResourceIdentifier))
          break;
      }
    }
  }
  AUTHORITY_INFO_ACCESS_free(info);
  return ret;
}

static STACK_OF(X509) *
_x509_extract(MemoryStruct *mem)
{
  X509 *x;
  PKCS7 *p7;
  BIO *bio;
  STACK_OF(X509) *certs = sk_X509_new_null();

  bio = BIO_new_mem_buf(mem->data, mem->size);
  x = d2i_X509_bio(bio, NULL);
  BIO_free(bio);
  if (x)
  {
    sk_X509_push(certs, x);
    return certs;
  }

  bio = BIO_new_mem_buf(mem->data, mem->size);
  p7 = d2i_PKCS7_bio(bio, NULL);
  BIO_free(bio);
  if (p7)
  {
    int nid=OBJ_obj2nid(p7->type);
    switch (nid)
    {
      case NID_pkcs7_signed:
        return p7->d.sign->cert;
      case NID_pkcs7_signedAndEnveloped:
        return p7->d.signed_and_enveloped->cert;
      default:
        PKCS7_free(p7);
    }
  }
  return NULL;
}

static int
_build_chain_of_trust(X509_STORE *x_store, X509 *cert_prev)
{
  X509 *cert = NULL;
  MemoryStruct cert_mem = {0};
  STACK_OF(X509) *certs;
  int i, rv = 0;

  STACK_OF(OPENSSL_STRING) *aia = _X509_get_aia(cert_prev);
  char *aia_str = sk_OPENSSL_STRING_value(aia, 0);
  BIO_printf(_bio_output, "cert_status: AIA URL: %s\n", aia_str);

  rv = _curl_download(aia_str, &cert_mem);
  if (rv != 0)
  {
    fprintf(stderr, "Failed to download certificate at URL %s\n", aia_str);
    goto exit;
  }

  certs = _x509_extract(&cert_mem);
  for (i = 0; i < sk_X509_num(certs); i++)
  {
    cert = sk_X509_value(certs, i);
    aia = _X509_get_aia(cert);
    aia_str = sk_OPENSSL_STRING_value(aia, 0);
    if (aia_str)
    {
      BIO_printf(_bio_output, "cert_status: AIA URL: %s\n", aia_str);
      X509_STORE_add_cert(x_store, cert);
      rv = _build_chain_of_trust(x_store, cert);
      if (rv != 0) goto exit;
    }
  }

exit:
  free(cert_mem.data);
  return rv;
}

int
zcure_connect(const char *server, const char *port, const char *username)
{
  int fd;
  X509* x_cert;
  X509_STORE *x_store;
  X509_STORE_CTX *x_ctx;
  EVP_PKEY *pkey = NULL;
  ClientChallengeRequest ccr;
  unsigned char recv_buffer[1024];
  void *out;
  int size;

  if (!server || !port) return -1;

  fd = _tcp_connect(server, port);

  if (fd <= 0)
  {
    fprintf(stderr, "TCP connection failed\n");
    return -1;
  }
  printf("TCP connection to %s:%s established\n", server, port);

  x_cert = _main_certificate_retrieve(fd);
  if (!x_cert) return -1;
  printf("Certificate of %s retrieved\n", server);

  x_store = X509_STORE_new();
  x_ctx = X509_STORE_CTX_new();

  X509_STORE_set_default_paths(x_store);
  X509_STORE_CTX_init(x_ctx, x_store, x_cert, NULL);

  if (_build_chain_of_trust(x_store, x_cert) != 0)
  {
    fprintf(stderr, "Building the chain of trust for %s failed\n", server);
    return -1;
  }
  printf("Chain of trust for %s built\n", server);

  if (X509_verify_cert(x_ctx) == 0)
  {
    fprintf(stderr, "%s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(x_ctx)));
    return -1;
  }
  printf("Certificate for %s verified\n", server);

  pkey = X509_get_pubkey(x_cert);
  if (!pkey)
  {
    fprintf(stderr, "Certificate public key extraction for %s failed\n", server);
    return -1;
  }

  zcure_data_randomize(sizeof(ccr), &ccr);
  strncpy(ccr.username, username, sizeof(ccr.username) - 1);

  size = zcure_asym_encrypt(&ccr, sizeof(ccr), pkey, &out);
  if (size <= 0)
  {
    fprintf(stderr, "Encryption failed\n");
    return -1;
  }

  if (send(fd, out, size, 0) != size)
  {
    fprintf(stderr, "Sending ClientChallengeRequest failed\n");
    return -1;
  }

  size = recv(fd, recv_buffer, sizeof(recv_buffer), 0);
  if (size <= 0)
  {
    fprintf(stderr, "Error in reception of ServerChallengeResponse\n");
    return -1;
  }

  EVP_PKEY *user_pkey = retrieve_key_by_username(username, 1);
  if (!user_pkey)
  {
    fprintf(stderr, "No public key found for user %s\n", username);
    return -1;
  }

  ServerChallengeResponse *scr;
  size = zcure_asym_decrypt(recv_buffer, size, user_pkey, (void **)&scr);
  if (size != sizeof(ServerChallengeResponse))
  {
    fprintf(stderr, "Expecting ServerChallengeResponse of %lu bytes - received %d bytes\n",
        sizeof(ServerChallengeResponse), size);
    return -1;
  }

  if (memcmp(scr->challenge_response, ccr.challenge_request, sizeof(scr->challenge_response)) != 0)
  {
    fprintf(stderr, "Wrong challenge\n");
    return -1;
  }

  ClientChallengeResponse ccrsp;
  memcpy(ccrsp.challenge_response, scr->challenge_request, sizeof(ccrsp.challenge_response));

  size = zcure_sym_encrypt(&ccrsp, sizeof(ccrsp), scr->aes_cbc_key, scr->aes_cbc_iv, &out);
  if (size <= 0)
  {
    fprintf(stderr, "Encryption failed\n");
    return -1;
  }

  if (send(fd, out, size, 0) != size)
  {
    fprintf(stderr, "Sending ClientChallengeResponse failed\n");
    return -1;
  }

  size = recv(fd, recv_buffer, sizeof(recv_buffer), 0);
  if (size <= 0)
  {
    fprintf(stderr, "Error in reception of final acknowledge\n");
    return -1;
  }

  /* Decrypt acknowledge */
  unsigned int *rsp_rc;
  size = zcure_sym_decrypt(recv_buffer, size, scr->aes_cbc_key, scr->aes_cbc_iv, (void **)&rsp_rc);
  if (size <= 0)
  {
    fprintf(stderr, "Decryption failed\n");
    return -1;
  }

  if (*rsp_rc != 0)
  {
    fprintf(stderr, "Acknowledge failed\n");
    return -1;
  }
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
  EVP_cleanup();
  return 0;
}
