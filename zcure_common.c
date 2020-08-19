#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

size_t
zcure_asym_encrypt(const unsigned char *in_buf, size_t in_len, EVP_PKEY *pkey, unsigned char **out_buf)
{
  int rv;
  size_t out_len;
  EVP_PKEY_CTX *pk_ctx;

  pk_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!pk_ctx)
  {
    fprintf(stderr, "EVP_PKEY_CTX_new failed\n");
    return -1;
  }
  if (EVP_PKEY_encrypt_init(pk_ctx) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_encrypt_init failed\n");
    return -1;
  }
  if ((rv = EVP_PKEY_encrypt(pk_ctx, NULL, &out_len, in_buf, in_len)) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_encrypt failed: %d\n", rv);
    return -1;
  }

  *out_buf = OPENSSL_malloc(out_len);
  memset(*out_buf, 0, out_len);
  if ((rv = EVP_PKEY_encrypt(pk_ctx, *out_buf, &out_len, in_buf, in_len)) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_encrypt failed: %d\n", rv);
    return -1;
  }

  return out_len;
}

size_t
zcure_asym_decrypt(const unsigned char *in_buf, size_t in_len, EVP_PKEY *pkey, unsigned char **out_buf)
{
  int rv;
  size_t out_len;
  EVP_PKEY_CTX *pk_ctx;

  pk_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!pk_ctx)
  {
    fprintf(stderr, "EVP_PKEY_CTX_new failed\n");
    return -1;
  }
  if (EVP_PKEY_decrypt_init(pk_ctx) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_decrypt_init failed\n");
    return -1;
  }
  if ((rv = EVP_PKEY_decrypt(pk_ctx, NULL, &out_len, in_buf, in_len)) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_decrypt failed: %d\n", rv);
    return -1;
  }

  *out_buf = OPENSSL_malloc(out_len);
  memset(*out_buf, 0, out_len);
  if ((rv = EVP_PKEY_decrypt(pk_ctx, *out_buf, &out_len, in_buf, in_len)) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_decrypt failed: %d\n", rv);
    return -1;
  }

  return out_len;
}
