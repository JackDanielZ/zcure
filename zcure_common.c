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

unsigned char *
get_file_content_as_string(const char *filename, unsigned int *size)
{
  unsigned char *file_data = NULL;
  long fsize = 0;
  FILE *fp;

  if (filename == NULL || size == NULL)
  {
    fprintf(stderr, "Invalid parameters\n");
    return NULL;
  }

  fp = fopen(filename, "rb");
  *size = 0;

  if (fp == NULL)
  {
    fprintf(stderr, "Can not open file: \"%s\".\n", filename);
    return NULL;
  }

  fseek(fp, 0, SEEK_END);
  fsize = ftell(fp);

  if (fsize < 0)
  {
    fprintf(stderr, "Can not ftell file: \"%s\".\n", filename);
    goto exit;
  }

  rewind(fp);
  if (fsize > 0)
  {
    file_data = (unsigned char *) calloc(1, fsize + 1);
    if (!file_data)
    {
      fprintf(stderr, "calloc failed\n");
      goto exit;
    }
    if (!fread(file_data, 1, fsize, fp)) {
      free(file_data);
      file_data = NULL;
      if (!feof(fp)) fprintf(stderr, "fread failed\n");
    }
    else {
      *size = fsize;
    }
  }

exit:
  fclose(fp);
  return file_data;
}

EVP_PKEY *
retrieve_key_by_username(const char *username, int is_private)
{
  char path[256];
  unsigned char *key_data;
  unsigned int key_data_size = 0;
  EVP_PKEY *key = NULL;

  sprintf(path, "~/.config/zcure/server/user_keys/%s%s.pem", username, is_private ? "_priv" : "");
  sprintf(path, "/home/daniel/%s%s.pem", username, is_private ? "_priv" : "");
  key_data = get_file_content_as_string(path, &key_data_size);
  if (!key_data || !key_data_size)
  {
    fprintf(stderr, "Failed to read key for user %s\n", username);
    return NULL;
  }

  BIO *bio = BIO_new_mem_buf((void*)key_data, key_data_size);
  if (is_private)
    PEM_read_bio_PrivateKey(bio, &key, NULL, NULL);
  else
    PEM_read_bio_PUBKEY(bio, &key, NULL, NULL);
  BIO_free(bio);

  return key;
}

void
zcure_data_randomize(unsigned int nb, void *out_buf)
{
  unsigned int i;
  srand(time(NULL));
  for (i = 0; i < nb; i++)
  {
    ((unsigned char *)out_buf)[i] = rand()%256;
  }
}

int
zcure_asym_encrypt(const void *in_buf, unsigned int in_len, EVP_PKEY *pkey, void **out_buf)
{
  int rv;
  size_t out_len;
  EVP_PKEY_CTX *pk_ctx;

  *out_buf = NULL;

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

  *out_buf = malloc(out_len);
  memset(*out_buf, 0, out_len);
  if ((rv = EVP_PKEY_encrypt(pk_ctx, *out_buf, &out_len, in_buf, in_len)) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_encrypt failed: %d\n", rv);
    return -1;
  }

  return out_len;
}

int
zcure_asym_decrypt(const void *in_buf, unsigned int in_len, EVP_PKEY *pkey, void **out_buf)
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

  *out_buf = malloc(out_len);
  memset(*out_buf, 0, out_len);
  if ((rv = EVP_PKEY_decrypt(pk_ctx, *out_buf, &out_len, in_buf, in_len)) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_decrypt failed: %d\n", rv);
    return -1;
  }

  return out_len;
}

int
zcure_sym_encrypt(const void *in_buf,
                  unsigned int in_len,
                  const unsigned char *key,
                  const unsigned char *iv,
                  void **out_buf)
{
  int update_out_len, final_out_len;
  EVP_CIPHER_CTX *ctx;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
    return -1;
  }
  EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);

  *out_buf = malloc(in_len + AES_BLOCK_SIZE - 1);

  if (EVP_EncryptUpdate(ctx, *out_buf, &update_out_len, in_buf, in_len) <= 0)
  {
    fprintf(stderr, "EVP_EncryptUpdate failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  if (EVP_EncryptFinal(ctx, *out_buf + update_out_len, &final_out_len) <= 0)
  {
    fprintf(stderr, "EVP_EncryptFinal failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  return update_out_len + final_out_len;
}

int
zcure_sym_decrypt(const void *in_buf,
                  unsigned int in_len,
                  const unsigned char *key,
                  const unsigned char *iv,
                  void **out_buf)
{
  int update_out_len, final_out_len;
  EVP_CIPHER_CTX *ctx;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
    return -1;
  }
  EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);

  *out_buf = malloc(in_len + AES_BLOCK_SIZE - 1);

  if (EVP_DecryptUpdate(ctx, *out_buf, &update_out_len, in_buf, in_len) <= 0)
  {
    fprintf(stderr, "EVP_DecryptUpdate failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  if (EVP_DecryptFinal(ctx, *out_buf + update_out_len, &final_out_len) <= 0)
  {
    fprintf(stderr, "EVP_DecryptFinal failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  return update_out_len + final_out_len;
}
