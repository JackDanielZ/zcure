#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "common/common.h"

unsigned int _logger_first_call = 1;
unsigned int _log_to_file = 0;

char *
get_file_content_as_string(const char *filename, unsigned int *size)
{
  char *file_data = NULL;
  long fsize = 0;
  FILE *fp;

  if (filename == NULL)
  {
    fprintf(stderr, "Invalid parameters\n");
    return NULL;
  }

  fp = fopen(filename, "rb");
  if (size) *size = 0;

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
    file_data = calloc(1, fsize + 1);
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
      if (size) *size = fsize;
    }
  }

exit:
  fclose(fp);
  return file_data;
}

unsigned char *
zcure_ecdh_key_compute_for_username(const char *username, unsigned char *salt, unsigned int salt_len, unsigned int secret_len)
{
  char path[256];
  EVP_PKEY *key = NULL;
  EC_KEY *priv_key;
  const EC_POINT *pub_key;
  BIO *bio;
  char *key_file_data;
  char *home;
  unsigned char *shared_secret;
  unsigned char *secret;

  unsigned int key_file_data_size = 0;
  unsigned int shared_secret_len;

  home = getenv("HOME");
  if (home == NULL)
  {
    fprintf(stderr, "Cannot get $HOME from getenv\n");
    return NULL;
  }

  sprintf(path, "%s/.config/zcure/local_key/mine.pem", home);
  key_file_data = get_file_content_as_string(path, &key_file_data_size);
  if (!key_file_data || !key_file_data_size)
  {
    fprintf(stderr, "Failed to read private key\n");
    return NULL;
  }

  bio = BIO_new_mem_buf((void*)key_file_data, key_file_data_size);
  PEM_read_bio_PrivateKey(bio, &key, NULL, NULL);
  BIO_free(bio);
  free(key_file_data);

  priv_key = EVP_PKEY_get1_EC_KEY(key);

  sprintf(path, "%s/.config/zcure/remote_keys/%s.pub", home, username);
  key_file_data = get_file_content_as_string(path, &key_file_data_size);
  if (!key_file_data || !key_file_data_size)
  {
    fprintf(stderr, "Failed to read key for user %s\n", username);
    return NULL;
  }

  bio = BIO_new_mem_buf((void*)key_file_data, key_file_data_size);
  PEM_read_bio_PUBKEY(bio, &key, NULL, NULL);
  BIO_free(bio);
  free(key_file_data);

  pub_key = EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(key));

  shared_secret_len = EC_GROUP_get_degree(EC_KEY_get0_group(priv_key));
  shared_secret_len = (shared_secret_len + 7) / 8;

  shared_secret = alloca(shared_secret_len + salt_len);
  if (!shared_secret)
  {
    fprintf(stderr, "Failed to allocate memory for shared_secret.\n");
    return NULL;
  }

  shared_secret_len = ECDH_compute_key(shared_secret, shared_secret_len, pub_key, priv_key, NULL);

  memcpy(shared_secret + shared_secret_len, salt, salt_len);

  secret = malloc(secret_len);
  SHA256(shared_secret, shared_secret_len + salt_len, secret);

  return secret;
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
zcure_gcm_encrypt(const unsigned char *key,
                  const unsigned char *iv,
                  unsigned int iv_len,
                  const void *aad_buf,
                  unsigned int aad_len,
                  const void *in_buf,
                  unsigned int in_len,
                  void *out_buf,
                  void *tag_buf,
                  unsigned int tag_len)
{
  EVP_CIPHER_CTX *ctx;
  int outlen, rv;

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  /* Set cipher type and mode */
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);

  /* Initialise key and IV */

  if (aad_buf)
  {
    rv = EVP_EncryptUpdate(ctx, NULL, &outlen, aad_buf, aad_len);
    if (rv == 0)
    {
      fprintf(stderr, "zcure_gcm_encrypt:EVP_EncryptUpdate AAD failed\n");
      return -1;
    }
  }

  if (in_buf)
  {
    /* Encrypt plaintext */
    rv = EVP_EncryptUpdate(ctx, out_buf, &outlen, in_buf, in_len);
    if (rv == 0)
    {
      fprintf(stderr, "zcure_gcm_encrypt:EVP_EncryptUpdate input failed\n");
      return -1;
    }
  }

  /* Finalise: note get no output for GCM */
  rv = EVP_EncryptFinal_ex(ctx, out_buf, &outlen);
  if (rv == 0)
  {
    fprintf(stderr, "zcure_gcm_encrypt:EVP_EncryptFinal_ex failed\n");
    return -1;
  }

  /* Get tag */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag_buf);

  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

int
zcure_gcm_decrypt(const unsigned char *key,
                  const unsigned char *iv,
                  unsigned int iv_len,
                  const void *aad_buf,
                  unsigned int aad_len,
                  const void *in_buf,
                  unsigned int in_len,
                  void *out_buf,
                  const void *tag_buf,
                  unsigned int tag_len)
{
  EVP_CIPHER_CTX *ctx;
  int outlen, rv;

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  /* Set cipher type and mode */
  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);

  /* Initialise key and IV */

  if (aad_buf)
  {
    rv = EVP_DecryptUpdate(ctx, NULL, &outlen, aad_buf, aad_len);
    if (rv == 0)
    {
      fprintf(stderr, "zcure_gcm_decrypt:EVP_DecryptUpdate AAD failed\n");
      return -1;
    }
  }

  if (in_buf)
  {
    /* Decrypt input */
    rv = EVP_DecryptUpdate(ctx, out_buf, &outlen, in_buf, in_len);
    if (rv == 0)
    {
      fprintf(stderr, "zcure_gcm_decrypt:EVP_DecryptUpdate input failed\n");
      return -1;
    }
  }

  /* Set tag */
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, (void*)tag_buf);

  rv = EVP_DecryptFinal_ex(ctx, out_buf, &outlen);
  if (rv == 0)
  {
    fprintf(stderr, "zcure_gcm_decrypt:EVP_DecryptFinal_ex failed\n");
    return -1;
  }

  EVP_CIPHER_CTX_free(ctx);

  return 0;
}
