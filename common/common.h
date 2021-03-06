#ifndef __ZCURE_COMMON_H__
#define __ZCURE_COMMON_H__

#include <stdint.h>

#define AES_BLOCK_SIZE 16

#define USERNAME_SIZE 32

#define SERVICE_SIZE 32

#define PRINT_BUFFER(name, buf, size) \
  printf("%s:\n  ", name); \
  for (unsigned int __i = 0; __i < size; __i++) printf("%02X ", ((unsigned char *)buf)[__i]); \
  printf("\n");

/*
Alice: calculate ECDH(Alice, Bob) -> key
Alice->Bob: gcm_encrypt(key, {"Alice", service}, tag)
Bob:
- Extract username
- Look for user public key
- Calculate ECDH(Alice, Bob) -> key
- gcm_decrypt(key and validate tag
- Generate cbc_key and cbc_iv
Bob->Alice: gcm_encrypt(key, {NULL, cbc_key, cbc_size}, tag)
Alice:
- gcm_decrypt(key) and validate tag
- Extract key and iv
*/

/*
 * Username and service sent by the client to the server
 * Encrypted with ECDH (server public key, client private key)
 */
typedef struct
{
  char username[USERNAME_SIZE]; /* Must be terminated with '\0' */
  uint8_t salt[128];
  char service[SERVICE_SIZE]; /* Must be terminated with '\0' */
  uint8_t tag[16];
} ClientConnectionRequest;

/*
 * Challenge response + AES key sent by the server to the client
 * Encrypted with ECDH(client public key, server private key) stored into the server database
 */
typedef struct
{
  uint8_t status;
  uint8_t aes_gcm_key[32];
  uint8_t aes_gcm_iv[AES_BLOCK_SIZE];
  uint8_t tag[16];
} ClientConnectionResponse;

typedef struct
{
  uint32_t size;
  uint8_t tag[16];
} Client_Data_Info;

char *
get_file_content_as_string(const char *filename, unsigned int *size);

unsigned char *
zcure_ecdh_key_compute_for_username(const char *username, unsigned char *salt, unsigned int salt_len, unsigned int secret_len);

void
zcure_data_randomize(unsigned int nb, void *out_buf);

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
                  unsigned int tag_len);

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
                  unsigned int tag_len);

#endif /* __ZCURE_COMMON_H__ */
