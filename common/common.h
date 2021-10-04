#ifndef __ZCURE_COMMON_H__
#define __ZCURE_COMMON_H__

#include <stdint.h>
#include <sys/stat.h>

#define AES_BLOCK_SIZE 16

#define USERNAME_SIZE 32

#define SERVICE_SIZE 32

#define PRINT_BUFFER(name, buf, size) \
  printf("%s:\n  ", name); \
  for (unsigned int __i = 0; __i < size; __i++) printf("%02X ", ((unsigned char *)buf)[__i]); \
  printf("\n");

/*
Client: generate salt and calculate ECDH(client, server, salt) -> key
Client->server: gcm_encrypt(key, {"Alice", service}, tag)
Server:
- Extract username and salt
- Look for user public key
- Calculate ECDH(client, server, salt) -> key
- gcm_decrypt(key) and validate tag
- Generate gcm_key and gcm_iv
Server->client: gcm_encrypt(key, {NULL, gcm_key, gcm_size}, tag)
Client:
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
 * Encrypted with ECDH(client public key, server private key, salt), public key stored into the server database
 */
typedef struct
{
  uint8_t iv[AES_BLOCK_SIZE];
  uint8_t status;
  uint8_t aes_gcm_key[32];
  uint8_t tag[16];
} ClientConnectionResponse;

typedef struct
{
  uint32_t size;
  uint8_t iv[AES_BLOCK_SIZE];
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

/* Logger APIs */

extern char *__progname;
extern unsigned int logger_first_call;

#define LOGGER_PRINT(type, fmt, ...) \
  do { \
    FILE *logger_fp; \
    char path[256]; \
    time_t current_time = time(NULL); \
    char *timetext = asctime(localtime(&current_time)); \
    \
    timetext[strlen(timetext) - 1] = '\0'; \
    if (logger_first_call == 1) \
    { \
      sprintf(path, "%s/.zcure", getenv("HOME")); \
      mkdir(path, S_IRWXU); \
      sprintf(path, "%s/.zcure/logs", getenv("HOME")); \
      mkdir(path, S_IRWXU); \
    } \
    logger_first_call = 0; \
    sprintf(path, "%s/.zcure/logs/%s.log", getenv("HOME"), __progname); \
    logger_fp = fopen(path, "a"); \
    if (logger_fp != NULL) \
    { \
      fprintf(logger_fp, "%s <%s> " fmt "\n", timetext, type, ## __VA_ARGS__); \
      fflush(logger_fp); \
      fclose(logger_fp); \
    } \
  } while (0);

#define LOGGER_INFO(fmt, ...) LOGGER_PRINT("INFO", fmt, ## __VA_ARGS__);
#define LOGGER_ERROR(fmt, ...) LOGGER_PRINT("ERROR", fmt, ## __VA_ARGS__);

#endif /* __ZCURE_COMMON_H__ */
