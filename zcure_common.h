#ifndef __ZCURE_COMMON_H__
#define __ZCURE_COMMON_H__

#define AES_BLOCK_SIZE 16

#define CERT_GET_OP 0

/*
 * Username and challenge sent by the client to the server
 * Encrypted with the server certificate public key
 */
typedef struct
{
  char username[32]; /* Must be terminated with '\0' */
  uint8_t challenge_request[32];
} ClientChallengeRequest;

/*
 * Challenge response + AES key sent by the server to the client
 * Encrypted with the client public key stored into the server database
 */
typedef struct
{
  uint8_t challenge_response[32];
  uint8_t challenge_request[32];
  uint8_t aes_cbc_key[32];
  uint8_t aes_cbc_iv[AES_BLOCK_SIZE];
} ServerChallengeResponse;

/*
 * Challenge response from the client to the server
 * Encrypted with the AES key previously sent by the server in ServerChallengeResponse
 */
typedef struct
{
  uint8_t challenge_response[32];
} ClientChallengeResponse;

unsigned char *
get_file_content_as_string(const char *filename, unsigned int *size);

EVP_PKEY *
retrieve_key_by_username(const char *username, int is_private);

void
zcure_data_randomize(unsigned int nb, void *out_buf);

int
zcure_asym_encrypt(const void *in_buf, unsigned int in_len, EVP_PKEY *pkey, void **out_buf);

int
zcure_asym_decrypt(const void *in_buf, unsigned int in_len, EVP_PKEY *pkey, void **out_buf);

int
zcure_sym_encrypt(const void *in_buf, unsigned int in_len, const uint8_t *key, const uint8_t *iv, void **out_buf);

int
zcure_sym_decrypt(const void *in_buf, unsigned int in_len, const uint8_t *key, const uint8_t *iv, void **out_buf);
#endif /* __ZCURE_COMMON_H__ */
