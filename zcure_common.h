#ifndef __ZCURE_COMMON_H__
#define __ZCURE_COMMON_H__

#define CERT_GET_OP 0

size_t
zcure_asym_encrypt(const unsigned char *in_buf, size_t in_len, EVP_PKEY *pkey, unsigned char **out_buf);

size_t
zcure_asym_decrypt(const unsigned char *in_buf, size_t in_len, EVP_PKEY *pkey, unsigned char **out_buf);

#endif /* __ZCURE_COMMON_H__ */
