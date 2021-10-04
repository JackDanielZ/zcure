#ifndef __ZCURE_CLIENT_H__
#define __ZCURE_CLIENT_H__

int zcure_client_init(void);
int zcure_client_shutdown(void);

int zcure_client_connect(const char *destination, const char *service);

int zcure_client_disconnect(int cid);

int zcure_client_send(int cid, const void *plain_buffer, unsigned int plain_size);

int zcure_client_receive(int cid, void **plain_buffer);

#endif /* __ZCURE_CLIENT_H__ */
