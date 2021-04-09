#ifndef __ZCURE_SERVER_H__
#define __ZCURE_SERVER_H__

#include <stdint.h>

int zcure_server_init(void);
int zcure_server_shutdown(void);

int zcure_server_register(const char *service);

int zcure_server_send(int fd, uint32_t client_id, const void *plain_buffer, unsigned int plain_size);

int zcure_server_receive(int fd, void **plain_buffer, uint32_t *client_id);

#endif /* __ZCURE_SERVER_H__ */
