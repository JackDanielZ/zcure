#ifndef __ZCURE_SERVER_H__
#define __ZCURE_SERVER_H__

#include <stdint.h>
#include "common/common.h"

typedef struct
{
  uint32_t size;
  uint32_t id;
  char name[USERNAME_SIZE];
  uint32_t ip;
} Client_Info;

typedef struct
{
  Client_Info client;
} Server2ServerApp_Data_Info;

typedef struct
{
  uint32_t size;
  uint32_t client_id;
} ServerApp2Server_Data_Info;

int zcure_server_init(void);
int zcure_server_shutdown(void);

int zcure_server_register(const char *service);

int zcure_server_send(int fd, uint32_t client_id, const void *plain_buffer, unsigned int plain_size);

int zcure_server_receive(int fd, void **plain_buffer, Client_Info *client_info);

#endif /* __ZCURE_SERVER_H__ */
