#ifndef __ZCURE_SERVER_H__
#define __ZCURE_SERVER_H__

#include <stdint.h>
#include "common/common.h"

typedef enum
{
  CLIENT_DATA                    =  0,
  CLIENT_CONNECT_NOTIFICATION    = (1 << 0),
  CLIENT_DISCONNECT_NOTIFICATION = (1 << 1)
} Server2ServerApp_DataType;

typedef struct
{
  char service[SERVICE_SIZE];
} ServerConnectionRequest;

typedef struct
{
  uint32_t size;
  uint32_t data_type; /* Server2ServerApp_DataType */
  uint32_t src_id;
  /* data is following */
} Server2ServerApp_Header;

typedef struct
{
  uint32_t size;
  uint32_t dest_id;
  /* data is following */
} ServerApp2Server_Header;

typedef struct
{
  char name[USERNAME_SIZE];
  uint32_t ip;
} Server2ServerApp_ClientConnectNotification;

int zcure_server_init(void);
int zcure_server_shutdown(void);

int zcure_server_register(const char *service);

int zcure_server_send(int fd, uint32_t client_id, const void *plain_buffer, unsigned int plain_size);

int zcure_server_receive(int fd, void **plain_buffer, Server2ServerApp_DataType *type, uint32_t *src_id);

#endif /* __ZCURE_SERVER_H__ */
