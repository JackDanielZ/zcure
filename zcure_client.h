#ifndef __ZCURE_CLIENT_H__
#define __ZCURE_CLIENT_H__

int zcure_init(void);
int zcure_shutdown(void);

int zcure_connect(const char *server, const char *port, const char *username);

int zcure_disconnect(int fd);

#endif /* __ZCURE_CLIENT_H__ */
