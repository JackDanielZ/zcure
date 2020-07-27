#ifndef __ZCURE_CLIENT_H__
#define __ZCURE_CLIENT_H__

int zcure_connect(const char *server, const char *port);

int zcure_disconnect(int fd);

#endif /* __ZCURE_CLIENT_H__ */
