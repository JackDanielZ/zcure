#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <json-c/json.h>

#include "lib/server/server.h"

#define JSON_GET(obj, args...) _json_get(obj, ## args, NULL)

#define STRING_GET(obj) \
   ((obj && json_object_get_type(obj) == json_type_string) ? \
   json_object_get_string(obj) : NULL)

static json_object *
_json_get(json_object *obj, ...)
{
   char* jkey;
   va_list vl;
   json_object *jval;

   if (!obj) return NULL;

   jval = obj;
   va_start(vl, obj);
   while ((jkey = va_arg(vl, char*)))
     {
        struct json_object *jtmp = NULL;
        if (!json_object_object_get_ex(jval, jkey, &jtmp) || !jtmp) return NULL;
        jval = jtmp;
     }
   va_end(vl);

   if (jval == obj) jval = NULL;

   return jval;
}

int main(void)
{
  char path[256];
  struct stat st = {0};
  int zcure_fd;
  int nb;
  int fd;
  char *config_json_content = NULL;
  const char *trigger_host = NULL;
  const char *namecheap_domain = NULL;
  const char *namecheap_name = NULL;
  const char *namecheap_key = NULL;

  zcure_fd = zcure_server_register("IP_Logger");
  if (zcure_fd <= 0)
  {
    fprintf(stderr, "Cannot connect\n");
    return 1;
  }

  if (stat("/home/daniel/IPs", &st) == -1)
  {
    mkdir("/home/daniel/IPs", 0700);
  }

  sprintf(path, "/home/daniel/.config/ip_logger/config.json");
  config_json_content = get_file_content_as_string(path, NULL);

  if (config_json_content)
  {
    struct json_tokener* json_tok = json_tokener_new();
    json_object *config_obj = json_tokener_parse_ex(json_tok, config_json_content, strlen(config_json_content));
    enum json_tokener_error jerr = json_tokener_get_error(json_tok);
    json_tokener_free(json_tok);
    if (jerr == json_tokener_success)
    {
      trigger_host = STRING_GET(JSON_GET(config_obj, "trigger_host"));
      namecheap_key = STRING_GET(JSON_GET(config_obj, "namecheap_key"));
      namecheap_domain = STRING_GET(JSON_GET(config_obj, "namecheap_domain"));
      namecheap_name = STRING_GET(JSON_GET(config_obj, "namecheap_name"));
    }
  }
  do
  {
    Client_Info client;
    char *buf = NULL;
    nb = zcure_server_receive(zcure_fd, (void **)&buf, &client);
    if (nb > 0)
    {
      char *last_ip = NULL;
      char cur_ip[16];

      sprintf(cur_ip, "%d.%d.%d.%d",
          client.ip & 0xFF,
          (client.ip >> 8) & 0xFF,
          (client.ip >> 16) & 0xFF,
          client.ip >> 24
          );
      printf("%d bytes received from client %d - Name %s IP %s\n", nb, client.id, client.name, cur_ip);

      sprintf(path, "/home/daniel/IPs/%s.last", client.name);
      last_ip = get_file_content_as_string(path, NULL);

      if (!last_ip || strcmp((char *)last_ip, cur_ip) != 0)
      {
        printf("Update needed\n");
        fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd <= 0)
        {
          perror("Cannot open IP last file");
        }
        else
        {
          write(fd, cur_ip, strlen(cur_ip));
          close(fd);
        }

        sprintf(path, "/home/daniel/IPs/%s.log", client.name);
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);

        if (fd <= 0)
        {
          perror("Cannot open IP log file");
        }
        else
        {
          time_t current_time = time(NULL);
          struct tm *tm = localtime(&current_time);
          dprintf(fd, "%02d/%02d/%04d %02d:%02d:%02d - %s\n",
              tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900,
              tm->tm_hour, tm->tm_min, tm->tm_sec,
              cur_ip);
          close(fd);
        }

        if (trigger_host && !strcmp(client.name, trigger_host))
        {
          char cmd[512];
          sprintf(cmd, "curl \"http://dynamicdns.park-your-domain.com/update?domain=%s&host=%s&password=%s&ip=%s\" > /dev/null 2>&1",
              namecheap_domain, namecheap_name, namecheap_key, cur_ip);
          printf(cmd);
          system(cmd);
        }
      }
      free(last_ip);

      free(buf);
    }
    else
    {
      fprintf(stderr, "Disconnection from server\n");
    }
  }
  while (nb > 0);

  return 0;
}
