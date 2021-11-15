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

typedef struct
{
  const char *name;
  uint32_t ip;
} IP_Info;

static IP_Info _infos[100] = {0};

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
  int zcure_fd;
  int nb;
  char *home = NULL;
  char *config_json_content = NULL;
  const char *trigger_host = NULL;
  const char *namecheap_domain = NULL;
  const char *namecheap_name = NULL;
  const char *namecheap_key = NULL;

  LOGGER_INFO("START");

  home = getenv("HOME");
  if (home == NULL)
  {
    LOGGER_ERROR("Cannot get $HOME from getenv\n");
    return 1;
  }

  zcure_fd = zcure_server_register("IP_Logger");
  if (zcure_fd <= 0)
  {
    LOGGER_ERROR("Cannot connect\n");
    return 1;
  }

  sprintf(path, "%s/.config/ip_logger/config.json", home);
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

  LOGGER_INFO("INIT DONE");

  do
  {
    Server2ServerApp_DataType type;
    char *buf = NULL;
    nb = zcure_server_receive(zcure_fd, (void **)&buf, &type, NULL);
    if (nb > 0)
    {
      if (type == CLIENT_CONNECT_NOTIFICATION)
      {
        unsigned int i;
        Server2ServerApp_ClientConnectNotification *notif = (Server2ServerApp_ClientConnectNotification *)buf;

        for (i = 0; i < sizeof(_infos) / sizeof(IP_Info); i++)
        {
          if (_infos[i].name == NULL) break;
          if (!strcmp(_infos[i].name, notif->name)) break;
        }

        if (i == sizeof(_infos) / sizeof(IP_Info))
        {
          LOGGER_ERROR("Too many clients!!!!");
        }
        else
        {
          if (_infos[i].name == NULL)
          {
            _infos[i].name = strdup(notif->name);
            _infos[i].ip = 0;
          }

          if (notif->ip != _infos[i].ip)
          {
            _infos[i].ip = notif->ip;
            LOGGER_INFO("New IP for %s: %d.%d.%d.%d",
                notif->name,
                notif->ip & 0xFF, (notif->ip >> 8) & 0xFF, (notif->ip >> 16) & 0xFF, notif->ip >> 24);

            if (trigger_host && !strcmp(notif->name, trigger_host))
            {
              char cmd[512];
              sprintf(cmd, "curl \"http://dynamicdns.park-your-domain.com/update?domain=%s&host=%s&password=%s&ip=%d.%d.%d.%d\" > /dev/null 2>&1",
                  namecheap_domain, namecheap_name, namecheap_key,
                  notif->ip & 0xFF, (notif->ip >> 8) & 0xFF, (notif->ip >> 16) & 0xFF, notif->ip >> 24);
              system(cmd);
            }
          }
        }
      }
      free(buf);
    }
    else
    {
      LOGGER_ERROR("Disconnection from server");
    }
  }
  while (nb > 0);

  return 0;
}
