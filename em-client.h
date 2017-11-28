#include "emp.h"
#include <json/json.h>
#include <stdbool.h>

typedef struct em_client em_client_t;

typedef int (*em_client_event_cb)(em_client_t *cli, const char *event,
                                  json_object *data);

#define EM_CLIENT_BUF_SIZE 1024
#define EM_READ_TIMEOUT 30

typedef struct em_client
{
   em_client_event_cb event_cb;
   int fd;
   void *data;
/* -- */

   char buf[EM_CLIENT_BUF_SIZE];
   int nbytes;
   bool needs_return;
   json_tokener *tok;
} emu_client_t;


struct argument;

int em_client_send_cmd(em_client_t *cli, enum command_num cmd_num);
int em_client_send_cmd_fd(em_client_t *cli, enum command_num cmd_num, int fd);
int em_client_send_cmd_args(em_client_t *cli, enum command_num cmd_num,
                            struct argument *args);
int em_client_send_cmd_fd_args(em_client_t *cli, enum command_num cmd_num,
                               int fd, struct argument *args);

int em_client_alloc(em_client_t **cli, em_client_event_cb event_cb, void* data);
int em_client_connect(em_client_t *cli, const char *path);
int em_client_process(em_client_t *cli);
int em_client_read(em_client_t *cli, int timeout);
void em_client_free(em_client_t *cli);
