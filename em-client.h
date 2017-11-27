#include "emp.h"
#include <json/json.h>
#include <stdbool.h>

typedef struct em_client em_client_t;

typedef int (*em_client_callback)(json_object *, em_client_t*);

#define EM_CLIENT_BUF_SIZE 1024
#define EM_READ_TIMEOUT 30

typedef struct em_client
{
   em_client_callback callback;
   int fd;
   void *data;
/* -- */

   char buf[EM_CLIENT_BUF_SIZE];
   int nbytes;
   bool needs_return;
   json_tokener *tok;
} emu_client_t;


struct argument;
extern struct command_names commands[];

int em_client_send_cmd(em_client_t* cli, enum command_num cmd_no);
int em_client_send_cmd_fd(em_client_t* cli, enum command_num cmd_no, int fd);
int em_client_send_cmd_args(em_client_t* cli, enum command_num cmd_no, struct argument* args);
int em_client_send_cmd_fd_args(em_client_t* cli, enum command_num cmd_no, int fd, struct argument* args);

int em_client_alloc(em_client_t **cli, em_client_callback callback, void* data);
int em_client_connect(em_client_t *cli, const char *path);
int em_client_process(em_client_t *cli);
int em_client_read(em_client_t *cli, int timeout);
void em_client_free(em_client_t *cli);
