#include "emp.h"
#include <json/json.h>
#include <stdbool.h>

typedef struct emu_socket emu_socket_t;

typedef int (*em_socket_callback)(json_object *, emu_socket_t*);

#define EM_SOCKET_BUF_SIZE 1024
#define EM_READ_TIMEOUT 30

typedef struct emu_socket
{
   em_socket_callback callback;
   int fd;
   void *data;
/* -- */

   char buf[EM_SOCKET_BUF_SIZE];
   int nbytes;
   bool needs_return;
   json_tokener *tok;
} emu_socket_t;


struct argument;
extern struct command_names commands[];

int em_socke_send_cmd(emu_socket_t* sock, enum command_num cmd_no);
int em_socke_send_cmd_fd(emu_socket_t* sock, enum command_num cmd_no, int fd);
int em_socke_send_cmd_args(emu_socket_t* sock, enum command_num cmd_no, struct argument* args);
int em_socke_send_cmd_fd_args(emu_socket_t* sock, enum command_num cmd_no, int fd, struct argument* args);

int em_socket_alloc(emu_socket_t **sock, em_socket_callback callback, void* data);
int em_socket_connect(emu_socket_t *sock, const char *path);
int em_socket_process(emu_socket_t *sock);
int em_socket_read(emu_socket_t *sock, int timeout);
void em_socket_free(emu_socket_t *sock);
