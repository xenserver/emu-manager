#include "emp.h"
#include <json/json.h>

typedef struct emu_socket emu_socket_t;

typedef int (*em_socket_callback)(json_object *, emu_socket_t*);

typedef struct emu_socket
{
   em_socket_callback callback;
   int fd;
   void *data;
/* -- */

   char* buf_rem;
   int rem_offset;
   int rem_len;
   int more;
} emu_socket_t;


struct args_list {
    struct args_list* next;
    char *key;
    char *value;
};

extern struct command_names commands[];

int em_socke_send_cmd(emu_socket_t* sock, enum command_num cmd_no);
int em_socke_send_cmd_fd(emu_socket_t* sock, enum command_num cmd_no, int fd);
int em_socke_send_cmd_args(emu_socket_t* sock, enum command_num cmd_no, struct args_list* args);

int em_socket_alloc(emu_socket_t **sock, em_socket_callback callback, void* data);
int em_socket_open(emu_socket_t *sock, char* path);
int em_socket_read(emu_socket_t* sock, int canread);
