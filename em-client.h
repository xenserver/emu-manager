#include "emp.h"
#include <json/json.h>

typedef struct emu_socket emu_socket_t;

typedef int (*em_socket_callback)(json_object *, emu_socket_t*);

enum migrate_state {
    not_done=0,
    live_done,
    all_done
};

typedef struct emu_socket
{
   em_socket_callback callback;
   int fd;
   void *data;
/* -- */

   enum migrate_state status;

/* -- */
   char* buf_rem;
   int rem_offset;
   int rem_len;
} emu_socket_t;

extern struct command_names commands[];

int em_socke_send_cmd(emu_socket_t* sock, enum command_num cmd_no, int param);
int em_socket_alloc(emu_socket_t **sock, em_socket_callback callback, void* data);
int em_socket_open(emu_socket_t *sock, char* path);
int em_socket_read(emu_socket_t* sock);
