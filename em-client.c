#include <sys/stat.h>
#include <fcntl.h>

#include <getopt.h>

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include "em-client.h"
#include <errno.h>
#include <syslog.h>
#include <stdbool.h>
#include <assert.h>

#define INFO(args...) syslog(LOG_DAEMON|LOG_INFO, args)
#define ERR(args...) syslog(LOG_DAEMON|LOG_ERR, args)
#define ERRN(str1)  syslog(LOG_DAEMON|LOG_ERR, "%s: %s failed with err %s", __func__, str1, strerror(errno))

#if 1
#define DEBUG(args...) syslog(LOG_DAEMON|LOG_INFO, args)
#else
#define DEBUG(args...)
#endif

#define UNIX_PATH_MAX 128

/*
 * Write @count bytes of @buf to @fd, handling interruptions from signals,
 * short writes, etc.
 * @return 0 on success. -errno on error.
 */
int write_all(int fd, const void *buf, size_t count)
{
    ssize_t rc;

    do {
        rc = write(fd, buf, count);

        if (rc < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == EINTR)
                continue;

            return -errno;
        }

        count -= rc;
        buf += rc;
    } while (count > 0);

    return 0;
}

/*
 * Write @count bytes of @buf to @socket as well as an open file descriptor
 * given by @fd_to_send. This function will handle spurious interruptions and
 * short writes.
 * @return 0 on success. -errno on error.
 */
static int send_buf_and_fd(int socket, void *buf, int count, int fd_to_send)
{
    struct msghdr msg = {NULL,};
    struct iovec iov;
    struct cmsghdr *cmsg;
    /*
     * Storage space needed for an ancillary element with a paylod of length
     * is CMSG_SPACE(sizeof(length)).
     */
    char control[CMSG_SPACE(sizeof(int))];
    ssize_t rc;

    iov.iov_base = buf;
    iov.iov_len = count;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    memset(control, 0, CMSG_SPACE(sizeof(int)));
    msg.msg_control = control;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd_to_send;

    do {
        rc = sendmsg(socket, &msg, 0);
    } while (rc < 0 &&
             (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));

    if (rc < 0)
        return -errno;
    else if (rc < count)
        return write_all(socket, buf + rc, count - rc);
    else
        return 0;
}

int em_socket_alloc(emu_socket_t **sock, em_socket_callback callback, void* data)
{
   assert(!*sock);

   *sock = malloc(sizeof(emu_socket_t));
   if (*sock == NULL) {
       ERR("Failed to alloc socket record");
       return -ENOMEM;
   }
   (*sock)->fd=-1;
   (*sock)->data=data;
   (*sock)->callback=callback;

   (*sock)->buf_rem=NULL;
   (*sock)->rem_len=0;
   (*sock)->more=false;

   return 0;
}

int em_socket_open(emu_socket_t *sock, char* path)
{
   int  socket_fd;
   struct sockaddr_un address;

   assert(sock);

   socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
   if(socket_fd < 0)
   {
      int saved_errno = errno;
      ERRN("socket()");
      return -saved_errno;
   }

   /* start with a clean address structure */
   memset(&address, 0, sizeof(struct sockaddr_un));

   address.sun_family = AF_UNIX;
   strncpy(address.sun_path, path, 107);
   address.sun_path[107]='\0';

   INFO(" connect to '%s'", address.sun_path);

   if(connect(socket_fd,
       (struct sockaddr *) &address,
            sizeof(struct sockaddr_un)) != 0)
   {
       int saved_errno = errno;
       ERRN("connect()");
       close(socket_fd);
       return -saved_errno;
   }
   sock->fd=socket_fd;
   return 0;
}

static int print_jerror(json_object *jobj)
{
   int r;
   r = json_object_get_type(jobj);
   if (r == json_type_string) {
      const char* err;
      err = json_object_get_string(jobj);
      ERR("Recived error '%s'", err);
   } else if (r == json_type_object) {
      ERR("Recived error object");
   } else {
      ERR("Recived weird error, type %d", r);
   }
   return 0;
}


int em_socket_read(emu_socket_t* sock, int canread) {

   int r;
   int len;
   int ret=-1;
   int offset=0;
   int need_read=1;

   const int buffersize = 128;

   char *buffer=NULL;
   struct json_tokener* tok = NULL;
   json_object *jobj = NULL;

   enum json_tokener_error jerr;

   em_socket_callback callback;
   int socket_fd = sock->fd;

   tok = json_tokener_new();
   if (tok == NULL) {
       ERR("In need of a tok (%d)\n", sock->fd);
       return -1;
   }

   buffer =  sock->buf_rem;
   len = sock->rem_len;

   if (len > 0) {
       offset = sock->rem_offset;
       DEBUG("Processing previouse buffer @ %d of %d bytes (%d)", offset, len, sock->fd);

       jobj = json_tokener_parse_ex(tok, &(buffer[offset]), len);
       jerr = json_tokener_get_error(tok);

       if (jerr == json_tokener_success ) {
           DEBUG("Tok had enough");
           need_read=0;
       } else if (jerr != json_tokener_continue) {
           ERR("Got an error %d (%d)", jerr, sock->fd);
           goto early_error;
       }
   } else if (buffer == NULL) {
       DEBUG("alloc buf");
       buffer=malloc(buffersize+1);
       if (buffer==NULL)
       {
            ERR("Malloc failed\n");
            goto early_error;
       }
       sock->buf_rem = buffer;
   }

   if (need_read && !canread) {
       ret = 0;
       sock->more = false;
       goto early_error;
   }

   if (need_read)
       offset = 0;

   while (need_read) {

       DEBUG("Reading %s (%d)", (len>0) ? "more" : "", sock->fd);

       len = read(socket_fd, buffer, buffersize);
       if (len <= 0) {
           if (len==0)
               errno=ENODATA;
           ERRN("Read reply");
           goto early_error;
       }

       jobj = json_tokener_parse_ex(tok, buffer, len);
       jerr = json_tokener_get_error(tok);

       buffer[len] = 0;
       DEBUG("Just read '%s' %s", buffer, (jerr == json_tokener_success)?"ok":"");

       if (jerr != json_tokener_continue) 
           need_read = 0;
   }

   if (jerr != json_tokener_success) {
       ERR("Tok failed with %d", jerr);
       goto error;
   }

   if (jobj==NULL) {
       ERR("NULL json tree!\n");
       goto early_error;
   }
   r = json_object_get_type(jobj);
   if (r != json_type_object) {
       ERR("Expected json object, but got %d", r);
       goto error;
   }

   if (len != tok->char_offset) {
       sock->rem_offset = tok->char_offset + offset;
       sock->rem_len = len - tok->char_offset;
       sock->more = true;
   } else {
       sock->rem_len = 0;
       sock->more = false;
   }

   json_object_object_foreach(jobj, key, val) {
      if (strcmp(key, "return") == 0) {
         DEBUG("Got return\n");
         if (ret>-2)
            ret = 1;
      } else if (strcmp(key, "error") == 0) {
         ret = -2;
         print_jerror(val);
      } else if (strcmp(key, "event") == 0
                  && json_object_get_type(val) == json_type_string) {
         if (ret==-1)
             ret = 0;
         callback = sock->callback;
         if (callback) {
                DEBUG("processing event\n" );
                callback(jobj, sock);
         } else {
                DEBUG("not processing event - no callback\n" );
         }
      } else if (strcmp(key, "data") == 0) {
//                INFO("has data");
      } else {
         ERR("Unexpected key %s\n", key);
      }
   }
   if (ret == -1)
     ERR("Didnt get anything expected");
   DEBUG("response processed (%d)", sock->fd);
error:
   json_object_put(jobj);
early_error:
   json_tokener_free(tok);

   /* -2 = recived error, -1 = our error, 0 = is good, may have processed somithng, 1 = returning somithng. */

   return ret;
}


static int size_args_list(struct argument *alist, int *char_count)
{
  struct argument *al = alist;

  int count = 0;
  int chars = 0;

  while (al) {
     count++;
     chars += strlen(al->key) + strlen(al->value);
     al = al->next;
  }
  *char_count = chars;
  return count;
}


int em_socke_send_cmd_fd_args(emu_socket_t* sock, enum command_num cmd_no, int fd, struct argument *args)
{
   const int buffersize = 128;
   int cmd;
   char buffer[128];
   int r;
   int socket_fd = -1;

   char* out_buffer = NULL;

   assert(sock);
   assert(sock->fd >= 0);

   socket_fd = sock->fd;

   for (cmd=0; cmd < cmd_number && commands[cmd].number != cmd_no; cmd++) ;

   if (commands[cmd].number != cmd_no) {
      ERR("Bad command");
      return -1;
   }
   INFO("sending %s", commands[cmd].name);

   if (args) {
       int buf_size;
       struct argument *al = args;
       
       r = size_args_list(args, &buf_size);
       buf_size += strlen("\"\":\"\", ") * r + strlen("} }"); /* note: \0 takes spair ',' space */

       buf_size += snprintf(buffer, buffersize, "{ \"execute\" : \"%s\", \"arguments\" : { ", commands[cmd].name);

       out_buffer = malloc(buf_size);
       strcpy(out_buffer, buffer);


       while (al) {
          snprintf(buffer, buffersize, "\"%s\":\"%s\"%s ", al->key, al->value, (al->next)?",":"");
          strcat(out_buffer, buffer);
          al = al->next;
       }

       strcat(out_buffer, "} }");
       }
   else {
       snprintf(buffer, buffersize, "{ \"execute\" : \"%s\"}", commands[cmd].name);
       out_buffer = buffer;
  }

   if (commands[cmd].fd && fd) {
        r = send_buf_and_fd(socket_fd, out_buffer, strlen(out_buffer), fd);
   } else if (!commands[cmd].fd && !fd)
        r = write_all(socket_fd, out_buffer, strlen(out_buffer));
   else {
        ERR("Invalid FD param (%d) for %s (needs fd = %d)",fd,  commands[cmd].name, commands[cmd].fd);
        goto error_free;
   }

   if (args) {
     free(out_buffer);
     out_buffer = NULL;
   }

   if (r < 0) {
      ERRN("Send()");
      return -1;
   }

   do {
       r = em_socket_read(sock, 1);
   } while ( r == 0);

   if (r==1)
       return 0;
   else {
       ERR("Failed to read after command");
       return -1;
   }

error_free:
   if (args)
      free(out_buffer);
   return -1;
}




int em_socke_send_cmd(emu_socket_t* sock, enum command_num cmd_no)
{
    return em_socke_send_cmd_fd_args(sock, cmd_no, 0, NULL);
}


int em_socke_send_cmd_fd(emu_socket_t* sock, enum command_num cmd_no, int fd)
{
    return em_socke_send_cmd_fd_args(sock, cmd_no, fd, NULL);
}


int em_socke_send_cmd_args(emu_socket_t* sock, enum command_num cmd_no, struct argument *args)
{
    return em_socke_send_cmd_fd_args(sock, cmd_no, 0, args);
}

