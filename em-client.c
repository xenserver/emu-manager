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

/*
 * Allocate and initialize an emu_socket_t object.
 * @return 0 on success. -errno on error.
 */
int em_socket_alloc(emu_socket_t **sock, em_socket_callback callback,
                    void *data)
{
    emu_socket_t *s;

    assert(!*sock);

    s = malloc(sizeof(emu_socket_t));
    if (!s) {
        ERR("Failed to allocate emu_socket_t");
        return -ENOMEM;
    }
    s->tok = json_tokener_new();
    if (!s->tok) {
        ERR("Failed to allocate JSON tokener");
        free(s);
        return -ENOMEM;
    }
    s->fd = -1;
    s->data = data;
    s->callback = callback;
    s->nbytes = 0;
    s->needs_return = false;
    *sock = s;

    return 0;
}

/* Close and free an emu_socket_t object given by @sock. */
void em_socket_free(emu_socket_t *sock)
{
    if (sock->fd >= 0)
        close(sock->fd);
    json_tokener_free(sock->tok);
    free(sock);
}

/*
 * Connect the emu_socket_t given by @sock to @path.
 * @return 0 on success. -errno on error.
 */
int em_socket_connect(emu_socket_t *sock, const char *path)
{
    struct sockaddr_un addr;
    int fd;

    assert(sock);

    if (strlen(path) >= sizeof(addr.sun_path))
        return ENAMETOOLONG;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        int saved_errno = errno;
        ERRN("socket()");
        return -saved_errno;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);

    INFO(" connect to '%s'", addr.sun_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
    {
        int saved_errno = errno;
        ERRN("connect()");
        close(fd);
        return -saved_errno;
    }
    sock->fd = fd;

    return 0;
}

/*
 * Read from the emu socket, @sock, into an internal buffer. @timeout specifies
 * the timeout for the read in seconds.
 * @return -ETIME if a timeout occurs. -ENOSPC if there is no space remaining
 * in the buffer. -errno if any other error occurs. 0 if the emu closes the
 * connection. Otherwise returns the number of bytes read.
 */
int em_socket_read(emu_socket_t *sock, int timeout)
{
    ssize_t ret;

    assert(sock->nbytes <= EM_SOCKET_BUF_SIZE);

    if (sock->nbytes == EM_SOCKET_BUF_SIZE)
        return -ENOSPC;

    ret = read_tlimit(sock->fd, sock->buf + sock->nbytes,
                      EM_SOCKET_BUF_SIZE - sock->nbytes, timeout);
    if (ret > 0)
        sock->nbytes += ret;

    return ret;
}

/*
 * Process JSON object @jobj from emu socket @sock.
 * @return 0 on success. -errno on error.
 */
static int process_object(emu_socket_t *sock, json_object *jobj)
{
    json_type type;
    int rc = 0;

    assert(jobj);

    type = json_object_get_type(jobj);
    if (type != json_type_object) {
        ERR("Expected JSON object, but got %d", type);
        rc = -EINVAL;
        goto out;
    }

    json_object_object_foreach(jobj, key, val) {
        if (!strcmp(key, "return")) {
            sock->needs_return = false;
        } else if (!strcmp(key, "error")) {
            if (json_object_is_type(val, json_type_string))
                ERR("Error from emu: %s", json_object_get_string(jobj));
            else
                ERR("Unknown error from emu: %s",
                    json_object_to_json_string(jobj));
            rc = -EINVAL;
            break;
        } else if (!strcmp(key, "event") &&
                   json_object_get_type(val) == json_type_string) {
            if (sock->callback)
                sock->callback(jobj, sock);
        } else if (!strcmp(key, "data")) {
            /* Ignore */
        } else {
            ERR("Unexpected key %s\n", key);
            rc = -EINVAL;
            break;
        }
    }

out:
    json_object_put(jobj);
    return rc;
}

/*
 * Process any messages in the internal buffer of emu socket @sock.
 * @return The number of messages processed on success. -errno on failure.
 */
int em_socket_process(emu_socket_t *sock)
{
    const char *ptr;
    json_object *jobj;
    enum json_tokener_error jerr;
    int processed = 0;
    int rc = 0;

    INFO("Process emu_socket_t read buffer: '%.*s'",
         sock->nbytes, sock->buf);

    ptr = sock->buf;
    while (sock->nbytes) {
        json_tokener_reset(sock->tok);
        jobj = json_tokener_parse_ex(sock->tok, ptr, sock->nbytes);
        jerr = json_tokener_get_error(sock->tok);

        if (jerr == json_tokener_continue) {
            if (sock->nbytes == EM_SOCKET_BUF_SIZE)
                return -EMSGSIZE;
            break;
        } else if (jerr != json_tokener_success) {
            ERR("Error from tokener: %s", json_tokener_error_desc(jerr));
            rc = -EINVAL;
            break;
        }

        rc = process_object(sock, jobj);
        sock->nbytes -= sock->tok->char_offset;
        ptr += sock->tok->char_offset;
        if (rc < 0)
            break;
        processed++;
    }

    memmove(sock->buf, ptr, sock->nbytes);

    return (rc < 0) ? rc : 0;
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

    sock->needs_return = true;

    do {
       r = em_socket_read(sock, EM_READ_TIMEOUT);
        if (r == 0) {
            ERR("Unexpected EOF on emu socket\n");
            return -EPIPE;
        } else if (r < 0) {
            ERR("emu read error: %d, %s\n", -r, strerror(-r));
            return r;
        }

        r = em_socket_process(sock);
    } while (r >= 0 && sock->needs_return);

   if (args)
      free(out_buffer);

    return (r < 0) ? r : 0;

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

