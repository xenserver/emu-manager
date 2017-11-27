#include <sys/stat.h>
#include <fcntl.h>

#include <getopt.h>

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include "em-client.h"
#include "lib.h"
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

/*
 * Allocate and initialize an em_client_t object.
 * @return 0 on success. -errno on error.
 */
int em_client_alloc(em_client_t **cli, em_client_callback callback,
                    void *data)
{
    em_client_t *c;

    assert(!*cli);

    c = malloc(sizeof(em_client_t));
    if (!c) {
        ERR("Failed to allocate em_client_t");
        return -ENOMEM;
    }
    c->tok = json_tokener_new();
    if (!c->tok) {
        ERR("Failed to allocate JSON tokener");
        free(c);
        return -ENOMEM;
    }
    c->fd = -1;
    c->data = data;
    c->callback = callback;
    c->nbytes = 0;
    c->needs_return = false;
    *cli = c;

    return 0;
}

/* Close and free an em_client_t object given by @sock. */
void em_client_free(em_client_t *cli)
{
    if (cli->fd >= 0)
        close(cli->fd);
    json_tokener_free(cli->tok);
    free(cli);
}

/*
 * Connect the em_client_t given by @sock to @path.
 * @return 0 on success. -errno on error.
 */
int em_client_connect(em_client_t *cli, const char *path)
{
    struct sockaddr_un addr;
    int fd;

    assert(cli);

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
    cli->fd = fd;

    return 0;
}

/*
 * Read from the em client, @cli, into an internal buffer. @timeout specifies
 * the timeout for the read in seconds.
 * @return -ETIME if a timeout occurs. -ENOSPC if there is no space remaining
 * in the buffer. -errno if any other error occurs. 0 if the other side closes
 * the connection. Otherwise returns the number of bytes read.
 */
int em_client_read(em_client_t *cli, int timeout)
{
    ssize_t ret;

    assert(cli->nbytes <= EM_CLIENT_BUF_SIZE);

    if (cli->nbytes == EM_CLIENT_BUF_SIZE)
        return -ENOSPC;

    ret = read_tlimit(cli->fd, cli->buf + cli->nbytes,
                      EM_CLIENT_BUF_SIZE - cli->nbytes, timeout);
    if (ret > 0)
        cli->nbytes += ret;

    return ret;
}

/*
 * Process JSON object @jobj from em client @cli.
 * @return 0 on success. -errno on error.
 */
static int process_object(em_client_t *cli, json_object *jobj)
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
            cli->needs_return = false;
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
            if (cli->callback)
                cli->callback(jobj, cli);
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
 * Process any messages in the internal buffer of em client @cli.
 * @return The number of messages processed on success. -errno on failure.
 */
int em_client_process(em_client_t *cli)
{
    const char *ptr;
    json_object *jobj;
    enum json_tokener_error jerr;
    int processed = 0;
    int rc = 0;

    INFO("Process em_client_t read buffer: '%.*s'",
         cli->nbytes, cli->buf);

    ptr = cli->buf;
    while (cli->nbytes) {
        json_tokener_reset(cli->tok);
        jobj = json_tokener_parse_ex(cli->tok, ptr, cli->nbytes);
        jerr = json_tokener_get_error(cli->tok);

        if (jerr == json_tokener_continue) {
            if (cli->nbytes == EM_CLIENT_BUF_SIZE)
                return -EMSGSIZE;
            break;
        } else if (jerr != json_tokener_success) {
            ERR("Error from tokener: %s", json_tokener_error_desc(jerr));
            rc = -EINVAL;
            break;
        }

        rc = process_object(cli, jobj);
        cli->nbytes -= cli->tok->char_offset;
        ptr += cli->tok->char_offset;
        if (rc < 0)
            break;
        processed++;
    }

    memmove(cli->buf, ptr, cli->nbytes);

    return (rc < 0) ? rc : 0;
}

int em_client_send_cmd_fd_args(em_client_t* cli, enum command_num cmd_no, int fd, struct argument *args)
{
   const int buffersize = 128;
   int cmd;
   char buffer[128];
   int r;

   char* out_buffer = NULL;

   assert(cli);
   assert(cli->fd >= 0);

   for (cmd=0; cmd < cmd_number && commands[cmd].number != cmd_no; cmd++) ;

   if (commands[cmd].number != cmd_no) {
      ERR("Bad command");
      return -1;
   }
   INFO("sending %s", commands[cmd].name);

   if (args) {
       int buf_size;
       struct argument *al = args;
       
       r = argument_list_size(args, &buf_size);
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
        r = send_buf_and_fd(cli->fd, out_buffer, strlen(out_buffer), fd);
   } else if (!commands[cmd].fd && !fd)
        r = write_all(cli->fd, out_buffer, strlen(out_buffer));
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

    cli->needs_return = true;

    do {
       r = em_client_read(cli, EM_READ_TIMEOUT);
        if (r == 0) {
            ERR("Unexpected EOF on em socket\n");
            return -EPIPE;
        } else if (r < 0) {
            ERR("emu read error: %d, %s\n", -r, strerror(-r));
            return r;
        }

        r = em_client_process(cli);
    } while (r >= 0 && cli->needs_return);

   if (args)
      free(out_buffer);

    return (r < 0) ? r : 0;

error_free:
   if (args)
      free(out_buffer);
   return -1;
}




int em_client_send_cmd(em_client_t* cli, enum command_num cmd_no)
{
    return em_client_send_cmd_fd_args(cli, cmd_no, 0, NULL);
}


int em_client_send_cmd_fd(em_client_t* cli, enum command_num cmd_no, int fd)
{
    return em_client_send_cmd_fd_args(cli, cmd_no, fd, NULL);
}


int em_client_send_cmd_args(em_client_t* cli, enum command_num cmd_no, struct argument *args)
{
    return em_client_send_cmd_fd_args(cli, cmd_no, 0, args);
}

