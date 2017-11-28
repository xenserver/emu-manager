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
int em_client_alloc(em_client_t **cli, em_client_event_cb event_cb,
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
    c->event_cb = event_cb;
    c->nbytes = 0;
    c->needs_return = false;
    *cli = c;

    return 0;
}

/* Close and free an em_client_t object given by @sock. */
int em_client_free(em_client_t *cli)
{
    int rc = 0;

    if (cli->fd >= 0)
        rc = close_retry(cli->fd);
    json_tokener_free(cli->tok);
    free(cli);

    return rc;
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
        close_retry(fd);
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
    json_object *event = NULL;
    json_object *data = NULL;

    assert(jobj);

    type = json_object_get_type(jobj);
    if (type != json_type_object) {
        ERR("Expected JSON object, but got %d", type);
        return -EINVAL;
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
            return -EINVAL;
        } else if (!strcmp(key, "event") &&
                   json_object_get_type(val) == json_type_string) {
            event = val;
        } else if (!strcmp(key, "data") &&
                   json_object_get_type(val) == json_type_object) {
            data = val;
        } else {
            ERR("Unexpected key %s\n", key);
            return -EINVAL;
        }
    }

    if (event && data) {
        if (cli->event_cb)
            return cli->event_cb(cli, json_object_get_string(event), data);
    } else if (event && !data) {
        ERR("Event without data");
        return -EINVAL;
    } else if (!event && data) {
        ERR("Data without event");
        return -EINVAL;
    }

    return 0;
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
        json_object_put(jobj);
        cli->nbytes -= cli->tok->char_offset;
        ptr += cli->tok->char_offset;
        if (rc < 0)
            break;
        processed++;
    }

    memmove(cli->buf, ptr, cli->nbytes);

    return (rc < 0) ? rc : 0;
}

/*
 * Send the command given by @cmd_num, an @fd, and a list of arguments given by
 * @arg to em client @cli. Wait for a response.
 * @return 0 on success. -errno on error.
 */
int em_client_send_cmd_fd_args(em_client_t *cli, enum command_num cmd_num,
                               int fd, struct argument *arg)
{
    char buf[EM_CLIENT_BUF_SIZE];
    const struct command *cmd = command_from_num(cmd_num);
    int rc;

    assert(cli);
    assert(!cmd->needs_fd || fd >= 0);

    INFO("sending %s", cmd->name);

    if (arg) {
        char *ptr = buf;
        int remaining = EM_CLIENT_BUF_SIZE;

        rc = snprintf(ptr, remaining,
                      "{ \"execute\" : \"%s\", \"arguments\" : { ", cmd->name);
        if (rc < 0)
            return -rc;
        if (rc >= remaining)
            return -EMSGSIZE;
        ptr += rc;
        remaining -= rc;

        while (arg) {
            rc = snprintf(ptr, remaining, "\"%s\":\"%s\"%s ",
                          arg->key, arg->value, arg->next ? "," : "");
            if (rc < 0)
                return -rc;
            if (rc >= remaining)
                return -EMSGSIZE;
            ptr += rc;
            remaining -= rc;

            arg = arg->next;
        }

        rc = snprintf(ptr, remaining, "} }");
        if (rc < 0)
            return -rc;
        if (rc >= remaining)
            return -EMSGSIZE;
    } else {
        rc = snprintf(buf, EM_CLIENT_BUF_SIZE,
                      "{ \"execute\" : \"%s\"}", cmd->name);
        if (rc < 0)
            return -rc;
        if (rc >= EM_CLIENT_BUF_SIZE)
            return -EMSGSIZE;
    }

    if (cmd->needs_fd)
        rc = send_buf_and_fd(cli->fd, buf, strlen(buf), fd);
    else
        rc = write_all(cli->fd, buf, strlen(buf));

    if (rc)
        return rc;

    cli->needs_return = true;
    do {
        rc = em_client_read(cli, EM_READ_TIMEOUT);
        if (rc == 0) {
            ERR("Unexpected EOF on em socket\n");
            return -EPIPE;
        } else if (rc < 0) {
            ERR("emu read error: %d, %s\n", -rc, strerror(-rc));
            return rc;
        }

        rc = em_client_process(cli);
    } while (rc >= 0 && cli->needs_return);

    return (rc < 0) ? rc : 0;
}

/*
 * Send the command given by @cmd_num to em client @cli. Wait for a
 * response.
 * @return 0 on success. -errno on error.
 */
int em_client_send_cmd(em_client_t *cli, enum command_num cmd_num)
{
    return em_client_send_cmd_fd_args(cli, cmd_num, -1, NULL);
}

/*
 * Send the command given by @cmd_num and an @fd to em client @cli. Wait for
 * a response.
 * @return 0 on success. -errno on error.
 */
int em_client_send_cmd_fd(em_client_t *cli, enum command_num cmd_num, int fd)
{
    return em_client_send_cmd_fd_args(cli, cmd_num, fd, NULL);
}

/*
 * Send the command given by @cmd_num and a list of arguments given by @arg to
 * em client @cli. Wait for a response.
 * @return 0 on success. -errno on error.
 */
int em_client_send_cmd_args(em_client_t *cli, enum command_num cmd_num,
                            struct argument *arg)
{
    return em_client_send_cmd_fd_args(cli, cmd_num, -1, arg);
}
