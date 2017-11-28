#include "lib.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>

static bool debug_log;

/*
 * Read up to @len bytes into @buf from @fd, waiting for up to @time seconds
 * for data to appear. This function will handle spurious errors like EINTR.
 * @return The number of bytes read if it succeeds. 0 if the other end closes
 * the file descriptor. -ETIME if a time occurs. -errno if an error occurs.
 */
ssize_t read_tlimit(int fd, char *buf, size_t len, int time)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc;
    ssize_t ret;

    if (time > 0) {
        /*
         * If a signal interrupts us we might wait a bit longer than was
         * requested. This shouldn't be a problem.
         */
        while ((rc = poll(&pfd, 1 , time * 1000)) == -1 &&
               (errno == EINTR || errno == EAGAIN))
            ;
        if (rc < 0)
            return -errno;
        if (rc == 0)
            return -ETIME;
    }

    while ((ret = read(fd, buf, len)) == -1 &&
           (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        ;
    if (ret < 0)
        return -errno;
    return ret;
}

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
int send_buf_and_fd(int socket, void *buf, int count, int fd_to_send)
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
 * Append the given @key and @value pair to the argument list given by @list.
 * @return 0 on success. -errno on failure.
 */
int argument_add(struct argument **list, const char *key, const char *value)
{
    struct argument *xa;

    xa = malloc(sizeof(*xa));
    if (!xa)
        return -errno;

    xa->key = strdup(key);
    xa->value = strdup(value);
    xa->next = NULL;

    if (!xa->key || !xa->value) {
        free(xa->key);
        free(xa->value);
        free(xa);
        return -errno;
    }

    while (*list)
        list = &(*list)->next;
    *list = xa;

    return 0;
}

/*
 * Search an item in an array of strings and return the index of the item.
 * @return The index of the item if found. -1 if not found.
 */
ssize_t strindex(const char * const *table, const char *item)
{
    ssize_t i;

    for (i = 0; table[i]; i++) {
        if (!strcmp(table[i], item))
            return i;
    }

    return -1;
}

/*
 * Close @fd, handling any interruptions due to receiving a signal.
 * @return 0 on success. -errno on failure.
 */
int close_retry(int fd)
{
    int rc;

    while ((rc = close(fd)) == -1 && (errno == EINTR))
        ;

    return rc == 1 ? -errno : 0;
}

/* Set debug logging to @enabled. */
void set_debug_log(bool enabled)
{
    debug_log = enabled;
}

/*
 * Log a message to syslog at the debug log level only if debug logging is
 * enabled.
 */
void log_debug(char *fmt, ...)
{
    va_list ap;

    if (!debug_log)
        return;

    va_start(ap, fmt);
    vsyslog(LOG_DEBUG, fmt, ap);
    va_end(ap);
}

/* Log a message to syslog at the info log level. */
void log_info(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(LOG_INFO, fmt, ap);
    va_end(ap);
}

/* Log a message to syslog at the error log level. */
void log_err(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(LOG_ERR, fmt, ap);
    va_end(ap);
}
