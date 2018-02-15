#ifndef LIB_H
#define LIB_H

#include <stdlib.h>
#include <stdbool.h>

struct argument {
    struct argument *next;
    char *key;
    char *value;
};

ssize_t read_tlimit(int fd, char *buf, size_t len, int time);

int write_all(int fd, const void *buf, size_t count);

int send_buf_and_fd(int socket, void *buf, int count, int fd_to_send);

int argument_add(struct argument **list, const char *key, const char *value);

ssize_t strindex(const char * const *table, const char *item);

int close_retry(int fd);

void set_debug_log(bool enabled);
void log_debug(char *fmt, ...);
void log_info(char *fmt, ...);
void log_err(char *fmt, ...);

int set_cloexec_flag(int fd, bool value);
#endif
