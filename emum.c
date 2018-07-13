#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>

#include "lib.h"
#include "em-client.h"

enum operation_mode {
    op_save,
    op_pvsave,
    op_restore,
    op_pvrestore,
    op_end,
    op_invalid,
};

/* These mode names correspond with enum operation_mode. */
static const char *mode_names[] = {
    "hvm_save",
    "save",
    "hvm_restore",
    "restore",
    NULL
};

enum protocol {
    emp,
    qmp,
};

enum state {
    not_ready, /* Initial value for for qemu (pre negotiation) */
    not_done,  /* initial value for all but qemu */
    started,   /* restore started */
    live_done,
    all_done,
    result_sent
};

enum stages {
    stage_enabled,
    stage_start,
    stage_init,
    stage_live,
    stage_ready,
    stage_pause,
    stage_paused,
    stage_stopcopy
};

#define STAGE_ENABLED  (1 << stage_enabled)
#define STAGE_START    (1 << stage_start)
#define STAGE_INIT     (1 << stage_init)
#define STAGE_LIVE     (1 << stage_live)
#define STAGE_READY    (1 << stage_ready)
#define STAGE_PAUSE    (1 << stage_pause)
#define STAGE_PAUSED   (1 << stage_paused)
#define STAGE_STOPCOPY (1 << stage_stopcopy)

#define FULL_LIVE    STAGE_START | STAGE_INIT | STAGE_LIVE  | STAGE_PAUSE | STAGE_PAUSED
#define FULL_NONLIVE STAGE_START | STAGE_INIT | STAGE_PAUSE | STAGE_PAUSED | STAGE_STOPCOPY

struct emu {
    char *name;
    char **startup;
    char *waitfor;
    unsigned int waitfor_size;
    pid_t pid;
    enum protocol proto;
    int proto_version;
    int enabled;

    int exp_total;

    em_client_t *client;
    struct stream_fd *stream;

    enum state status;
    int emu_error;
    bool first_error;
    char *result;
    struct argument *extra;

    uint64_t part_sent;
    uint64_t sent;
    uint64_t remaining;
    int iter;
};

struct stream_fd {
    int fd;
/* Bit mask */
#define FD_CLOSED       1
#define FD_BUSY         2
    int state;

    int remaining_uses;
    int refs;
};

#define EMP_CONTROL_PATH "/var/xen/%s/%d/control"
#define QMP_CONTROL_PATH "/var/run/xen/qmp-libxl-%d"

#define XENOPSD_TIMEOUT 120
#define XENOPSD_MSG_SIZE 128      /* maximum size of a message */
#define XENOPSD_RESTORE_MSG "restore:"
#define XENOPSD_ABORT_MSG "abort"
#define XENOPSD_ACK_MSG "done"

#define CMD_START_TIMEOUT 60 * 3
#define CMD_TERM_TIMEOUT  60 * 1
#define CMD_START_RBUF_LEN 128

/* xenopsd state */
static int xenopsd_in = -1;       /* xenopsd read fd */
static int xenopsd_out = -1;      /* xenopsd write fd */
static bool xenopsd_needs_ack;    /* true if we're expecting an ACK message */
static char xenopsd_rbuf[XENOPSD_MSG_SIZE];  /* receive buffer */
static int xenopsd_nbytes;        /* number of bytes of data in xenopsd_rbuf */

/* manager state */
static int domid = -1;
static bool live_migrate;
static int last_progress = -1;
static enum operation_mode operation_mode = op_invalid;

#define EEMUM_DISCONNECT (-2)
#define EEMUM_DIED       (-3)
#define EEMUM_EXITERROR  (-4)

#define EEMUM_FIRST_ECODE EEMUM_DISCONNECT
#define EEMUM_LAST_ECODE EEMUM_EXITERROR

static char *emum_error_str[3] = {
    "unexpectedly disconnected",
    "was killed by a signal",
    "exited with an error"
};

char *xenguest_args[] = {
    "/usr/libexec/xen/bin/xenguest",
    "-debug",
    "-domid", "%d",
    "-controloutfd", "2",
    "-controlinfd", "0",
    "-mode", "listen",
    NULL,
};

struct emu emus[] = {
    {
        .name = "xenguest",
        .startup = xenguest_args,
        .waitfor = "Ready\n",
        .waitfor_size = 6,
        .proto = emp,
        .enabled = FULL_LIVE | STAGE_READY | STAGE_ENABLED,
        .exp_total = 1000000,
        .stream = NULL,
        .status = not_done,
        .iter = -1
    },
    {
        .name = "vgpu",
        .proto = emp,
        .enabled = FULL_LIVE,
        .exp_total = 100000,
        .stream = NULL,
        .status = not_done,
        .iter = -1
    },
    {
        .name = "qemu",
        .proto = qmp,
        .enabled = FULL_NONLIVE,
        .exp_total = 10,
        .stream = NULL,
        .status = not_ready,
        .iter = -1
    },
};
#define num_emus ((int)(sizeof(emus) / sizeof(*emus)))

/* Forward declarations */

static int restore_emu(struct emu *emu);
static struct emu *find_emu_by_name(const char *name);
static int wait_on_condition(bool (*check)(struct emu *emu));
static bool check_and_respond_qemu_negotiation(struct emu *emu);

/*
 * Check streams fds are safe to use.
 * A stream with random write access allows for different processes to
 * inadvertently write over each others data, resulting in corruption.
 * This can occur without any seeking - simply due to metadata
 * caching issues.
 */
static int check_stream_fd(int fd)
{
    struct stat statbuf;
    int r;

    r = fstat(fd, &statbuf);
    if (r < 0)
        return -errno;

    /* Sockets can't do random write access and so is safe. */
    if (S_ISSOCK(statbuf.st_mode))
        return 0;

    r = fcntl(fd, F_GETFL);
    if (r == -1)
        return -errno;

    /*
     * If the fd represents a file, and it is either read only or
     * has O_APPEND set, then it also can't do random write access
     * and is also safe.
     */
    if (((r & O_ACCMODE) == O_RDONLY) || (r & O_APPEND))
        return 0;

    log_info("FD %d is a file with flags %x", fd, r);

    return -ENOSTR;
}

static int set_stream(struct emu *emu, int fd)
{
    struct stream_fd *c_fd = NULL;
    int i;

    if (emu->stream) {
        log_err("Emu %s cannot have more then one stream. First %d Second %d", emu->name, emu->stream->fd, fd);
        return -EINVAL;
    }

    for (i = 0; i < num_emus; i++) {
        if (emus[i].stream && emus[i].stream->fd == fd) {
            c_fd = emus[i].stream;
            break;
        }
    }

    /* If not found, add */
    if (c_fd == NULL) {
        int rc;

        c_fd = malloc(sizeof(struct stream_fd));
        if (!c_fd) {
            log_err("Failed to alloc for stream_fd");
            return -ENOMEM;
        }

        c_fd->fd = fd;
        c_fd->remaining_uses = 1;
        c_fd->refs = 1;
        c_fd->state = 0;

        rc = check_stream_fd(fd);
        if (rc) {
            log_err("Failed to validate stream %d for %s: %s", fd, emu->name, strerror(-rc));
            return rc;
        }

    } else {
        c_fd->remaining_uses++;
        c_fd->refs++;
    }

    emu->stream = c_fd;

    return 0;
}

static int free_stream(struct emu *emu)
{
    struct stream_fd *fd;

    assert(emu);

    if (!emu->stream)
        return 0;

    fd = emu->stream;
    if (fd->refs == 0)
        return -EINVAL;

    emu->stream = NULL;

    fd->refs--;
    if (fd->refs == 0) {
        if (!(fd->state & FD_CLOSED)) {
            int rc;
            log_info("Closing fd %d, before freeing for %s", fd->fd, emu->name);
            rc = close_retry(fd->fd);
            if (rc)
                 log_err("Failed to close stream fd for emu %s:", emu->name, strerror(-rc));
        }
        free(fd);
    }
    return 0;
}

static int set_used_stream(struct emu *emu)
{
    struct stream_fd *fd;

    assert(emu);
    assert(emu->stream);
    fd = emu->stream;

    if (fd->remaining_uses == 0 || fd->state & FD_CLOSED) {
        log_err("Attempted to use a stream FD who's remaining uses is %d and is %s.",
                 fd->remaining_uses, (fd->state & FD_CLOSED) ? "closed" : "open");
        return -EINVAL;
    }

    fd->remaining_uses--;
    if (fd->remaining_uses == 0) {
        int rc;

        rc = close_retry(fd->fd);
        if (rc) {
            log_err("Failed to close stream fd for emu %s", emu->name);
            return rc;
        }
        fd->state |= FD_CLOSED;
    }
    return 0;
}

static int set_stream_busy(struct emu *emu, bool busy)
{
    struct stream_fd *fd;

    assert(emu);
    assert(emu->stream);
    fd = emu->stream;

    if (!!(fd->state & FD_BUSY) == busy) {
        log_err("Attempted to set stream as %s when already in this state.", (busy) ? "busy" : "idle");
        return -EINVAL;
    }

    fd->state = busy ? fd->state | FD_BUSY : fd->state & ~FD_BUSY;
    return 0;
}

static int set_cloexec_flag_for_emus(void)
{
    int i;

    for (i = 0; i < num_emus; i++) {
        if (emus[i].stream) {
            if (set_cloexec_flag(emus[i].stream->fd, true)) {
                 int saved_error = errno;
                 log_err("Failed to set_cloexec flag on stream %d for %s due to %s",
                          emus[i].stream->fd, emus[i].name, strerror(saved_error));
                 return -saved_error;
            }
        }
    }
    return 0;
}

static char *get_nonstandard_error(int err)
{
   if (err > 0)
      return strerror(err);
   else if (err > EEMUM_FIRST_ECODE || err < EEMUM_LAST_ECODE)
      return "erroneous";
   else
      return emum_error_str[-err + EEMUM_FIRST_ECODE];
}

#define SET_EMU_ERR(em, er) set_emu_err(em, er, __func__);

static int set_emu_err(const int emu, const int err, const char* func)
{
    static int first = true;
    struct emu *e = &emus[emu];

    log_err("%s: emu %s %s", func, e->name, get_nonstandard_error(err));

    if (err && e->emu_error == 0) {
        e->emu_error = err;
        e->first_error = first;
        first = false;
    }
    return err;
}

/* Functions for communicating with xenopsd */

/*
 * Read from xenopsd into an internal buffer. @timeout specifies the timeout
 * for the read in seconds.
 * @return -ETIME if a timeout occurs. -ENOSPC if there is no space remaining
 * in the buffer. -errno if any other error occurs. 0 if xenopsd
 * closes the connection. Otherwise returns the number of bytes read.
 */
static int xenopsd_read(int timeout)
{
    ssize_t ret;

    assert(xenopsd_nbytes <= XENOPSD_MSG_SIZE);

    if (xenopsd_nbytes == XENOPSD_MSG_SIZE)
        return -ENOSPC;

    ret = read_tlimit(xenopsd_in, xenopsd_rbuf + xenopsd_nbytes,
                      XENOPSD_MSG_SIZE - xenopsd_nbytes, timeout);
    if (ret > 0)
        xenopsd_nbytes += ret;

    return ret;
}

/*
 * Process a message, @msg, from xenopsd and perform actions depending on our
 * internal state.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_process_message(const char *msg)
{
    log_debug("xenopsd: Processing '%s'", msg);

    if (!strncmp(msg, XENOPSD_ACK_MSG, sizeof(XENOPSD_ACK_MSG))) {
        if (!xenopsd_needs_ack) {
            log_err("Unexpected ACK received from xenopsd");
            return -EINVAL;
        }
        xenopsd_needs_ack = false;
        return 0;
    /* Check for "restore:" followed by <argument>. Don't compare \0 to allow argument. */
    } else if (!strncmp(msg, XENOPSD_RESTORE_MSG, sizeof(XENOPSD_RESTORE_MSG) - 1)) {
        struct emu *emu;

        msg += strlen(XENOPSD_RESTORE_MSG);

        emu = find_emu_by_name(msg);
        if (!emu) {
            log_err("xenopsd: Restore for unknown emu '%s'", msg);
            return -EINVAL;
        }

        return restore_emu(emu);
    }  else if (!strncmp(msg, XENOPSD_ABORT_MSG, sizeof(XENOPSD_ABORT_MSG))) {
        log_debug("xenopsd: Received abort command");
        return -ESHUTDOWN;
    }

    log_err("Unexpected message from xenopsd: %s", msg);
    return -EINVAL;
}

/*
 * Process any messages from xenopsd in the internal buffer.
 * @return The number of messages processed on success. -errno on failure.
 */
static int xenopsd_process(void)
{
    int processed = 0;
    int rc = 0;
    char *ptr, *endl;

    log_debug("xenopsd: Process read buffer: '%.*s'",
              xenopsd_nbytes, xenopsd_rbuf);

    ptr = xenopsd_rbuf;
    while (xenopsd_nbytes) {
        endl = memchr(ptr, '\n', xenopsd_nbytes);
        if (!endl) {
            if (xenopsd_nbytes == XENOPSD_MSG_SIZE)
                return -EMSGSIZE;
            break;
        }

        *endl = '\0';
        rc = xenopsd_process_message(ptr);
        xenopsd_nbytes -= endl - ptr + 1;
        ptr = endl + 1;
        if (rc < 0)
            break;
        processed++;
    }

    memmove(xenopsd_rbuf, ptr, xenopsd_nbytes);

    return rc ? rc : processed;
}

/*
 * Send @msg to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_message(const char *msg)
{
    int rc;

    log_debug("xenopsd: Send '%s'", msg);

    rc = write_all(xenopsd_out, msg, strlen(msg));
    if (rc)
        log_err("Failed to write to xenopsd: %d, %s", -rc, strerror(-rc));

    return rc;
}

/*
 * Inform xenopsd about progress of the operation.
 * @progress A value between 0 and 100 inclusive.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_progress(int progress)
{
    char buf[XENOPSD_MSG_SIZE];
    int rc;

    rc = snprintf(buf, XENOPSD_MSG_SIZE, "info:\\b\\b\\b\\b%d\n", progress);
    if (rc < 0)
        return -errno;

    return xenopsd_send_message(buf);
}

/*
 * Send a message to xenopsd and wait for the ACK.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_message_with_ack(const char *msg)
{
    int rc;

    rc = xenopsd_send_message(msg);
    if (rc)
        return rc;

    xenopsd_needs_ack = true;

    /*
     * Wait for an ACK by repeating until a message is processed or an
     * error occurs.
     */
    do {
        rc = xenopsd_read(XENOPSD_TIMEOUT);
        if (rc == 0) {
            log_err("xenopsd: Unexpected EOF on control fd after sending '%s'.\n", msg);
            return -EPIPE;
        } else if (rc < 0) {
            log_err("xenopsd read error after sending '%s': %d, %s\n", msg, -rc, strerror(-rc));
            return rc;
        }

        rc = xenopsd_process();
    } while (rc >= 0 && xenopsd_needs_ack);

    return (rc < 0) ? rc : 0;
}

/*
 * Send the suspend message to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_suspend(void)
{
    return xenopsd_send_message_with_ack("suspend:\n");
}

/*
 * Send the prepare message for @emu to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_prepare(const struct emu *emu)
{
    char buf[XENOPSD_MSG_SIZE];
    int rc;

    rc = snprintf(buf, XENOPSD_MSG_SIZE, "prepare:%s\n", emu->name);
    if (rc < 0)
        return -errno;

    return xenopsd_send_message_with_ack(buf);
}

/*
 * Notify xenopsd that @emu is 'all done' along its result, if available.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_result(const struct emu *emu)
{
    char buf[XENOPSD_MSG_SIZE];
    int rc;

    if (emu->result)
        rc = snprintf(buf, XENOPSD_MSG_SIZE, "result:%s %s\n",
                      emu->name, emu->result);
    else
        rc = snprintf(buf, XENOPSD_MSG_SIZE, "result:%s\n", emu->name);

    if (rc < 0)
        return -errno;

    return xenopsd_send_message(buf);
}

/*
 * Sends the 'all done' message to xenopsd after a save operation.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_final_result(void)
{
    return xenopsd_send_message("result:0 0\n");
}

/*
 * Sends @err as an error result to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int xenopsd_send_error_result(int err)
{
    char msg[XENOPSD_MSG_SIZE];
    int rc;
    int emu = false;
    char *emu_name = "";
    int i;
    int err_code = err;

    for (i = 0; i < num_emus; i++) {
        if (emus[i].first_error) {
              emu = true;
              err_code = emus[i].emu_error;
              emu_name = emus[i].name;
        }
    }

    rc = snprintf(msg, XENOPSD_MSG_SIZE, "error:%s%s%s\n", emu_name, (emu) ? " " : "",
                  get_nonstandard_error(err_code));
    log_info("Reporting %s", msg);

    if (rc < 0)
        return -errno;

    return xenopsd_send_message(msg);
}

/* Functions for program startup. */

/*
 * Parses an integer from a string given by @str. Except for whitespace at the
 * start, the string may not have leading or trailing characters that do not
 * form part of the number. Exits with status 1 if an error occurs.
 */
static int parse_int(const char *str)
{
    char *end;
    long result;

    errno = 0;
    result = strtol(str, &end, 10);

    if (errno || *end || (int)result != result) {
        log_err("Cannot parse '%s' as a valid integer", str);
        exit(1);
    }

    return (int)result;
}

/*
 * Parses the argument for the -dm option, given by @arg.
 * The argument is of the form: <emu-name>[:<fd>]
 * @arg may be mutated. Exits with status 1 if an error occurs.
 */
static void parse_dm_arg(char *arg)
{
    struct emu *emu;
    char *param;

    param = strchr(arg, ':');
    if (param) {
        *param = '\0';
        param++;
    }

    emu = find_emu_by_name(arg);

    if (!emu) {
        log_err("Bad dm arg: '%s', '%s'", arg, param);
        exit(1);
    }

    emu->enabled |= STAGE_ENABLED;

    if (param) {
        switch (emu->proto) {
        case emp:
            if (set_stream(emu, parse_int(param)))
                 exit(1);
            break;
        case qmp:
            abort();
            break;
        }
    }
}

/*
 * Parse program arguments given by @argc and @argv.
 * Exits with status 1 if an error occurs.
 */
static void parse_args(int argc, char *argv[])
{
    enum {
        arg_controlinfd,
        arg_controloutfd,
        arg_debuglog,
        arg_fd,
        arg_domid,
        arg_live,
        arg_dm,
        arg_mode,
        arg_xg_store_port,
        arg_xg_console_port,
        arg_fork,
        arg_supports
    };

    static const struct option args[] = {
        {"controlinfd",  required_argument, NULL,   arg_controlinfd},
        {"controloutfd", required_argument, NULL,   arg_controloutfd},
        {"debuglog",     required_argument, NULL,   arg_debuglog},
        {"fd",           required_argument, NULL,   arg_fd},
        {"domid",        required_argument, NULL,   arg_domid},
        {"live",         required_argument, NULL,   arg_live},
        {"dm",           required_argument, NULL,   arg_dm},
        {"mode",         required_argument, NULL,   arg_mode},
        {"store_port",   required_argument, NULL,   arg_xg_store_port},
        {"console_port", required_argument, NULL,   arg_xg_console_port},
        {"fork",         required_argument, NULL,   arg_fork},
        {"supports",     required_argument, NULL,   arg_supports},
        {NULL},
    };

    static const char *supports_table[] = {
        "migration-v2",
        NULL
    };

    int c, rc;
    ssize_t idx;

    for(;;) {
        int arg_index = 0;

        c = getopt_long_only(argc, argv, "", args, &arg_index);
        if (c == -1)
            break;

        switch (c) {
        case arg_controlinfd:
            xenopsd_in = parse_int(optarg);
            break;
        case arg_controloutfd:
            xenopsd_out = parse_int(optarg);
            break;
        case arg_debuglog:
            set_debug_log(!strcmp(optarg, "true"));
            break;
        case arg_fd:
            rc = set_stream(&emus[0], parse_int(optarg));
            if (rc)
                exit(1);
            break;
        case arg_domid:
            domid = parse_int(optarg);
            break;
        case arg_live:
            if (!strcmp(optarg, "true")) {
                live_migrate = true;
            } else if (strcmp(optarg, "false")) {
                log_err("Unknown live argument: '%s'", optarg);
                exit(1);
            }
            break;
        case arg_dm:
            parse_dm_arg(optarg);
            break;
        case arg_mode:
            idx = strindex(mode_names, optarg);
            if (idx < 0) {
                log_err("Unknown mode '%s'", optarg);
                exit(1);
            }
            operation_mode = idx;
            break;
        case arg_xg_store_port:
        case arg_xg_console_port:
            rc = argument_add_string(&emus[0].extra, args[arg_index].name, optarg);
            if (rc) {
                log_err("Error adding xenguest argument: %d, %s",
                        -rc, strerror(-rc));
                exit(1);
            }
            break;
        case arg_fork: /* ignore */
            break;
        case arg_supports:
            operation_mode = op_end;
            if (strindex(supports_table, optarg) >= 0)
                printf("true\n");
            else
                printf("false\n");
            break;
        default:
            log_err("Error parsing arguments");
            exit(1);
            break;
        }
    }

    if (optind < argc) {
        log_err("Unknown extra arguments");
        exit(1);
    }
}

/* Functions for emu-manager operation. */

/*
 * Return the emu whose name is @name.
 * @return A pointer to the given emu if found, otherwise NULL. The pointer
 * should not be freed.
 */
static struct emu *find_emu_by_name(const char *name)
{
    int i;

    for (i = 0; i < num_emus; i++) {
        if (!strcmp(emus[i].name, name))
            return &emus[i];
    }

    return NULL;
}

static bool is_emu_enabled(const char *name)
{
   struct emu *found_emu = find_emu_by_name(name);

   return found_emu->enabled;
}

/* Given @command, a list of program arguments, substitute all parameterized
 * arguments. This modifies @command.
 * @return 0 on success. -errno on failure.
 */
static int substitute_args(char **command)
{
    while (*command) {
        if (!strcmp(*command, "%d")) {
            if (asprintf(command, "%d", domid) < 0)
                return -errno;
        }
        command++;
    }

    return 0;
}

/*
 * This prevents stdout being buffered for a child process. This is a hack.
 * Remove this code when xenguest is fixed to avoid buffering its output.
 */
static int setenv_nobuffs(void)
{
    clearenv();
    if ((putenv("LD_PRELOAD=/usr/libexec/coreutils/libstdbuf.so") != 0) ||
            (putenv ("_STDBUF_O=0") != 0)) {
        log_err("Failed to putenv\n");
        return -1;
    }
    return 0;
}

/*
 * Execute @command and wait for it to signal that it has started by
 * matching @waitfor_size bytes of its stdout against @waitfor.
 * @return 0 on success. -errno on failure.
 */
static int exec_command(char **command,
                        char *waitfor, unsigned int waitfor_size, pid_t *child_pid)
{
    int comm[2];
    pid_t pid;
    ssize_t ret;
    size_t nbytes = 0;
    char buf[CMD_START_RBUF_LEN];

    assert(waitfor_size <= CMD_START_RBUF_LEN);

    if (pipe(comm) == -1)
        return -errno;

    pid = fork();
    if (pid == -1) {
        close_retry(comm[0]);
        close_retry(comm[1]);
        return -errno;
    } else if (pid == 0) {
        int rc;

        while ((rc = dup2(comm[1], STDOUT_FILENO)) == -1 && (errno == EINTR))
            ;

        if (rc < 0)
            _exit(1);

        close_retry(comm[1]);
        close_retry(comm[0]);

        setenv_nobuffs();

        execvp(command[0], command);
        _exit(1);
    }
    *child_pid = pid;
    close_retry(comm[1]);

    do {
        ret = read_tlimit(comm[0], buf + nbytes,
                          waitfor_size - nbytes, CMD_START_TIMEOUT);
        if (ret < 0) {
            goto out;
        } else if (ret == 0) {
            ret = -EPIPE;
            goto out;
        }
        nbytes += ret;
    } while (nbytes < waitfor_size);

    ret = !memcmp(buf, waitfor, waitfor_size) ? 0 : -EINVAL;

out:
    close_retry(comm[0]);
    return ret;
}

/*
 * Calculates the progress.
 * @return The current progress between 0 and 100 inclusive.
 */
static int calculate_done(void)
{
    int i;
    uint64_t expect = 0;
    uint64_t sent  = 0;

    for (i = 0; i < num_emus; i++) {
        if (!emus[i].enabled)
            continue;

        if (emus[i].iter >= 0) {
            sent += emus[i].sent;

            /*
             * Add only 80% of a partial update to compensate for dirty pages
             * that will need to be copied again later.
             */
            sent += (emus[i].part_sent - emus[i].sent) * 80 / 100;

            expect += emus[i].sent + emus[i].remaining;
        } else {
            expect += emus[i].exp_total;
            if (emus[i].status >= all_done)
                sent += emus[i].exp_total;
        }
    }

    return expect ? sent * 100 / expect : 0;
}

/*
 * Calculates the progress and sends it to xenopsd.
 * @return The current progress between 0 and 100 inclusive. -errno on failure.
 */
static int update_progress(void)
{
    int rc = 0;
    int progress = calculate_done();

    if (last_progress != progress) {
        rc = xenopsd_send_progress(progress);
        last_progress = progress;
    }
    return rc ? rc : progress;
}

/*
 * Process @event from em client @cli with data given by @data.
 * Calculate the updated progress and send it to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int emp_event_cb(em_client_t *cli, const char *event, json_object *data)
{
    struct emu *emu = cli->data;
    int64_t rem = -1;
    int64_t sent = -1;
    int iter = -1;

    log_debug("Processing emp event from %s", emu->name);

    if (strcmp(event, "MIGRATION")) {
        log_err("Unknown event type: %s", event);
        return -EINVAL;
    }

    json_object_object_foreach(data, key, val) {
        if (!strcmp(key, "status")) {
            if (json_object_get_type(val) == json_type_string) {
                const char *status = json_object_get_string(val);
                int rc;

                if (strcmp(status, "completed")) {
                    log_err("Error: emu %s status: %s", emu->name, status);
                    return -EREMOTEIO;
                }
                log_info("%s is complete", emu->name);
                emu->status = all_done;
                rc = set_stream_busy(emu, false);
                if (rc)
                    return rc;
            } else {
                log_err("Unexpected event status");
                return -EINVAL;
            }
        } else if (!strcmp(key, "result")) {
            if (json_object_get_type(val) == json_type_string) {
                free(emu->result);
                emu->result = strdup(json_object_get_string(val));
                if (!emu->result)
                    return -ENOMEM;
            } else {
                log_err("Unexpected event result");
                return -EINVAL;
            }
        }  else if (json_object_get_type(val) == json_type_int) {
            if (!strcmp(key, "remaining")) {
                rem = json_object_get_int64(val);
            } else if (!strcmp(key, "sent")) {
                sent = json_object_get_int64(val);
            } else if (!strcmp(key, "iteration")) {
                iter = json_object_get_int(val);
            } else {
                log_err("Unexpected event data: %s", key);
                return -EINVAL;
            }
        } else {
            log_err("Unexpected event data: %s", key);
            return -EINVAL;
        }
    }

    if (rem >= 0 || iter >= 0) {
        int progress;
        bool ready = emu->status == live_done;

        /* remaining can be wrong - fix it up if it is. */
        if (rem == 0 && iter == 0)
            rem = -1;

        if (rem != -1) {
            emu->remaining = rem;
            emu->sent = sent;
            emu->iter = iter;
        }
        emu->part_sent = sent;

        progress = update_progress();
        if (progress < 0)
            return progress;

        log_info("Event for %s: rem %"PRId64", sent %"PRId64", iter %d, %s. Progress = %d",
                 emu->name, rem, sent, iter,
                 ready ? "waiting" : "not waiting", progress);
        if ((iter > 0) && (rem < 50 || iter >= 4) && !ready) {
            log_info("%s live stage is done", emu->name);
            emu->status = live_done;
        }
    }

    return 0;
}


/*
 * Process @event from em client @cli with data given by @data.
 * Calculate the updated progress and send it to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int qmp_event_cb(em_client_t *cli, const char *event, json_object *data)
{
    (void) data;
    log_debug("Processing event from QMP client");

    if (!strcmp(event, "QMP")) {
        struct emu *emu = cli->data;

        log_info("Got QMP version negotiation");
        emu->proto_version = 1;
        return 0;
    }
    log_err("Ignoring QMP event %s", event);
    return 0;
}

/*
 * Start all emus that need to be started.
 * @return 0 on success. -errno on failure.
 */
static int startup_emus(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (emus[i].startup) {
            log_info("Starting %s\n", emus[i].name);

            rc = substitute_args(emus[i].startup);
            if (rc) {
                log_err("Error substituting arguments for %s: %d, %s",
                        emus[i].name, -rc, strerror(-rc));
                return rc;
            }

            rc = exec_command(emus[i].startup,
                              emus[i].waitfor, emus[i].waitfor_size, &emus[i].pid);
            if (rc) {
                log_err("Error starting %s: %d, %s",
                        emus[i].name, -rc, strerror(-rc));
                return rc;
            }
        }
    }
    return 0;
}

/*
 * Open a connection to @emu.
 * @return 0 on success. -errno on failure.
 */
static int connect_emp(struct emu *emu)
{
    char path[64];
    int rc;

    rc = snprintf(path, sizeof(path), EMP_CONTROL_PATH, emu->name, domid);
    if (rc < 0)
        return -errno;

    rc = em_client_alloc(&emu->client, emp_event_cb, emu);
    if (rc)
        return rc;

    return em_client_connect(emu->client, path);
}

static int connect_qmp(struct emu *emu)
{
    char path[64];
    int rc;

    rc = snprintf(path, sizeof(path), QMP_CONTROL_PATH, domid);
    if (rc < 0)
        return -errno;

    rc = em_client_alloc(&emu->client, qmp_event_cb, emu);
    if (rc)
        return rc;

    return em_client_connect(emu->client, path);
}

/*
 * Connect to all emus.
 * @return 0 on success. -errno on failure.
 */
static int connect_emus(void)
{
    int i;
    int rc = EINVAL;
    struct emu *emu;

    for (i = 0; i < num_emus; i++) {
        emu = &emus[i];
        if (!emu->enabled)
            continue;

        switch (emu->proto) {
        case emp:
            rc = connect_emp(emu);
            break;
        case qmp:
            rc = connect_qmp(emu);
            break;
        }

        if (rc) {
            log_err("Failed to connect to %s: %d, %s",
                    emu->name, -rc, strerror(-rc));
            return rc;
        }
     }
    return 0;
}

/*
 * Send migrate_init to each emu and any extra arguments required.
 * @return 0 on success. -errno on failure.
 */
static int init_emus(void)
{
    int i;
    int rc;
    struct emu *emu;

    for (i = 0; i < num_emus; i++) {
        struct stream_fd *stream;

        emu = &emus[i];
        if (!(emu->enabled && STAGE_INIT))
            continue;

        stream = emu->stream;

        if (stream && stream->remaining_uses == 0) {
            log_err("Attempted to use a stream FD who's remaining uses is already 0");
            return -EINVAL;
        }

        switch (emu->proto) {
        case emp:
            rc = emp_client_send_cmd_fd(emu->client, cmd_migrate_init,
                                       stream ? stream->fd : -1);
            if (rc)
                return rc;

            if (stream) {
                rc = set_used_stream(emu);
                if (rc)
                    return rc;
            }

            if (emu->extra) {
                rc = emp_client_send_cmd_args(emu->client, cmd_set_args,
                                             emu->extra);
                if (rc)
                    return rc;
            }

            break;
        case qmp:

            log_debug("Wait for QEMU");
            rc = wait_on_condition(check_and_respond_qemu_negotiation);
            if (rc)
                return rc;
            log_debug("QEMU ready");
            break;
        }
    }
    return 0;
}

static int disconnect_emu(int emu_i)
{
    int rc = 0;
    int ret;
    struct emu *emu;

    assert(emu_i >= 0 && emu_i < num_emus);
    emu = &emus[emu_i];

    if (emu->client) {
        if (emu->client->fd >= 0 && emu->startup) {
            ret = emp_client_send_cmd(emu->client, cmd_quit);
            if (ret && !rc)
                rc = ret;
        }

        ret = em_client_free(emu->client);
        if (ret && !rc)
            rc = ret;
        emu->client = NULL;
    }

    ret = free_stream(emu);
    if (ret && !rc) {
        log_err("Failed to free stream for %s", emu->name);
        rc = ret;
    }

    emu->enabled = false;
    return rc;
}

/*
 * Enable dirty page tracking and progress reporting for live emus.
 * @return 0 on success. -errno on failure.
 */
static int request_track_emus(void)
{
    int i;
    int rc;
    struct emu *emu;

    for (i = 0; i < num_emus; i++) {
        emu = &emus[i];
        if (!(emu->enabled && STAGE_LIVE))
            continue;

        switch (emu->proto) {
        case emp:
            rc = emp_client_send_cmd(emu->client, cmd_track_dirty);
            if (rc)
                return rc;

            rc = emp_client_send_cmd(emu->client, cmd_migrate_progress);
            if (rc)
                return rc;

            break;
        case qmp:
            {
                struct argument arg = {.key = "enable", .value= "true", .next = NULL};
                rc = qmp_client_send_cmd_args(emu->client, cmd_xen_set_global_dirty_log, &arg);
            }

            /* This is the last command, so can close connection */
            if (!rc)
                rc = disconnect_emu(i);

            if (rc)
                return rc;
            break;
        }
    }
    return 0;
}

/*
 * Send cmd_restore to @emu.
 * @return 0 on success. -errno on failure.
 */
static int restore_emu(struct emu *emu)
{
    if (emu->status != not_done) {
        log_err("Request to restore emu '%s' already in progress", emu->name);
        return -EINVAL;
    }
    emu->status = started;
    if (set_stream_busy(emu, true))
        return -EINVAL;

    return emp_client_send_cmd(emu->client, cmd_restore);
}

/*
 * Start migration for each live emu.
 * @return 0 on success. -errno on failure.
 */
static int migrate_live_emus(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (!(emus[i].enabled & STAGE_LIVE))
            continue;

        rc = set_stream_busy(&emus[i], true);
        if (rc)
           return rc;

        rc = xenopsd_send_prepare(&emus[i]);
        if (rc < 0) {
            if (rc != -ESHUTDOWN)
                log_err("Failed to prepare stream for %s: %d, %s\n",
                        emus[i].name, -rc, strerror(-rc));
            return rc;
        }

        rc = emp_client_send_cmd(emus[i].client, cmd_migrate_live);
        if (rc)
            return rc;
    }

    return 0;
}

/*
 * Tell all emus to pause.
 * @return 0 on success. -errno on failure.
 */
static int pause_emus(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (!(emus[i].enabled & STAGE_PAUSE))
            continue;

        rc = emp_client_send_cmd(emus[i].client, cmd_migrate_pause);
        if (rc)
            return rc;
    }

    return 0;
}

/*
 * Send all emus the migrate_paused command.
 * @return 0 on success. -errno on failure.
 */
static int migrate_paused(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (!(emus[i].enabled & STAGE_PAUSED))
            continue;

        rc = emp_client_send_cmd(emus[i].client, cmd_migrate_paused);
        if (rc)
            return rc;
    }

    return 0;
}

/*
 * Close connections to all connected emus and tell any emus we've started to
 * quit. This will not return immediately if an error is received. Instead, it
 * will perform all the work and return the first error code.
 * @return 0 on success. -errno on failure.
 */
static int migrate_end(void)
{
    int i;
    int ret;
    int rc = 0;

    for (i = 0; i < num_emus; i++) {
        ret = disconnect_emu(i);
        if (ret && !rc)
            rc = ret;
    }
    return rc;
}

/*
 * Wait for an event to occur or process existing data.
 * @return 0 on success. -errno on failure.
 */
static int wait_for_event(void)
{
    int i;
    int rc;
    fd_set rfds;
    fd_set wfds;
    fd_set xfds;
    int max_fd = xenopsd_in;
    struct timeval tv = {30, 0};  /* 30 second timeout */

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);

    FD_SET(xenopsd_in, &rfds);

    for (i = 0; i < num_emus; i++) {
        int fd;

        if (!emus[i].enabled)
            continue;

        fd = emus[i].client->fd;
        if (fd >= 0 ) {
            FD_SET(fd, &rfds);
            if (fd > max_fd)
                max_fd = fd;
        }
    }

    rc = select(max_fd + 1, &rfds, &wfds, &xfds, &tv);

    if (rc > 0) {
        if (FD_ISSET(xenopsd_in, &rfds)) {
            rc = xenopsd_read(0);
            if (rc == 0) {
                log_err("xenopsd: Unexpected EOF on control fd\n");
                return -EPIPE;
            } else if (rc < 0) {
                log_err("xenopsd read error: %d, %s\n", -rc, strerror(-rc));
                return rc;
            }
            rc = xenopsd_process();
            if (rc < 0)
                return rc;
        }

        for (i = 0; i < num_emus; i++) {
            if (emus[i].enabled && FD_ISSET(emus[i].client->fd, &rfds)) {
                rc = em_client_read(emus[i].client, 0);
                if (rc == 0) {
                    log_err("em-client: emu %s unexpectedly disconnected (died?)", emus[i].name);

                    emus[i].client->fd = -1;
                    SET_EMU_ERR(i, EEMUM_DISCONNECT);
                    return -EPIPE;
                } else if (rc < 0)
                    return set_emu_err(i, rc, "em_client_read");

                rc = em_client_process(emus[i].client);
                if (rc < 0)
                    return set_emu_err(i, rc, "em_client_process");
            }
        }

        return 0;
    } else if (rc == 0) {
        return -ETIME;
    } else {
        return rc;
    }
}

/* Returns true if @emu is live and has not yet finished. False otherwise. */
static bool check_live_not_finished(struct emu *emu)
{
    return (emu->enabled & STAGE_LIVE) && emu->status != all_done;
}

/*
 * Returns true if @emu supports indicating readiness but is not yet ready.
 * False otherwise.
 */
static bool check_not_ready(struct emu *emu)
{
    return (emu->enabled & STAGE_READY) && emu->status == not_done;
}

/*
 * Capability negotiation requires waiting for QEMU to send a
 * version string, and in response to this, send a qmp_capabilities
 * command.  This function checks to see if the proto_version has
 * set, and if so, it sends the command, and updates the emu status
 * (preventing multiple issues of the command).
 * This can be used by wait_on_condition to negotiate many qemus
 * in parallel.
 */

static bool check_and_respond_qemu_negotiation(struct emu *emu)
{
    if (emu->proto != qmp)
        return false;

    if (emu->proto_version == 0)
        return true;

    if (emu->status == not_ready) {
        qmp_client_send_cmd(emu->client, cmd_qmp_capabilities);
        emu->status = not_done;
    }
    return false;
}

/*
 * Wait for @check to return false for every emu.
 * @return 0 on success. -errno on failure.
 */
static int wait_on_condition(bool (*check)(struct emu *emu))
{
    int i;
    int rc;
    int remaining;

    for (;;) {
        remaining = 0;
        for (i = 0; i < num_emus; i++) {
            if (check(&emus[i]))
                remaining++;
        }

        if (remaining == 0)
            break;

        rc = wait_for_event();
        if (rc < 0 && rc != -ETIME) {
            if (rc != -ESHUTDOWN)
                log_err("Error waiting for events: %d, %s",
                        -rc, strerror(-rc));
            return rc;
        }
        rc = update_progress();
        if (rc < 0)
            return rc;
    }

    return 0;
}

/*
 * Sequentially save each non-live emu and wait for completion.
 * @return 0 on success. -errno on failure.
 */
static int save_nonlive_one_by_one(void)
{
    int i;
    int rc;

    for (i = 0; i < num_emus; i++) {
        if (!(emus[i].enabled & STAGE_STOPCOPY))
            continue;

        rc = set_stream_busy(&emus[i], true);
        if (rc)
           return rc;

        rc = xenopsd_send_prepare(&emus[i]);
        if (rc < 0)
            return rc;

        rc = emp_client_send_cmd(emus[i].client, cmd_migrate_nonlive);
        if (rc < 0)
            return rc;

        while (emus[i].status != all_done) {
            rc = wait_for_event();
            if (rc < 0 && rc != -ETIME) {
                log_err("Error waiting for events: %d, %s",
                        -rc, strerror(-rc));
                return rc;
            }

            rc = update_progress();
            if (rc < 0)
                return rc;
        }
    }

    return 0;
}

/* Set up the enabled stages for each emu. */
static int configure_emus(void)
{
    int i;

    for (i = 0; i < num_emus; i++) {
        if (emus[i].enabled & STAGE_ENABLED) {
            log_info("%s is enabled", emus[i].name);

            switch (emus[i].proto) {
            case emp:
                if (!live_migrate) {
                    emus[i].enabled = (emus[i].enabled | STAGE_STOPCOPY ) &
                                      ~(STAGE_LIVE | STAGE_READY);
                }
                break;
            case qmp:
                if (operation_mode == op_restore || operation_mode == op_pvrestore || !live_migrate)
                    emus[i].enabled = 0;
                break;
            }

        } else {
            emus[i].enabled = 0;
        }
    }

    if (is_emu_enabled("vgpu")) {
        struct emu *xenguest = find_emu_by_name("xenguest");
        int rc;

        assert(xenguest);
        rc = argument_add_string(&xenguest->extra, "vgpu", "true");
        if (rc) {
            log_err("Error adding vgpu argument: %d, %s", -rc, strerror(-rc));
            return rc;
        }
    }
    return 0;
}

static int out_of_time;

static void alarm_sig_handler(int sig)
{
    (void)(sig);
    out_of_time = true;
}

static void wait_for_children(void)
{
    int i;
    int status;
    int errcode = 0;
    pid_t pid;
    int emu_pids_remaining = 0;
    struct sigaction sa;

    for (i = 0; i < num_emus; i++)
         if (emus[i].startup && emus[i].pid)
             emu_pids_remaining++;

    out_of_time = false;

    sa.sa_handler = alarm_sig_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL)) {
        log_err("Error waiting on  SIGALM %d, %s", errno, strerror(errno));
        return;
    }

    alarm(CMD_TERM_TIMEOUT);

    log_debug("emus left = %d", emu_pids_remaining);
    /* Wait politely for children to terminate */
    while (!out_of_time && emu_pids_remaining > 0) {
        log_debug("waiting for children");
        pid = wait(&status);
        for (i = 0; i < num_emus; i++) {
            if (emus[i].pid == pid) {

               if (WIFSIGNALED(status))
                   errcode = EEMUM_DIED;
               else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
                   errcode = EEMUM_EXITERROR;

               log_debug("emu %s %s", emus[i].name,
                                      errcode ? get_nonstandard_error(errcode) : "completed normally");

               /* Can we improve the current exit reason? */
               if (errcode && emus[i].emu_error)
                   emus[i].emu_error = errcode;
               emus[i].pid = 0;
               emu_pids_remaining--;
               break;
            }
        }
    }
    alarm(0);

    /* Anyone left will be killed */
    if (out_of_time) {
        log_err("Timeout on emu exit");
        for (i = 0; i < num_emus; i++) {
            if (emus[i].startup && emus[i].pid) {
                 log_err("sending sigkill to %s", emus[i].name);
                 kill(emus[i].pid, SIGKILL);
                 pid = waitpid(emus[i].pid, &status, 0);
                 if (pid == -1) {
                     log_err("Failed to wait for %s, due to %s", emus[i].name, strerror(errno));
                 }
            }
        }
    }
    log_debug("All children exited");
}

/*
 * Perform the load operation. Reports the final result or an error to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int operation_load(void)
{
    int rc, end_rc;
    int i;
    int remaining = 0;

    log_debug("Phase: configure_emus");
    rc = configure_emus();
    if (rc)
        goto out;

    log_debug("Phase: startup_emus");
    rc = startup_emus();
    if (rc)
        goto out;

    log_debug("Phase: connect_emus");
    rc = connect_emus();
    if (rc)
        goto out;

    log_debug("Phase: init_emus");
    rc = init_emus();
    if (rc)
        goto out;

    log_debug("Phase: wait_for_completion");
    /* Count number of emus we need to wait for. */
    for (i = 0; i < num_emus; i++) {
        if (emus[i].enabled)
            remaining++;
    }
    while (remaining) {
        rc = wait_for_event();
        if (rc < 0 && rc != -ETIME) {
            if (rc != -ESHUTDOWN)
                log_err("Error waiting for events: %d, %s",
                        -rc, strerror(-rc));
            goto out;
        }

        for (i = 0; i < num_emus; i++) {
            if (emus[i].status == all_done) {
                xenopsd_send_result(&emus[i]);
                emus[i].status = result_sent;
                remaining--;
            }
        }
    }
    rc = 0;

out:
    log_debug("Phase: migrate_end");
    end_rc = migrate_end();
    if (end_rc) {
        log_err("Error calling migrate_end(): %d, %s",
                -end_rc, strerror(-end_rc));
        if (!rc)
            rc = end_rc;
    }

    wait_for_children();

    if (rc && rc != -ESHUTDOWN) {
        end_rc = xenopsd_send_error_result(-rc);

        if (end_rc)
            log_err("sending error to xenopsd failed: %d, %s",
                    -end_rc, strerror(-end_rc));
        return rc;
    }
    return 0;
}

/*
 * Tell all emus to abort. This will not return immediately if an error is
 * received. Instead, it will tell all the emus to abort and return the
 * first error code.
 * @return 0 on success. -errno on failure.
 */
static int migrate_abort(void)
{
    int i;
    int rc = 0;
    int ret;

    log_info("Aborting all emus...");

    for (i = 0; i < num_emus; i++) {
        if (emus[i].enabled) {
            switch (emus[i].proto) {
            case emp:
                if (emus[i].client && emus[i].client->fd >= 0) {
                    ret = emp_client_send_cmd(emus[i].client, cmd_migrate_abort);
                    if (ret && !rc)
                        rc = ret;
                }
                break;
            case qmp:
                abort();
                break;
            }
        }
    }

    return rc;
}

/*
 * Perform the save operation. Reports the final result or an error to xenopsd.
 * @return 0 on success. -errno on failure.
 */
static int operation_save(void)
{
    int rc;
    int end_rc = 0;

    log_debug("Phase: configure_emus");
    configure_emus();

    log_debug("Phase: startup_emus");
    rc = startup_emus();
    if (rc)
        goto out;

    log_debug("Phase: connect_emus");
    rc = connect_emus();
    if (rc)
        goto out;

    log_debug("Phase: init_emus");
    rc = init_emus();
    if (rc)
        goto out;

    if (live_migrate) {
        log_debug("Phase: request_track_emus");
        rc = request_track_emus();
        if (rc)
            goto out;

        log_debug("Phase: migrate_live_emus");
        rc = migrate_live_emus();
        if (rc)
            goto out;

        log_debug("Phase: wait until ready");
        rc = wait_on_condition(check_not_ready);
        if (rc)
            goto out;
    }

    log_debug("Phase: xenopsd_send_suspend");
    rc = xenopsd_send_suspend();
    if (rc)
        goto out;

    log_debug("Phase: pause_emus");
    rc = pause_emus();
    if (rc)
        goto out;

    log_debug("Phase: migrate_paused");
    rc = migrate_paused();
    if (rc)
        goto out;

    log_debug("Phase: wait until live finished");
    rc = wait_on_condition(check_live_not_finished);
    if (rc)
        goto out;

    log_debug("Phase: save_nonlive_one_by_one");
    rc = save_nonlive_one_by_one();
    if (rc)
        goto out;

    log_debug("Phase: send_final_result");
    rc = xenopsd_send_final_result();

out:
    if (rc) {
        end_rc = migrate_abort();
        if (end_rc)
            log_err("Error calling migrate_abort(): %d, %s",
                    -end_rc, strerror(-end_rc));
    }

    log_debug("Phase: migrate_end");
    end_rc = migrate_end();
    if (end_rc) {
        log_err("Error calling migrate_end(): %d, %s",
                -end_rc, strerror(-end_rc));
        if (!rc)
            rc = end_rc;
    }

    wait_for_children();

    if (rc && rc != -ESHUTDOWN) {
        end_rc = xenopsd_send_error_result(-rc);
        if (end_rc)
            log_err("sending error to xenopsd failed: %d, %s",
                    -end_rc, strerror(-end_rc));
        return rc;
    }
    return 0;
}

/*
 * Exits with code 0 on success, 1 if an error occurs during argument parsing
 * or emu-manager initialization, 2 if an error occurs during operation.
 */
int main(int argc, char *argv[])
{
    int rc;
    struct sigaction sa;
    char *ident;

    openlog(NULL, LOG_PID, LOG_DAEMON);

    parse_args(argc, argv);

    if (operation_mode == op_end)
        return 0;

    if (asprintf(&ident, "%s-%d", basename(argv[0]), domid) > 0)
        openlog(ident, LOG_PID, LOG_DAEMON);

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL)) {
        log_err("Error ignoring SIGPIPE %d, %s", errno, strerror(errno));
        return 1;
    }

    if (operation_mode == op_invalid) {
        log_err("Operation mode not set!");
        return 1;
    }
    if (xenopsd_in == -1 || xenopsd_out == -1) {
        log_err("Control fd(s) not set!");
        return 1;
    }
    if (set_cloexec_flag(xenopsd_in, true) || set_cloexec_flag(xenopsd_out, true)) {
        log_err("failed to set_cloexec flag for control fds %d, %s",
                errno, strerror(errno));
        return 1;
    }

    if (set_cloexec_flag_for_emus())
         return 1;

    if (domid == -1) {
        log_err("domid not set!");
        return 1;
    }

    log_info("Startup: xenopsd control fds (%d, %d)", xenopsd_in, xenopsd_out);
    log_info("Startup: domid %d", domid);
    log_info("Startup: operation mode: %s, %s", mode_names[operation_mode],
             live_migrate ? "live" : "non-live");

    switch (operation_mode) {
    case op_pvsave:
        rc = argument_add_string(&emus[0].extra, "pv", "true");
        if (rc) {
            log_err("Error adding pv argument: %d, %s", -rc, strerror(-rc));
            return 1;
        }
        /* fall though */
    case op_save:
        return operation_save() ? 2 : 0;
    case op_pvrestore:
        rc = argument_add_string(&emus[0].extra, "pv", "true");
        if (rc) {
            log_err("Error adding pv argument: %d, %s", -rc, strerror(-rc));
            return 1;
        }
        /* fall though */
    case op_restore:
        return operation_load() ? 2 : 0;
    default:
        log_err("Invalid mode");
        return 1;
    }
}
